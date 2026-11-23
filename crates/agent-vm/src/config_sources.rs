//! A project config's `sources = [...]` (ADR-0074): which other config files a
//! project reads, under which alias, and whether each is `:trust`.
//!
//! Pure: no filesystem access. [`crate::config::load`] reads what this module
//! resolves. Every diagnostic names `sources[N]` and the project config, never
//! entry text ([`crate::config`]'s value-safe rule).
//!
//! Three rules shape the grammar:
//!
//! * **Flat sourcing.** Only the project config may declare `sources`; a sourced
//!   file that declares it is refused by presence, so no file can widen the set
//!   of files a launch reads without the user editing the one file that decides
//!   it.
//! * **Trust is a route, not a spelling.** `:trust` is admitted only for the
//!   discovered user config path (ADR-0038's guarded file), and this module
//!   compares lexically: canonical equality must never widen trust, because a
//!   symlink into the checkout would then name the guarded file and read
//!   repository bytes (ADR-0074 D3).
//! * **Resolution is lexical.** Nothing here canonicalizes or stats. `..` is kept
//!   uncollapsed so the OS resolves it through a symlink the way the user's
//!   spelling says, instead of this module silently choosing a different file.

use std::fmt;
use std::path::{Component, Path, PathBuf};

use anyhow::{Result, anyhow};

/// The implicit source's alias: an absent project config, or no `sources` key
/// (ADR-0074 D2).
pub(crate) const HOME_ALIAS: &str = "home";
const MAX_ALIAS_LEN: usize = 32;
const TRUST_QUALIFIER: &str = "trust";
const IMAGE_SELECTOR: &str = "image";

/// A validated alias: `[a-z][a-z0-9_-]{0,31}`.
///
/// Validation is what lets `doctor` render the alias raw: no control, quote or
/// backslash byte can survive it, so a source label cannot rewrite the terminal.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct SourceAlias(String);

impl SourceAlias {
    pub(crate) fn parse(raw: &str) -> Option<Self> {
        let mut characters = raw.chars();
        match characters.next() {
            Some(first) if first.is_ascii_lowercase() => {}
            _ => return None,
        }
        if raw.len() > MAX_ALIAS_LEN {
            return None;
        }
        chars_are_alias_tail(characters).then(|| Self(raw.to_owned()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    fn home() -> Self {
        Self(HOME_ALIAS.to_owned())
    }

    #[cfg(test)]
    pub(crate) fn for_test(raw: &str) -> Self {
        Self::parse(raw).expect("valid test alias")
    }
}

fn chars_are_alias_tail(characters: impl Iterator<Item = char>) -> bool {
    characters.into_iter().all(|character| {
        character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || character == '-'
            || character == '_'
    })
}

impl fmt::Display for SourceAlias {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SourceTrust {
    /// `:trust`: read as the user tier (ADR-0040 verify, may carry authority).
    Trusted,
    /// No qualifier: declarations only; pinned by #736.
    Untrusted,
}

/// Where an entry came from, for diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Declaration {
    Implicit,
    Entry(usize),
}

impl fmt::Display for Declaration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Implicit => formatter.write_str("the default home:trust source"),
            Self::Entry(index) => write!(formatter, "sources[{index}]"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SourceEntry {
    declared: Declaration,
    alias: SourceAlias,
    trust: SourceTrust,
    path: PathBuf,
}

impl SourceEntry {
    pub(crate) fn declared(&self) -> Declaration {
        self.declared
    }

    pub(crate) fn alias(&self) -> &SourceAlias {
        &self.alias
    }

    pub(crate) fn trust(&self) -> SourceTrust {
        self.trust
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Sourcing {
    /// No project config, or a project config without a `sources` key (D2).
    Implicit,
    /// The project config listed `sources = [...]`, `[]` included.
    Listed,
}

#[derive(Debug)]
pub(crate) struct DeclaredSources {
    sourcing: Sourcing,
    entries: Vec<SourceEntry>,
}

/// Everything resolution is relative to. Named fields, because four paths in a
/// positional signature could be swapped at a call site without a compile error
/// (`CODING_STANDARDS.md` → *Types*).
pub(crate) struct ResolveContext<'a> {
    /// The file the entries were read from: diagnostics, and the self-source
    /// refusal.
    pub(crate) project_config: &'a Path,
    /// The `$HOME` the project config path was derived from (`~/`).
    pub(crate) home: &'a Path,
    /// The captured, canonical `ProjectDir` (`./` and other relative spellings).
    pub(crate) project_root: &'a Path,
    /// `ConfigPaths::user`: the only path `:trust` accepts (D3).
    pub(crate) user_config: &'a Path,
}

impl DeclaredSources {
    /// The implicit single source: `home:trust <user_config>`, or nothing when
    /// `$HOME` is unavailable, which keeps the user tier `UnavailableHome`.
    pub(crate) fn implicit(user_config: Option<&Path>) -> Self {
        let entries = user_config
            .map(|path| {
                vec![SourceEntry {
                    declared: Declaration::Implicit,
                    alias: SourceAlias::home(),
                    trust: SourceTrust::Trusted,
                    path: path.to_path_buf(),
                }]
            })
            .unwrap_or_default();
        Self {
            sourcing: Sourcing::Implicit,
            entries,
        }
    }

    /// Parse the project config's own list, entry by entry, rules in table order.
    pub(crate) fn listed(raw: &[String], context: &ResolveContext<'_>) -> Result<Self> {
        let mut entries: Vec<SourceEntry> = Vec::with_capacity(raw.len());
        for (index, text) in raw.iter().enumerate() {
            let entry = match entry(index, text, context) {
                Ok(entry) => entry,
                Err(refusal) => return Err(sources_error(context.project_config, index, refusal)),
            };
            // Earlier entries only, so the diagnostic always names the later
            // one — the entry the user has to change.
            if let Some(first) = entries
                .iter()
                .position(|earlier| earlier.alias == entry.alias)
            {
                return Err(sources_error(
                    context.project_config,
                    index,
                    EntryRefusal::DuplicateAlias(first),
                ));
            }
            if let Some(first) = entries
                .iter()
                .position(|earlier| earlier.path == entry.path)
            {
                return Err(sources_error(
                    context.project_config,
                    index,
                    EntryRefusal::DuplicatePath(first),
                ));
            }
            entries.push(entry);
        }
        Ok(Self {
            sourcing: Sourcing::Listed,
            entries,
        })
    }

    pub(crate) fn sourcing(&self) -> Sourcing {
        self.sourcing
    }

    pub(crate) fn entries(&self) -> &[SourceEntry] {
        &self.entries
    }

    pub(crate) fn by_alias(&self, alias: &SourceAlias) -> Option<&SourceEntry> {
        self.entries.iter().find(|entry| &entry.alias == alias)
    }
}

/// The alias of a project-config `image` value shaped exactly `ALIAS:image`
/// (ADR-0074 D6), whether or not that alias is declared. `None` means "an OCI
/// reference".
///
/// Recognised by shape rather than by lookup, because falling back to OCI for an
/// *undeclared* alias would turn the typo `image = "rpeo:image"` into a pull of
/// `docker.io/library/rpeo:image`. The alias is returned parsed, so no caller has
/// to re-parse validated text.
pub(crate) fn image_alias(raw: &str) -> Option<SourceAlias> {
    let (alias, selector) = raw.rsplit_once(':')?;
    (selector == IMAGE_SELECTOR).then(|| SourceAlias::parse(alias))?
}

/// One entry's grammar and path refusal, before the set rules run.
enum EntryRefusal {
    Fixed(&'static str),
    DuplicateAlias(usize),
    DuplicatePath(usize),
}

impl fmt::Display for EntryRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fixed(reason) => formatter.write_str(reason),
            Self::DuplicateAlias(index) => {
                write!(
                    formatter,
                    "the alias is already declared by sources[{index}]"
                )
            }
            Self::DuplicatePath(index) => {
                write!(
                    formatter,
                    "this file is already sourced by sources[{index}]"
                )
            }
        }
    }
}

const MALFORMED_ENTRY: &str = "expected \"<alias>[:trust] <path>\"";
const INVALID_ALIAS: &str =
    "an alias is 1 to 32 characters of a-z, 0-9, '-' or '_', starting with a letter";
const ONLY_QUALIFIER: &str = "the only qualifier is \":trust\"";
const EMPTY_PATH: &str = "the path is empty";
const SPACE_AFTER_ALIAS: &str = "separate the alias and the path with exactly one space";
const TRAILING_WHITESPACE: &str = "the path ends with whitespace";
const CONTROL_CHARACTER: &str = "the path contains a control character";
const TILDE_SPELLING: &str = "only \"~/\" is expanded; write \"~/PATH\", \"./PATH\" or \"/PATH\"";
const TRUST_ONLY_FOR_USER_CONFIG: &str = "\":trust\" is accepted only for ~/.config/agent-vm/config.toml; source this file without \":trust\"";
const SELF_SOURCE: &str = "the project config cannot source itself";

fn sources_error(file: &Path, index: usize, refusal: EntryRefusal) -> anyhow::Error {
    anyhow!(
        "config: {}: sources[{index}]: {refusal}",
        crate::one_line::quoted_path(file)
    )
}

fn entry(
    index: usize,
    raw: &str,
    context: &ResolveContext<'_>,
) -> std::result::Result<SourceEntry, EntryRefusal> {
    let (head, spelled) = raw
        .split_once(' ')
        .ok_or(EntryRefusal::Fixed(MALFORMED_ENTRY))?;
    let (alias, trust) = match head.split_once(':') {
        None => (head, SourceTrust::Untrusted),
        Some((alias, TRUST_QUALIFIER)) => (alias, SourceTrust::Trusted),
        // A valid alias with any other qualifier is a rejected *qualifier*, not a
        // malformed alias: the user has to learn which qualifier exists.
        Some((alias, _)) if SourceAlias::parse(alias).is_some() => {
            return Err(EntryRefusal::Fixed(ONLY_QUALIFIER));
        }
        Some(_) => return Err(EntryRefusal::Fixed(INVALID_ALIAS)),
    };
    let alias = SourceAlias::parse(alias).ok_or(EntryRefusal::Fixed(INVALID_ALIAS))?;
    if spelled.is_empty() {
        return Err(EntryRefusal::Fixed(EMPTY_PATH));
    }
    if spelled.starts_with(char::is_whitespace) {
        return Err(EntryRefusal::Fixed(SPACE_AFTER_ALIAS));
    }
    if spelled.ends_with(char::is_whitespace) {
        return Err(EntryRefusal::Fixed(TRAILING_WHITESPACE));
    }
    if spelled.chars().any(char::is_control) {
        return Err(EntryRefusal::Fixed(CONTROL_CHARACTER));
    }
    let path = resolve(spelled, context)?;
    if trust == SourceTrust::Trusted && path != context.user_config {
        return Err(EntryRefusal::Fixed(TRUST_ONLY_FOR_USER_CONFIG));
    }
    if path == context.project_config {
        return Err(EntryRefusal::Fixed(SELF_SOURCE));
    }
    Ok(SourceEntry {
        declared: Declaration::Entry(index),
        alias,
        trust,
        path,
    })
}

fn resolve(
    spelled: &str,
    context: &ResolveContext<'_>,
) -> std::result::Result<PathBuf, EntryRefusal> {
    let (base, rest) = if let Some(rest) = spelled.strip_prefix("~/") {
        // Repeated separators are dropped so the suffix is relative by
        // construction: a leading `RootDir` component would discard `base` when
        // pushed onto it, turning `~//x` into `/x`.
        (context.home, rest.trim_start_matches('/'))
    } else if spelled.starts_with('~') {
        return Err(EntryRefusal::Fixed(TILDE_SPELLING));
    } else if spelled.starts_with('/') {
        return Ok(PathBuf::from(spelled));
    } else {
        (context.project_root, spelled)
    };
    // `CurDir` is dropped so `./.agent-vm/config.toml` has exactly the spelling
    // the legacy probe builds; `..` is kept (lexical, never resolved through a
    // symlink here). Only relative components are pushed, so `base` survives.
    let mut out = base.to_path_buf();
    for component in Path::new(rest).components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::ParentDir => out.push(Component::ParentDir),
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => {
                debug_assert!(
                    false,
                    "a relative source suffix cannot contain a root or prefix component"
                );
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Literal paths: this module never touches the filesystem (D1).
    struct TestContext {
        project_config: PathBuf,
        home: PathBuf,
        project_root: PathBuf,
        user_config: PathBuf,
    }

    impl TestContext {
        fn new() -> Self {
            Self {
                project_config: PathBuf::from("/h/.config/agent-vm/projects/abc/config.toml"),
                home: PathBuf::from("/h"),
                project_root: PathBuf::from("/w/app"),
                user_config: PathBuf::from("/h/.config/agent-vm/config.toml"),
            }
        }

        fn resolve(&self) -> ResolveContext<'_> {
            ResolveContext {
                project_config: &self.project_config,
                home: &self.home,
                project_root: &self.project_root,
                user_config: &self.user_config,
            }
        }

        fn list(&self, entries: &[&str]) -> Result<DeclaredSources> {
            let raw: Vec<String> = entries.iter().map(|entry| (*entry).to_owned()).collect();
            DeclaredSources::listed(&raw, &self.resolve())
        }
    }

    /// The one entry a single-entry list resolved to, with its exact spelling.
    fn resolved_path(context: &TestContext, entry: &str) -> String {
        let listed = context
            .list(&[&format!("repo {entry}")])
            .expect("accepted entry");
        listed.entries()[0]
            .path()
            .to_str()
            .expect("UTF-8 test path")
            .to_owned()
    }

    fn refusal(context: &TestContext, entries: &[&str]) -> String {
        format!("{:#}", context.list(entries).expect_err("refused entry"))
    }

    fn assert_refused(context: &TestContext, entry: &str, expected: &str, index: usize) {
        let message = refusal(context, &[entry]);
        assert!(
            message.contains(&format!("sources[{index}]: {expected}")),
            "{message}"
        );
        assert!(message.contains("\"/h/.config/agent-vm/projects/abc/config.toml\""));
    }

    #[test]
    fn v1_grammar_accepts_well_formed_entries() {
        let context = TestContext::new();
        for entry in [
            "home:trust ~/.config/agent-vm/config.toml",
            "repo ./x.toml",
            "a_1-b /abs/x.toml",
            "repo /abs/my file.toml",
        ] {
            context
                .list(&[entry])
                .unwrap_or_else(|error| panic!("expected {entry:?} to be accepted: {error:#}"));
        }
        let listed = context
            .list(&["repo ./x.toml", "team /abs/team.toml"])
            .expect("two entries");
        assert_eq!(listed.sourcing(), Sourcing::Listed);
        assert_eq!(listed.entries()[1].declared(), Declaration::Entry(1));
        assert_eq!(
            listed.entries()[1].declared().to_string(),
            "sources[1]",
            "indices are zero-based, the way the file is read"
        );
    }

    #[test]
    fn v1_grammar_refuses_each_malformed_shape() {
        let context = TestContext::new();
        let too_long = format!("{} /x", "a".repeat(33));
        for (entry, expected) in [
            ("nospace", MALFORMED_ENTRY),
            ("Repo x", INVALID_ALIAS),
            ("repo:pin x", ONLY_QUALIFIER),
            ("Re:pin x", INVALID_ALIAS),
            ("repo ", EMPTY_PATH),
            ("repo  x", SPACE_AFTER_ALIAS),
            ("repo x ", TRAILING_WHITESPACE),
            ("repo x\u{7}", CONTROL_CHARACTER),
            ("repo ~", TILDE_SPELLING),
            ("repo ~al/x", TILDE_SPELLING),
            (too_long.as_str(), INVALID_ALIAS),
        ] {
            assert_refused(&context, entry, expected, 0);
        }
        // The index is the refused entry's, not the first entry's.
        let message = refusal(&context, &["repo ./a.toml", "nospace"]);
        assert!(
            message.contains(&format!("sources[1]: {MALFORMED_ENTRY}")),
            "{message}"
        );
    }

    #[test]
    fn v1_refusals_never_echo_the_entry() {
        let context = TestContext::new();
        for entry in [
            "SECRET-734 x.toml",
            "repo x\u{7} SECRET-734",
            "repo:SECRET-734 x.toml",
            "repo  SECRET-734",
        ] {
            let message = refusal(&context, &[entry]);
            assert!(!message.contains("SECRET-734"), "{message}");
        }
    }

    #[test]
    fn v2_paths_resolve_lexically() {
        let context = TestContext::new();
        for (entry, expected) in [
            ("~/a/b", "/h/a/b"),
            // A repeated separator must never rebase the path onto `/`.
            ("~//x", "/h/x"),
            ("~///a//b", "/h/a/b"),
            ("~/", "/h"),
            ("~//", "/h"),
            ("/", "/"),
            ("./", "/w/app"),
            ("./a", "/w/app/a"),
            ("a", "/w/app/a"),
            ("./a/./b", "/w/app/a/b"),
            ("./.agent-vm/config.toml", "/w/app/.agent-vm/config.toml"),
            // `..` stays uncollapsed: the OS resolves it through a symlink.
            ("../outside/a.toml", "/w/app/../outside/a.toml"),
            ("sub/../a.toml", "/w/app/sub/../a.toml"),
            ("/x/y", "/x/y"),
        ] {
            assert_eq!(resolved_path(&context, entry), expected, "{entry:?}");
        }
    }

    #[test]
    fn v3_set_rules_refuse_duplicates_self_and_foreign_trust() {
        let context = TestContext::new();

        let message = refusal(&context, &["repo ./a.toml", "repo ./b.toml"]);
        assert!(
            message.contains("sources[1]: the alias is already declared by sources[0]"),
            "{message}"
        );

        // Two spellings of one file are one lexical path.
        let message = refusal(&context, &["one ./a.toml", "two /w/app/a.toml"]);
        assert!(
            message.contains("sources[1]: this file is already sourced by sources[0]"),
            "{message}"
        );

        let message = refusal(
            &context,
            &["self /h/.config/agent-vm/projects/abc/config.toml"],
        );
        assert!(message.contains(SELF_SOURCE), "{message}");

        for entry in [
            "team:trust ~/team.toml",
            "team:trust /h/.config/agent-vm/config.toml.bak",
            // Lexical-only admission: `..` cannot name its way to the user file.
            "team:trust ~/../h/.config/agent-vm/config.toml",
        ] {
            assert_refused(&context, entry, TRUST_ONLY_FOR_USER_CONFIG, 0);
        }

        // The same path spelled two ways is still the discovered user config.
        for entry in [
            "home:trust ~//.config/agent-vm/config.toml",
            "me:trust ~/.config/agent-vm/config.toml",
            "me:trust /h/.config/agent-vm/config.toml",
        ] {
            let listed = context.list(&[entry]).expect("trusted user config");
            assert_eq!(listed.entries()[0].trust(), SourceTrust::Trusted);
        }

        let empty = context.list(&[]).expect("an empty list is valid");
        assert!(empty.entries().is_empty());
        assert_eq!(empty.sourcing(), Sourcing::Listed);
    }

    #[test]
    fn v3_by_alias_finds_declared_entries_only() {
        let context = TestContext::new();
        let listed = context
            .list(&["repo ./r.toml", "home:trust ~/.config/agent-vm/config.toml"])
            .expect("two entries");
        assert_eq!(
            listed
                .by_alias(&SourceAlias::for_test("repo"))
                .map(SourceEntry::path),
            Some(Path::new("/w/app/r.toml"))
        );
        assert_eq!(
            listed.by_alias(&SourceAlias::home()).map(SourceEntry::path),
            Some(Path::new("/h/.config/agent-vm/config.toml"))
        );
        assert!(listed.by_alias(&SourceAlias::for_test("rpeo")).is_none());
    }

    #[test]
    fn v4_image_alias_recognises_only_the_exact_shape() {
        for (raw, expected) in [
            ("repo:image", Some("repo")),
            ("a:image", Some("a")),
            ("repo-1:image", Some("repo-1")),
            ("", None),
            (":image", None),
            ("docker.io/x:image", None),
            ("Repo:image", None),
            ("repo:images", None),
            ("repo:image@sha256:abc", None),
            ("ubuntu:22.04", None),
            ("localhost:5000/x", None),
        ] {
            assert_eq!(
                image_alias(raw).as_ref().map(SourceAlias::as_str),
                expected,
                "{raw:?}"
            );
        }
    }

    #[test]
    fn implicit_sourcing_is_the_trusted_user_config_or_nothing() {
        let user_config = PathBuf::from("/h/.config/agent-vm/config.toml");
        let implicit = DeclaredSources::implicit(Some(&user_config));
        assert_eq!(implicit.sourcing(), Sourcing::Implicit);
        assert_eq!(implicit.entries().len(), 1);
        let entry = &implicit.entries()[0];
        assert_eq!(entry.alias().as_str(), HOME_ALIAS);
        assert_eq!(entry.trust(), SourceTrust::Trusted);
        assert_eq!(entry.path(), user_config);
        assert_eq!(entry.declared(), Declaration::Implicit);
        assert_eq!(
            entry.declared().to_string(),
            "the default home:trust source"
        );

        let unavailable = DeclaredSources::implicit(None);
        assert!(unavailable.entries().is_empty());
        assert_eq!(unavailable.sourcing(), Sourcing::Implicit);
    }

    #[test]
    fn aliases_are_ascii_lowercase_with_a_letter_start() {
        assert!(SourceAlias::parse("home").is_some());
        assert_eq!(
            SourceAlias::parse("a").map(|alias| alias.as_str().len()),
            Some(1)
        );
        assert_eq!(
            SourceAlias::parse(&"a".repeat(MAX_ALIAS_LEN)).map(|alias| alias.as_str().len()),
            Some(MAX_ALIAS_LEN)
        );
        assert!(SourceAlias::parse(&"a".repeat(MAX_ALIAS_LEN + 1)).is_none());
        assert!(SourceAlias::parse("1home").is_none());
        assert!(SourceAlias::parse("").is_none());
        assert!(SourceAlias::parse("ho me").is_none());
        assert!(SourceAlias::parse("ho\u{1b}me").is_none());
        assert!(SourceAlias::parse("hoé").is_none());
    }
}
