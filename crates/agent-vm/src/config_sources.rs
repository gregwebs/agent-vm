//! A project config's `[[sources]]` tables (ADR-0076): which other config
//! files a project reads, under which alias, and with which attributes.
//!
//! Pure: no filesystem access. [`crate::config::load`] reads what this module
//! resolves. Every diagnostic names `sources[N]` and the project config, never
//! entry text ([`crate::config`]'s value-safe rule).
//!
//! Five rules shape the grammar:
//!
//! * **A bounded list.** At most `MAX_DECLARED_SOURCES` entries. Every source is
//!   route-verified and fully parsed on every launch, so the count is the cheapest
//!   place to bound what one project config can ask a launch to spend, and it is
//!   checked before any entry is scanned.
//! * **Flat sourcing.** Only the project config may declare `sources`; a sourced
//!   file that declares it is refused by presence, so no file can widen the set
//!   of files a launch reads without the user editing the one file that decides
//!   it.
//! * **Two independent attributes.** `trust` (bypass content-hash pinning) and
//!   `allow` (adopt this file's top-level authorizations) are separate booleans,
//!   so all four combinations are expressible. Nothing here decides what either
//!   one *means*; that is [`crate::config::load`]'s job.
//! * **Trust is a route, not a spelling.** Any path outside the checkout may be
//!   `trust = true` (ADR-0076), but whether the route to it is host-controlled
//!   is decided by [`crate::project_config`], never by canonical equality here.
//! * **Resolution is lexical.** Nothing here canonicalizes or stats. `..` is kept
//!   uncollapsed so the OS resolves it through a symlink the way the user's
//!   spelling says, instead of this module silently choosing a different file.

use std::collections::HashMap;
use std::fmt;
use std::path::{Component, Path, PathBuf};

use anyhow::{Result, anyhow};

/// The implicit source's alias: an absent project config, or no `sources` key
/// (ADR-0076 R1.1).
pub(crate) const HOME_ALIAS: &str = "home";
const MAX_ALIAS_LEN: usize = 32;
const IMAGE_SELECTOR: &str = "image";

/// A fail-closed bound on the `[[sources]]` tables one project config may
/// declare.
///
/// A real project lists the default `home` file plus a handful of shared, team or
/// per-checkout files; thirty-two is several times the largest hand-written list
/// we have seen, and it stays an order of magnitude below the 256 distinct trusted
/// sources the cross-project guard scans across **all** projects. Each entry costs
/// a route walk from `/`, a verified read and a full parse on every launch, and an
/// `allow = true` one can adopt authority, so the count is where the bound belongs:
/// it is checked before the list is scanned at all.
pub(crate) const MAX_DECLARED_SOURCES: usize = 32;

const KEY_NAME: &str = "name";
const KEY_PATH: &str = "path";
const KEY_TRUST: &str = "trust";
const KEY_ALLOW: &str = "allow";

/// A validated alias: `[a-z][a-z0-9_-]{0,31}`.
///
/// Validation is what lets `doctor` render the alias raw: no control, quote or
/// backslash byte can survive it, so a source label cannot rewrite the terminal.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

    pub(crate) fn home() -> Self {
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

/// Named booleans so `trust` and `allow` can never be transposed at a call site
/// (`CODING_STANDARDS.md` → *Types*).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SourceAttributes {
    /// Bypass content-hash pinning (#736) and read through the verified path.
    pub(crate) trust: bool,
    /// Adopt this file's top-level `image`/`mounts`/`[network]`/`allow_tools`.
    pub(crate) allow: bool,
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
            // Neither attribute is implied by the position, so the label names
            // only the source, not a `:trust` qualifier that no longer exists.
            Self::Implicit => formatter.write_str("the default home source"),
            Self::Entry(index) => write!(formatter, "sources[{index}]"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SourceEntry {
    declared: Declaration,
    alias: SourceAlias,
    attributes: SourceAttributes,
    path: PathBuf,
    /// Whether the user wrote a path with no `/` or `~/` anchor. The walker
    /// starts a relative entry at the captured project root, and records the
    /// resulting scope from the route it actually walks; this flag is what
    /// tells that walker which floor to start from, not what the scope is.
    spelled_relative: bool,
}

impl SourceEntry {
    pub(crate) fn declared(&self) -> Declaration {
        self.declared
    }

    pub(crate) fn alias(&self) -> &SourceAlias {
        &self.alias
    }

    pub(crate) fn is_trusted(&self) -> bool {
        self.attributes.trust
    }

    pub(crate) fn is_allowed(&self) -> bool {
        self.attributes.allow
    }

    pub(crate) fn attributes(&self) -> SourceAttributes {
        self.attributes
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    #[cfg_attr(not(test), allow(dead_code))] // Phase 4's untrusted route walker
    pub(crate) fn is_spelled_relative(&self) -> bool {
        self.spelled_relative
    }

    /// A hand-built entry for route tests: production entries come from
    /// [`DeclaredSources::parse`], which is the only place that decides the
    /// spelling/attribute defaults.
    #[cfg(test)]
    pub(crate) fn for_tests(spelled_relative: bool, path: PathBuf) -> Self {
        Self {
            declared: Declaration::Entry(0),
            alias: SourceAlias::for_test("repo"),
            attributes: SourceAttributes::default(),
            path,
            spelled_relative,
        }
    }
}

/// Which read policy an untrusted source's route earns (ADR-0076 R2.4, #736).
///
/// Decided by the route the walker actually traversed, never by the spelling:
/// a relative path, an enclosing-worktree path, a case alias and a symlinked
/// ancestor all become `Checkout` once a boundary directory is entered by
/// descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))] // Phase 4's untrusted route walker
pub(crate) enum SourceScope {
    /// The route entered the captured checkout or an enclosing Git worktree and
    /// stayed confined to it.
    Checkout,
    /// An explicit `/...` or `~/...` route that never entered the boundary.
    External,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Sourcing {
    /// No project config, or a project config without a `sources` key.
    Implicit,
    /// The project config listed `[[sources]]`, `sources = []` included.
    Listed,
}

#[derive(Debug)]
pub(crate) struct DeclaredSources {
    sourcing: Sourcing,
    entries: Vec<SourceEntry>,
}

/// Everything resolution is relative to. Named fields, because three paths in a
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
}

impl DeclaredSources {
    /// The implicit single source, behaving exactly like an explicit
    /// `{ name = "home", path = "~/.config/agent-vm/config.toml", trust = true,
    /// allow = true }`, or nothing when `$HOME` is unavailable (which keeps the
    /// user tier `UnavailableHome`).
    pub(crate) fn implicit(user_config: Option<&Path>) -> Self {
        let entries = user_config
            .map(|path| {
                vec![SourceEntry {
                    declared: Declaration::Implicit,
                    alias: SourceAlias::home(),
                    attributes: SourceAttributes {
                        trust: true,
                        allow: true,
                    },
                    path: path.to_path_buf(),
                    spelled_relative: false,
                }]
            })
            .unwrap_or_default();
        Self {
            sourcing: Sourcing::Implicit,
            entries,
        }
    }

    /// Parse the project config's own `sources` value as an array of tables,
    /// entry by entry, rules in declaration order.
    pub(crate) fn parse(value: &toml::Value, context: &ResolveContext<'_>) -> Result<Self> {
        let Some(items) = value.as_array() else {
            return Err(anyhow!(
                "config: {}: sources: must be an array of [[sources]] tables (or sources = [])",
                crate::one_line::quoted_path(context.project_config)
            ));
        };
        // Before any entry is scanned: the bound is on the list, so a config that
        // asks for more is refused without the per-entry work it asks for.
        if items.len() > MAX_DECLARED_SOURCES {
            return Err(anyhow!(
                "config: {}: sources: more than {MAX_DECLARED_SOURCES} declared sources; each one \
                 is verified and parsed on every launch, so keep the files this project uses and \
                 remove the rest",
                crate::one_line::quoted_path(context.project_config)
            ));
        }
        let mut entries: Vec<SourceEntry> = Vec::with_capacity(items.len());
        let mut declared = DeclaredIndex::default();
        for (index, item) in items.iter().enumerate() {
            if item.is_str() {
                return Err(list_error(
                    context.project_config,
                    index,
                    STRING_ENTRY_MIGRATION,
                ));
            }
            let Some(table) = item.as_table() else {
                return Err(list_error(
                    context.project_config,
                    index,
                    NOT_A_SOURCES_TABLE,
                ));
            };
            let entry = entry(index, table, context)?;
            declared.record(index, &entry, context.project_config)?;
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

/// The aliases and paths already declared, by the index that declared them.
///
/// Two maps, so a new entry costs one lookup each instead of a rescan of every
/// earlier entry: the check has to stay linear, or accepting a long list becomes
/// quadratic work of its own (5,000 entries cost 3.8 s when it was a scan).
#[derive(Default)]
struct DeclaredIndex {
    aliases: HashMap<SourceAlias, usize>,
    paths: HashMap<PathBuf, usize>,
}

impl DeclaredIndex {
    /// Refuse `entry` when an earlier one already used its alias or its path,
    /// naming the later entry first — the one the user has to change — and the
    /// earlier one second.
    fn record(&mut self, index: usize, entry: &SourceEntry, file: &Path) -> Result<()> {
        if let Some(first) = self.aliases.get(&entry.alias) {
            return Err(anyhow!(
                "config: {}: sources[{index}]: the alias is already declared by sources[{first}]",
                crate::one_line::quoted_path(file)
            ));
        }
        if let Some(first) = self.paths.get(&entry.path) {
            return Err(anyhow!(
                "config: {}: sources[{index}]: this file is already sourced by sources[{first}]",
                crate::one_line::quoted_path(file)
            ));
        }
        self.aliases.insert(entry.alias.clone(), index);
        self.paths.insert(entry.path.clone(), index);
        Ok(())
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

/// Recover the `~/`- and `/`-anchored paths of `trust = true` sources in a
/// project config's raw bytes, lexically and with zero filesystem access.
///
/// Used by [`crate::protected_config_dir`] to protect routes that *other*
/// projects trust; a project config's own launch gets its paths from the parsed
/// [`DeclaredSources`]. Syntactically broken TOML (or any other malformed shape)
/// yields no paths: the file itself stays protected as a project store, and that
/// project's own load is what reports the error.
pub(crate) fn extract_trusted_non_relative_paths(text: &str, home: &Path) -> Vec<PathBuf> {
    let Ok(document) = toml::from_str::<toml::Table>(text) else {
        return Vec::new();
    };
    let Some(items) = document.get("sources").and_then(toml::Value::as_array) else {
        return Vec::new();
    };
    let mut paths = Vec::new();
    for item in items {
        let Some(table) = item.as_table() else {
            continue;
        };
        if table.get(KEY_TRUST).and_then(toml::Value::as_bool) != Some(true) {
            continue;
        }
        let Some(spelled) = table.get(KEY_PATH).and_then(toml::Value::as_str) else {
            continue;
        };
        // Only host-anchored spellings can be trusted (ADR-0076 R2.2): a
        // relative path is anchored at whichever project is loading, so it is
        // never usable as a `trust = true` source.
        if !(spelled.starts_with("~/") || spelled.starts_with('/')) {
            continue;
        }
        if let Ok(path) = resolve_spelled(spelled, home, home) {
            paths.push(path);
        }
    }
    paths
}

const STRING_ENTRY_MIGRATION: &str = "string entries (\"<alias>[:trust] <path>\") are no longer \
     supported; declare each source as a [[sources]] table with name = \"...\", path = \"...\", \
     and optional trust = true / allow = true";
const NOT_A_SOURCES_TABLE: &str = "must be a [[sources]] table with name and path";
const UNKNOWN_KEY: &str = "unknown key; supported keys are name, path, trust and allow";
const INVALID_ALIAS: &str =
    "an alias is 1 to 32 characters of a-z, 0-9, '-' or '_', starting with a letter";
const EMPTY_PATH: &str = "the path is empty";
const PATH_WHITESPACE: &str = "the path starts or ends with whitespace";
const CONTROL_CHARACTER: &str = "the path contains a control character";
const TILDE_SPELLING: &str = "only \"~/\" is expanded; write \"~/PATH\", \"./PATH\" or \"/PATH\"";
const NOT_A_BOOL: &str = "must be true or false";
const SELF_SOURCE: &str = "the project config cannot source itself";
const DIRECTORY_ASSERTION: &str =
    "the path names a directory (it ends with \"/\", \"/.\" or \"/..\"); a source must name a file";

fn list_error(file: &Path, index: usize, refusal: &str) -> anyhow::Error {
    anyhow!(
        "config: {}: sources[{index}]: {refusal}",
        crate::one_line::quoted_path(file)
    )
}

fn field_error(file: &Path, index: usize, field: &str, refusal: &str) -> anyhow::Error {
    anyhow!(
        "config: {}: sources[{index}].{field}: {refusal}",
        crate::one_line::quoted_path(file)
    )
}

/// One `[[sources]]` table's keys, attributes, and lexical path.
fn entry(
    index: usize,
    table: &toml::map::Map<String, toml::Value>,
    context: &ResolveContext<'_>,
) -> Result<SourceEntry> {
    let file = context.project_config;
    // Deterministic key order (a `BTreeMap`), so a table with two problems always
    // reports the same one.
    for key in table.keys() {
        match key.as_str() {
            KEY_NAME | KEY_PATH | KEY_TRUST | KEY_ALLOW => {}
            other => {
                // A top-level field written after `[[sources]]` belongs to that
                // source by TOML scoping; name the fixed canonical spelling so
                // the user can move the line instead of guessing.
                if let Some(field) = crate::config::top_level_field(other) {
                    return Err(anyhow!(
                        "config: {}: sources[{index}]: {field} is not a source key; top-level \
                         {field} must be written before the first [[sources]] or table header \
                         (keys after [[sources]] belong to that source)",
                        crate::one_line::quoted_path(file)
                    ));
                }
                return Err(list_error(file, index, UNKNOWN_KEY));
            }
        }
    }

    let Some(raw_name) = table.get(KEY_NAME) else {
        return Err(list_error(file, index, "missing required key \"name\""));
    };
    let Some(raw_name) = raw_name.as_str() else {
        return Err(field_error(file, index, KEY_NAME, "must be a string"));
    };
    let alias = SourceAlias::parse(raw_name)
        .ok_or_else(|| field_error(file, index, KEY_NAME, INVALID_ALIAS))?;

    let Some(raw_path) = table.get(KEY_PATH) else {
        return Err(list_error(file, index, "missing required key \"path\""));
    };
    let Some(spelled) = raw_path.as_str() else {
        return Err(field_error(file, index, KEY_PATH, "must be a string"));
    };
    if spelled.is_empty() {
        return Err(field_error(file, index, KEY_PATH, EMPTY_PATH));
    }
    if spelled.starts_with(char::is_whitespace) || spelled.ends_with(char::is_whitespace) {
        return Err(field_error(file, index, KEY_PATH, PATH_WHITESPACE));
    }
    if spelled.chars().any(char::is_control) {
        return Err(field_error(file, index, KEY_PATH, CONTROL_CHARACTER));
    }
    let path = resolve_spelled(spelled, context.home, context.project_root)
        .map_err(|refusal| field_error(file, index, KEY_PATH, refusal))?;

    let trust = optional_bool(file, index, KEY_TRUST, table.get(KEY_TRUST))?;
    let allow = optional_bool(file, index, KEY_ALLOW, table.get(KEY_ALLOW))?;

    if path == file {
        return Err(list_error(file, index, SELF_SOURCE));
    }

    Ok(SourceEntry {
        declared: Declaration::Entry(index),
        alias,
        attributes: SourceAttributes { trust, allow },
        path,
        spelled_relative: !(spelled.starts_with("~/") || spelled.starts_with('/')),
    })
}

fn optional_bool(
    file: &Path,
    index: usize,
    key: &str,
    value: Option<&toml::Value>,
) -> Result<bool> {
    match value {
        None => Ok(false),
        Some(value) => value
            .as_bool()
            .ok_or_else(|| field_error(file, index, key, NOT_A_BOOL)),
    }
}

/// The one lexical normalization `SourceEntry` and the future `PinKey` share.
///
/// Absolute, never canonicalizing and never touching the filesystem: repeated
/// separators and interior `.` components are dropped, `..` is kept
/// **uncollapsed** so the OS resolves it through the symlink the user's spelling
/// names, and a spelling that asserts a directory (`/a/b/`, `/a/b/.`,
/// `/a/b/..`) is refused rather than silently read as the file `a/b`. `None`
/// means "not this shape"; callers supply the refusal text for their context.
pub(crate) fn normalize_lexical_absolute(path: &Path) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt as _;
    let bytes = path.as_os_str().as_bytes();
    if bytes.first() != Some(&b'/') {
        return None;
    }
    // `Path::components` drops a trailing separator, so the directory assertion
    // has to be read off the bytes before the component walk loses it.
    if bytes.len() > 1 && bytes.ends_with(b"/") {
        return None;
    }
    // `components()` normalizes a trailing `.` away, so the final directory
    // spellings `/.` and `/..` are read off the bytes before the walk.
    if bytes.ends_with(b"/.") || bytes.ends_with(b"/..") {
        return None;
    }
    let components: Vec<Component<'_>> = path.components().collect();
    let last = components.last()?;
    match last {
        Component::Normal(_) => {}
        // A final `.` or `..`, or the bare root, names a directory.
        Component::CurDir | Component::ParentDir | Component::RootDir => return None,
        Component::Prefix(_) => return None,
    }
    let mut out = PathBuf::from("/");
    for component in components {
        match component {
            Component::RootDir => {}
            Component::Normal(part) => out.push(part),
            Component::ParentDir => out.push(Component::ParentDir),
            Component::CurDir => {}
            Component::Prefix(_) => return None,
        }
    }
    Some(out)
}

fn resolve_spelled(
    spelled: &str,
    home: &Path,
    project_root: &Path,
) -> std::result::Result<PathBuf, &'static str> {
    // Read the directory assertion off the user's own spelling: a `~//` or
    // `./` suffix would otherwise be indistinguishable from the file it names.
    if spelled.len() > 1 && spelled.ends_with('/') {
        return Err(DIRECTORY_ASSERTION);
    }
    let (base, rest) = if let Some(rest) = spelled.strip_prefix("~/") {
        // Repeated separators are dropped so the suffix is relative by
        // construction: a leading `RootDir` component would discard `base` when
        // pushed onto it, turning `~//x` into `/x`.
        (home, rest.trim_start_matches('/'))
    } else if spelled.starts_with('~') {
        return Err(TILDE_SPELLING);
    } else if spelled.starts_with('/') {
        return normalize_lexical_absolute(Path::new(spelled)).ok_or(DIRECTORY_ASSERTION);
    } else {
        (project_root, spelled)
    };
    // `..` is kept (lexical, never resolved through a symlink here); interior
    // `.` is dropped. Only relative components are pushed, so `base` survives.
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
    normalize_lexical_absolute(&out).ok_or(DIRECTORY_ASSERTION)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Literal paths: this module never touches the filesystem.
    struct TestContext {
        project_config: PathBuf,
        home: PathBuf,
        project_root: PathBuf,
    }

    impl TestContext {
        fn new() -> Self {
            Self {
                project_config: PathBuf::from("/h/.config/agent-vm/projects/abc/config.toml"),
                home: PathBuf::from("/h"),
                project_root: PathBuf::from("/w/app"),
            }
        }

        fn resolve(&self) -> ResolveContext<'_> {
            ResolveContext {
                project_config: &self.project_config,
                home: &self.home,
                project_root: &self.project_root,
            }
        }

        /// Parse source tables written as a whole `[[sources]]` TOML document.
        fn parse(&self, toml_text: &str) -> Result<DeclaredSources> {
            let document: toml::Table =
                toml::from_str(toml_text).expect("test fixture is valid TOML");
            let value = document
                .get("sources")
                .expect("test fixture declares sources");
            DeclaredSources::parse(value, &self.resolve())
        }

        fn parse_ok(&self, toml_text: &str) -> DeclaredSources {
            self.parse(toml_text)
                .unwrap_or_else(|error| panic!("expected acceptance: {error:#}"))
        }
    }

    fn refusal(context: &TestContext, toml_text: &str) -> String {
        format!("{:#}", context.parse(toml_text).expect_err("refused value"))
    }

    fn assert_fragment(context: &TestContext, toml_text: &str, expected: &str) {
        let message = refusal(context, toml_text);
        assert!(
            message.contains(expected),
            "expected {expected:?} in {message:?}"
        );
        assert!(message.contains("\"/h/.config/agent-vm/projects/abc/config.toml\""));
    }

    const PROJECT_CONFIG: &str = "/h/.config/agent-vm/projects/abc/config.toml";

    #[test]
    fn tables_accept_all_four_combinations_and_defaults() {
        let context = TestContext::new();
        let listed = context.parse_ok(
            r#"
            [[sources]]
            name = "home"
            path = "~/.config/agent-vm/config.toml"
            trust = true
            allow = true

            [[sources]]
            name = "team"
            path = "/srv/team.toml"
            trust = true

            [[sources]]
            name = "repo"
            path = "./conf/agent-vm.toml"
            allow = false
            "#,
        );
        assert_eq!(listed.sourcing(), Sourcing::Listed);
        let entries = listed.entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(
            entries[0].attributes(),
            SourceAttributes {
                trust: true,
                allow: true
            }
        );
        assert_eq!(
            entries[1].attributes(),
            SourceAttributes {
                trust: true,
                allow: false
            }
        );
        assert_eq!(
            entries[2].attributes(),
            SourceAttributes {
                trust: false,
                allow: false
            }
        );
        assert_eq!(entries[2].path(), Path::new("/w/app/conf/agent-vm.toml"));
        assert_eq!(entries[2].declared(), Declaration::Entry(2));
        assert_eq!(entries[2].declared().to_string(), "sources[2]");
        assert_eq!(
            entries[0].path(),
            Path::new("/h/.config/agent-vm/config.toml")
        );
    }

    #[test]
    fn minimal_table_defaults_both_attributes_to_false() {
        let context = TestContext::new();
        let listed = context.parse_ok(
            r#"
            [[sources]]
            name = "repo"
            path = "./x.toml"
            "#,
        );
        let entry = &listed.entries()[0];
        assert!(!entry.is_trusted());
        assert!(!entry.is_allowed());
        assert_eq!(entry.attributes(), SourceAttributes::default());
    }

    #[test]
    fn an_empty_array_is_valid_and_sources_nothing() {
        let context = TestContext::new();
        let listed = context.parse_ok("sources = []\n");
        assert_eq!(listed.sourcing(), Sourcing::Listed);
        assert!(listed.entries().is_empty());
    }

    #[test]
    fn non_array_values_are_refused() {
        let context = TestContext::new();
        for value in ["sources = \"x\"\n", "sources = {}\n", "sources = 1\n"] {
            assert_fragment(
                &context,
                value,
                "sources: must be an array of [[sources]] tables (or sources = [])",
            );
        }
    }

    #[test]
    fn old_string_entries_are_refused_with_the_migration_message() {
        let context = TestContext::new();
        for value in [
            "sources = [\"home:trust ~/.config/agent-vm/config.toml\"]\n",
            "sources = [\"repo ./x.toml\"]\n",
            "sources = [{ name = \"a\", path = \"./a.toml\" }, \"b ./b.toml\"]\n",
        ] {
            for marker in [
                "sources[",
                "string entries (\"<alias>[:trust] <path>\") are no longer supported",
                "declare each source as a [[sources]] table with name = \"...\", path = \"...\"",
                "trust = true / allow = true",
            ] {
                assert!(
                    refusal(&context, value).contains(marker),
                    "{value:?} missing {marker:?}: {}",
                    refusal(&context, value)
                );
            }
        }
    }

    #[test]
    fn non_table_elements_are_refused() {
        let context = TestContext::new();
        for value in [
            "sources = [123]\n",
            "sources = [true]\n",
            "sources = [[]]\n",
        ] {
            assert_fragment(
                &context,
                value,
                "sources[0]: must be a [[sources]] table with name and path",
            );
        }
    }

    #[test]
    fn required_and_typed_keys_are_validated() {
        let context = TestContext::new();
        let cases = [
            (
                "[[sources]]\npath = \"./x.toml\"\n",
                "sources[0]: missing required key \"name\"",
            ),
            (
                "[[sources]]\nname = 1\npath = \"./x.toml\"\n",
                "sources[0].name: must be a string",
            ),
            (
                "[[sources]]\nname = \"Repo\"\npath = \"./x.toml\"\n",
                "sources[0].name: an alias is 1 to 32 characters",
            ),
            (
                "[[sources]]\nname = \"repo\"\n",
                "sources[0]: missing required key \"path\"",
            ),
            (
                "[[sources]]\nname = \"repo\"\npath = 1\n",
                "sources[0].path: must be a string",
            ),
            (
                "[[sources]]\nname = \"repo\"\npath = \"\"\n",
                "sources[0].path: the path is empty",
            ),
            (
                "[[sources]]\nname = \"repo\"\npath = \" ./x.toml\"\n",
                "sources[0].path: the path starts or ends with whitespace",
            ),
            (
                "[[sources]]\nname = \"repo\"\npath = \"./x.toml \"\n",
                "sources[0].path: the path starts or ends with whitespace",
            ),
            (
                "[[sources]]\nname = \"repo\"\npath = \"./x\\u0007.toml\"\n",
                "sources[0].path: the path contains a control character",
            ),
            (
                "[[sources]]\nname = \"repo\"\npath = \"~\"\n",
                "sources[0].path: only \"~/\" is expanded",
            ),
            (
                "[[sources]]\nname = \"repo\"\npath = \"~mu/x.toml\"\n",
                "sources[0].path: only \"~/\" is expanded",
            ),
            (
                "[[sources]]\nname = \"repo\"\npath = \"./x.toml\"\ntrust = \"true\"\n",
                "sources[0].trust: must be true or false",
            ),
            (
                "[[sources]]\nname = \"repo\"\npath = \"./x.toml\"\nallow = 1\n",
                "sources[0].allow: must be true or false",
            ),
        ];
        for (value, expected) in cases {
            assert_fragment(&context, value, expected);
        }
    }

    #[test]
    fn unknown_keys_are_refused_value_safely_and_top_level_fields_get_the_hint() {
        let context = TestContext::new();
        assert_fragment(
            &context,
            "[[sources]]\nname = \"repo\"\npath = \"./x.toml\"\nSECRET-748 = 1\n",
            "sources[0]: unknown key; supported keys are name, path, trust and allow",
        );
        let message = refusal(
            &context,
            "[[sources]]\nname = \"repo\"\npath = \"./x.toml\"\nSECRET-748 = 1\n",
        );
        assert!(!message.contains("SECRET-748"), "{message}");

        for field in [
            "allow_tools",
            "egress_sets",
            "image",
            "mounts",
            "mount_sets",
            "network",
            "sources",
            "tools",
        ] {
            let value = format!("[[sources]]\nname = \"repo\"\npath = \"./x.toml\"\n{field} = 1\n");
            let message = refusal(&context, &value);
            assert!(
                message.contains(&format!(
                    "sources[0]: {field} is not a source key; top-level {field} must be written \
                     before the first [[sources]] or table header"
                )),
                "{message}"
            );
        }
    }

    #[test]
    fn set_rules_refuse_duplicates_and_self_sourcing() {
        let context = TestContext::new();
        assert_fragment(
            &context,
            "[[sources]]\nname = \"repo\"\npath = \"./a.toml\"\n\
             [[sources]]\nname = \"repo\"\npath = \"./b.toml\"\n",
            "sources[1]: the alias is already declared by sources[0]",
        );
        assert_fragment(
            &context,
            "[[sources]]\nname = \"one\"\npath = \"./a.toml\"\n\
             [[sources]]\nname = \"two\"\npath = \"/w/app/a.toml\"\n",
            "sources[1]: this file is already sourced by sources[0]",
        );
        assert_fragment(
            &context,
            &format!("[[sources]]\nname = \"self\"\npath = \"{PROJECT_CONFIG}\"\n"),
            "sources[0]: the project config cannot source itself",
        );
    }

    /// `count` distinct `[[sources]]` tables, each naming its own file.
    fn distinct_sources(count: usize) -> String {
        (0..count)
            .map(|index| {
                format!("[[sources]]\nname = \"s{index}\"\npath = \"/srv/{index}.toml\"\n")
            })
            .collect()
    }

    /// The list bound is checked before any entry is scanned: at the limit the
    /// config is accepted, one past it is refused, and the refusal names the limit
    /// without echoing what the user wrote.
    #[test]
    fn the_declared_source_count_is_bounded() {
        let context = TestContext::new();
        let at_the_limit = context.parse_ok(&distinct_sources(MAX_DECLARED_SOURCES));
        assert_eq!(at_the_limit.entries().len(), MAX_DECLARED_SOURCES);
        assert_eq!(
            at_the_limit
                .entries()
                .last()
                .expect("the last entry")
                .declared(),
            Declaration::Entry(MAX_DECLARED_SOURCES - 1)
        );

        let message = refusal(&context, &distinct_sources(MAX_DECLARED_SOURCES + 1));
        assert!(
            message.contains(&format!(
                "sources: more than {MAX_DECLARED_SOURCES} declared sources"
            )),
            "the limit must be named: {message}"
        );
        assert!(message.contains(PROJECT_CONFIG), "{message}");
        assert!(
            !message.contains("/srv/"),
            "the refusal is value-free: {message}"
        );
    }

    /// A duplicate anywhere in a maximal list gets the same sentence a two-entry
    /// list gets, and the map proves it holds the **first** declaring index, so the
    /// diagnostic names the entry the user has to change.
    #[test]
    fn a_duplicate_at_the_end_of_a_maximal_list_is_refused() {
        let context = TestContext::new();
        let last = MAX_DECLARED_SOURCES - 1;

        let mut aliased = distinct_sources(last);
        aliased.push_str("[[sources]]\nname = \"s0\"\npath = \"/srv/last.toml\"\n");
        let alias_refusal = format!("sources[{last}]: the alias is already declared by sources[0]");
        assert!(refusal(&context, &aliased).contains(&alias_refusal));

        let mut pathed = distinct_sources(last);
        pathed.push_str("[[sources]]\nname = \"last\"\npath = \"/srv/0.toml\"\n");
        let path_refusal = format!("sources[{last}]: this file is already sourced by sources[0]");
        assert!(refusal(&context, &pathed).contains(&path_refusal));
    }

    /// Duplicate detection is one map lookup per entry, so indexing a list is
    /// linear: a rescan of every earlier entry (the shape this replaced) is
    /// quadratic and cannot index 100,000 entries anywhere near the bound. The
    /// count is far past `MAX_DECLARED_SOURCES` on purpose — the duplicate check is
    /// the one part that must not get more expensive as the list grows.
    #[test]
    fn duplicate_detection_is_one_lookup_per_entry() {
        let file = Path::new(PROJECT_CONFIG);
        let entries: Vec<SourceEntry> = (0..100_000)
            .map(|index| SourceEntry {
                declared: Declaration::Entry(index),
                alias: SourceAlias::for_test(&format!("s{index}")),
                attributes: SourceAttributes::default(),
                path: PathBuf::from(format!("/srv/{index}.toml")),
                spelled_relative: false,
            })
            .collect();
        let mut index = DeclaredIndex::default();
        let started = std::time::Instant::now();
        for (position, entry) in entries.iter().enumerate() {
            index
                .record(position, entry, file)
                .expect("distinct entries");
        }
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "indexing {} entries took {elapsed:?}",
            entries.len()
        );

        let duplicate = SourceEntry {
            declared: Declaration::Entry(entries.len()),
            ..entries[0].clone()
        };
        assert!(index.record(entries.len(), &duplicate, file).is_err());
    }

    #[test]
    fn refusals_never_echo_the_offending_values() {
        let context = TestContext::new();
        for value in [
            "sources = [\"SECRET-748 x.toml\"]\n",
            "[[sources]]\nname = \"SECRET-748\"\npath = \"./x.toml\"\n",
            "[[sources]]\nname = \"repo\"\npath = \"./SECRET-748\"\ntrust = \"SECRET-748\"\n",
            "[[sources]]\nname = \"repo\"\npath = \"./x.toml\"\nzz_SECRET-748 = 1\n",
        ] {
            let message = refusal(&context, value);
            assert!(!message.contains("SECRET-748"), "{message}");
        }
    }

    #[test]
    fn paths_resolve_lexically() {
        let context = TestContext::new();
        for (spelled, expected) in [
            ("~/a/b", "/h/a/b"),
            // A repeated separator must never rebase the path onto `/`.
            ("~//x", "/h/x"),
            ("~///a//b", "/h/a/b"),
            ("./a", "/w/app/a"),
            ("a", "/w/app/a"),
            ("./a/./b", "/w/app/a/b"),
            ("./.agent-vm/config.toml", "/w/app/.agent-vm/config.toml"),
            // `..` stays uncollapsed: the OS resolves it through a symlink.
            ("../outside/a.toml", "/w/app/../outside/a.toml"),
            ("sub/../a.toml", "/w/app/sub/../a.toml"),
            // Absolute spellings take the same component walk as relative ones.
            ("/x/y", "/x/y"),
            ("/x//y/./z.toml", "/x/y/z.toml"),
            ("/x/y/../z.toml", "/x/y/../z.toml"),
        ] {
            let listed = context.parse_ok(&format!(
                "[[sources]]\nname = \"repo\"\npath = {spelled:?}\n"
            ));
            assert_eq!(
                listed.entries()[0]
                    .path()
                    .to_str()
                    .expect("UTF-8 test path"),
                expected,
                "{spelled:?}"
            );
        }
    }

    /// The one shape rule `PinKey` will reuse: absolute, interior `.`/`//`
    /// dropped, `..` kept, and a trailing directory assertion refused.
    #[test]
    fn lexical_normalization_is_shared_and_directory_assertions_are_refused() {
        for (raw, expected) in [
            ("/a/b.toml", Some("/a/b.toml")),
            ("/a//b.toml", Some("/a/b.toml")),
            ("/a/./b.toml", Some("/a/b.toml")),
            ("/a/b/../c.toml", Some("/a/b/../c.toml")),
            ("/a/../b.toml", Some("/a/../b.toml")),
            // Not absolute, or a directory assertion.
            ("a/b.toml", None),
            ("/", None),
            ("/a/", None),
            ("/a//", None),
            ("/a/.", None),
            ("/a/..", None),
            ("", None),
        ] {
            assert_eq!(
                normalize_lexical_absolute(Path::new(raw)).as_deref(),
                expected.map(Path::new),
                "{raw:?}"
            );
        }
    }

    /// A directory spelling must never silently read as the regular file it
    /// happens to name; the refusal is uniform across anchors.
    #[test]
    fn a_trailing_directory_assertion_is_refused_for_every_anchor() {
        let context = TestContext::new();
        for spelled in [
            "~/", "~//", "/", "./", "a/", "./a/", "/a/b/", "/a/b/.", "/a/b/..", "../",
        ] {
            let message = refusal(
                &context,
                &format!("[[sources]]\nname = \"repo\"\npath = {spelled:?}\n"),
            );
            assert!(
                message.contains("the path names a directory"),
                "{spelled:?}: {message}"
            );
        }
    }

    #[test]
    fn by_alias_finds_declared_entries_only() {
        let context = TestContext::new();
        let listed = context.parse_ok(
            "[[sources]]\nname = \"repo\"\npath = \"./r.toml\"\n\
             [[sources]]\nname = \"home\"\npath = \"~/.config/agent-vm/config.toml\"\n\
             trust = true\nallow = true\n",
        );
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
    fn image_alias_recognises_only_the_exact_shape() {
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
    fn implicit_sourcing_is_the_trusted_allowed_user_config_or_nothing() {
        let user_config = PathBuf::from("/h/.config/agent-vm/config.toml");
        let implicit = DeclaredSources::implicit(Some(&user_config));
        assert_eq!(implicit.sourcing(), Sourcing::Implicit);
        assert_eq!(implicit.entries().len(), 1);
        let entry = &implicit.entries()[0];
        assert_eq!(entry.alias().as_str(), HOME_ALIAS);
        assert!(entry.is_trusted());
        assert!(entry.is_allowed());
        assert_eq!(
            entry.attributes(),
            SourceAttributes {
                trust: true,
                allow: true
            }
        );
        assert_eq!(entry.path(), user_config);
        assert!(!entry.is_spelled_relative());
        assert_eq!(entry.declared(), Declaration::Implicit);
        assert_eq!(entry.declared().to_string(), "the default home source");

        let unavailable = DeclaredSources::implicit(None);
        assert!(unavailable.entries().is_empty());
        assert_eq!(unavailable.sourcing(), Sourcing::Implicit);
    }

    #[test]
    fn extraction_finds_only_trusted_host_anchored_paths() {
        let home = Path::new("/h");
        let text = r#"
            [[sources]]
            name = "team"
            path = "~/team.toml"
            trust = true

            [[sources]]
            name = "abs"
            path = "/srv/abs.toml"
            trust = true

            [[sources]]
            name = "repo"
            path = "./repo.toml"
            trust = true

            [[sources]]
            name = "pinned"
            path = "~/pinned.toml"
            "#;
        assert_eq!(
            extract_trusted_non_relative_paths(text, home),
            vec![
                PathBuf::from("/h/team.toml"),
                PathBuf::from("/srv/abs.toml")
            ]
        );
        assert!(extract_trusted_non_relative_paths("sources = [unclosed", home).is_empty());
        assert!(extract_trusted_non_relative_paths("", home).is_empty());
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
