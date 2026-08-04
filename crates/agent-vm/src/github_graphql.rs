//! Repo allow-list filtering for `POST api.github.com/graphql` bodies.
//!
//! The REST policy in `intercept_hook` scopes `/repos/<owner>/<repo>`
//! paths against the per-launch allow-list, but gh CLI does most of
//! its reads over GraphQL — `gh repo list` (`repositoryOwner(login:)
//! { repositories … }`), `gh repo view` (`repository(owner:, name:)`),
//! `gh pr`/`gh issue` (same), and arbitrary `gh api graphql`. Passing
//! `/graphql` through authenticated therefore let an in-VM agent
//! enumerate every repo the host token can see and read private-repo
//! contents via blob queries.
//!
//! Policy mirrors the REST one: a query gets the user's token iff
//! every piece of repository-scoped data it can return is scoped to
//! an allow-listed repo; anything else is forwarded anonymously (the
//! Authorization header is dropped — GitHub's GraphQL endpoint then
//! 401s, exactly what a third party without a token gets).
//!
//! Concretely, a request is **Authenticated** only when the document
//! parses and every operation satisfies:
//!
//! * `query` root fields limited to: `repository(owner:, name:)` with
//!   the resolved slug in the allow-list; `viewer` restricted to
//!   scalar identity fields (`login`, `id`, `name`, `email`, `url`,
//!   `databaseId`, `__typename`) — same information as REST `/user`;
//!   `search` whose `query:` argument is scoped by positive `repo:`
//!   qualifiers that are all allow-listed (what `gh pr status` sends);
//!   `rateLimit` and schema introspection.
//! * Repo-enumerating connection fields are rejected at **any**
//!   depth, because `User`/`Organization` objects reachable from an
//!   allowed subtree (e.g. `repository { owner { … } }`) re-expose
//!   them: `repositories`, `repositoriesContributedTo`,
//!   `topRepositories`, `starredRepositories`, `watching`,
//!   `repositoryOwner`, `organization`, `enterprise`, `user`.
//! * Any `repository`/`search` field carrying owner/name/query
//!   arguments — wherever it appears — passes the same allow-list
//!   check. (`repository` *without* those args, e.g. inside a search
//!   result node, is a child object already scoped by its parent and
//!   is fine.)
//! * `mutation` root fields are not name-restricted (gh needs
//!   `createPullRequest`, `mergePullRequest`, `addComment`, … and
//!   their inputs are opaque node IDs we cannot map to a repo), but
//!   their result subtrees get the same banned-field / argument
//!   checks. Node IDs for private objects are only obtainable through
//!   already-filtered reads, so the residual surface is writes to
//!   *public* repos via forged/out-of-band IDs — the price of keeping
//!   gh's PR workflow functional. `subscription` operations are
//!   always anonymous.
//!
//! Anything the parser doesn't understand — malformed JSON, GraphQL
//! syntax we don't model, variables that aren't plain strings —
//! resolves to **Anonymous**, never to Authenticated.

use std::collections::{HashMap, HashSet};

use serde_json::Value;

/// Decision for one buffered `/graphql` request body.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub enum GraphqlAccess {
    /// Forward with the host user's real token.
    Authenticated,
    /// Forward without Authorization (GitHub 401s the whole request).
    Anonymous,
}

/// Repo-enumerating / cross-repo connection fields, banned at any
/// depth. See module docs for why depth doesn't matter here.
const BANNED_FIELDS: &[&str] = &[
    "repositories",
    "repositoriesContributedTo",
    "topRepositories",
    "starredRepositories",
    "watching",
    "repositoryOwner",
    "organization",
    "enterprise",
    "user",
];

/// Scalar identity fields allowed under a root `viewer` selection —
/// the GraphQL equivalent of the REST policy's authenticated `/user`.
/// Everything else on `User` (pullRequests, issues, gists, …) spans
/// repos and would leak private inventory.
const VIEWER_SCALAR_FIELDS: &[&str] =
    &["login", "id", "name", "email", "url", "databaseId", "__typename"];

/// Cap on fragment-spread nesting during validation; combined with
/// the visited-set cycle guard this bounds pathological documents.
const MAX_FRAGMENT_DEPTH: usize = 32;

/// Decide whether a `/graphql` request body may carry the user's
/// token. `allowed` is the per-launch `owner/repo` allow-list
/// (compared case-insensitively).
pub fn graphql_access(body: &[u8], allowed: &[String]) -> GraphqlAccess {
    match evaluate(body, allowed) {
        Some(true) => GraphqlAccess::Authenticated,
        _ => GraphqlAccess::Anonymous,
    }
}

fn evaluate(body: &[u8], allowed: &[String]) -> Option<bool> {
    let json: Value = serde_json::from_slice(body).ok()?;
    let query = json.get("query")?.as_str()?;
    // `variables` may be absent or null; non-string values only matter
    // if something we must resolve references them (then: Anonymous).
    let variables: HashMap<String, String> = json
        .get("variables")
        .and_then(|v| v.as_object())
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    let doc = parse_document(query)?;
    let fragments: HashMap<&str, &Vec<Sel>> = doc
        .fragments
        .iter()
        .map(|f| (f.name.as_str(), &f.sel))
        .collect();

    // Every operation in the document must pass — gh sends one, but a
    // crafted body could batch a benign op with a leaking one.
    for op in &doc.ops {
        let ctx = Ctx {
            allowed,
            variables: &variables,
            defaults: &op.var_defaults,
            fragments: &fragments,
        };
        let ok = match op.kind {
            OpKind::Query => validate_query_root(&op.sel, &ctx, 0),
            OpKind::Mutation => validate_mutation_root(&op.sel, &ctx),
            OpKind::Subscription => false,
        };
        if !ok {
            return Some(false);
        }
    }
    Some(!doc.ops.is_empty())
}

// ─── validation ───────────────────────────────────────────────────────

struct Ctx<'a> {
    allowed: &'a [String],
    variables: &'a HashMap<String, String>,
    defaults: &'a HashMap<String, String>,
    fragments: &'a HashMap<&'a str, &'a Vec<Sel>>,
}

impl Ctx<'_> {
    fn resolve(&self, v: &Val) -> Option<String> {
        match v {
            Val::Str(s) => Some(s.clone()),
            Val::Var(name) => self
                .variables
                .get(name)
                .or_else(|| self.defaults.get(name))
                .cloned(),
            Val::Other => None,
        }
    }

    fn slug_allowed(&self, owner: &str, name: &str) -> bool {
        let slug = format!("{owner}/{name}");
        self.allowed.iter().any(|a| a.eq_ignore_ascii_case(&slug))
    }
}

fn arg<'a>(field: &'a Field, key: &str) -> Option<&'a Val> {
    field.args.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// `repository`-shaped field check, applied at any depth. Fields
/// *without* owner/name args are child objects scoped by their parent
/// and pass; a field carrying either arg must resolve both to an
/// allow-listed slug.
fn repository_args_ok(field: &Field, ctx: &Ctx) -> bool {
    let owner = arg(field, "owner");
    let name = arg(field, "name");
    if owner.is_none() && name.is_none() {
        return true;
    }
    let (Some(owner), Some(name)) = (owner, name) else {
        return false;
    };
    match (ctx.resolve(owner), ctx.resolve(name)) {
        (Some(o), Some(n)) => ctx.slug_allowed(&o, &n),
        _ => false,
    }
}

/// `search(query: …)` is allowed only when the search string is
/// positively scoped by `repo:` qualifiers that are all allow-listed
/// (matching gh's own `repo:owner/name is:pr …` shape). Qualifiers
/// that broaden scope (`org:`, `user:`, `owner:`) reject.
fn search_args_ok(field: &Field, ctx: &Ctx) -> bool {
    let Some(q) = arg(field, "query").and_then(|v| ctx.resolve(v)) else {
        return false;
    };
    let mut saw_repo = false;
    for token in q.split_whitespace() {
        let t = token.trim_matches('"');
        let lower = t.to_ascii_lowercase();
        if lower.starts_with("org:") || lower.starts_with("user:") || lower.starts_with("owner:") {
            return false;
        }
        if let Some(slug) = lower.strip_prefix("repo:") {
            if !ctx.allowed.iter().any(|a| a.eq_ignore_ascii_case(slug)) {
                return false;
            }
            saw_repo = true;
        }
    }
    saw_repo
}

/// Shared per-field checks + recursion, used inside every allowed
/// subtree (repository, search results, rateLimit, mutation results).
fn validate_generic(sel: &[Sel], ctx: &Ctx, depth: usize, visiting: &mut HashSet<String>) -> bool {
    if depth > MAX_FRAGMENT_DEPTH {
        return false;
    }
    for s in sel {
        match s {
            Sel::Field(f) => {
                if BANNED_FIELDS.contains(&f.name.as_str()) {
                    return false;
                }
                if f.name == "repository" && !repository_args_ok(f, ctx) {
                    return false;
                }
                if f.name == "search" && !search_args_ok(f, ctx) {
                    return false;
                }
                if !validate_generic(&f.sel, ctx, depth, visiting) {
                    return false;
                }
            }
            Sel::Spread(name) => {
                if !validate_fragment(name, ctx, depth, visiting) {
                    return false;
                }
            }
            Sel::Inline(inner) => {
                if !validate_generic(inner, ctx, depth, visiting) {
                    return false;
                }
            }
        }
    }
    true
}

fn validate_fragment(name: &str, ctx: &Ctx, depth: usize, visiting: &mut HashSet<String>) -> bool {
    let Some(sel) = ctx.fragments.get(name) else {
        return false; // spread of an undefined fragment: refuse
    };
    if !visiting.insert(name.to_string()) {
        return false; // cycle
    }
    let ok = validate_generic(sel, ctx, depth + 1, visiting);
    visiting.remove(name);
    ok
}

/// Root selections of a `query` operation: whitelist of entry points.
fn validate_query_root(sel: &[Sel], ctx: &Ctx, depth: usize) -> bool {
    if depth > MAX_FRAGMENT_DEPTH || sel.is_empty() {
        return false;
    }
    for s in sel {
        match s {
            Sel::Field(f) => {
                let mut visiting = HashSet::new();
                let ok = match f.name.as_str() {
                    // Must name an allow-listed repo explicitly —
                    // unlike the generic rule, argless `repository`
                    // at the root would be schema-invalid anyway.
                    "repository" => {
                        arg(f, "owner").is_some()
                            && arg(f, "name").is_some()
                            && repository_args_ok(f, ctx)
                            && validate_generic(&f.sel, ctx, depth, &mut visiting)
                    }
                    "viewer" => validate_viewer(&f.sel),
                    "search" => {
                        search_args_ok(f, ctx)
                            && validate_generic(&f.sel, ctx, depth, &mut visiting)
                    }
                    "rateLimit" | "__typename" | "__schema" | "__type" => {
                        validate_generic(&f.sel, ctx, depth, &mut visiting)
                    }
                    _ => false,
                };
                if !ok {
                    return false;
                }
            }
            // Root-level fragment spread / inline fragment (fragment
            // on Query): apply the root rules to its selections.
            Sel::Spread(name) => {
                let Some(frag_sel) = ctx.fragments.get(name.as_str()) else {
                    return false;
                };
                if !validate_query_root(frag_sel, ctx, depth + 1) {
                    return false;
                }
            }
            Sel::Inline(inner) => {
                if !validate_query_root(inner, ctx, depth + 1) {
                    return false;
                }
            }
        }
    }
    true
}

/// `viewer { … }` restricted to scalar identity fields: no arguments,
/// no sub-selections, names from [`VIEWER_SCALAR_FIELDS`].
fn validate_viewer(sel: &[Sel]) -> bool {
    if sel.is_empty() {
        return false;
    }
    sel.iter().all(|s| match s {
        Sel::Field(f) => {
            f.args.is_empty()
                && f.sel.is_empty()
                && VIEWER_SCALAR_FIELDS.contains(&f.name.as_str())
        }
        _ => false,
    })
}

/// Mutation roots keep their names (see module docs) but the result
/// subtrees and any owner/name-bearing fields still get checked.
fn validate_mutation_root(sel: &[Sel], ctx: &Ctx) -> bool {
    if sel.is_empty() {
        return false;
    }
    let mut visiting = HashSet::new();
    validate_generic(sel, ctx, 0, &mut visiting)
}

// ─── GraphQL document model ───────────────────────────────────────────

struct Doc {
    ops: Vec<Op>,
    fragments: Vec<Fragment>,
}

enum OpKind {
    Query,
    Mutation,
    Subscription,
}

struct Op {
    kind: OpKind,
    /// String-literal defaults from the operation's variable
    /// definitions (`$owner: String = "x"`), used as resolution
    /// fallback when the request's `variables` omits one.
    var_defaults: HashMap<String, String>,
    sel: Vec<Sel>,
}

struct Fragment {
    name: String,
    sel: Vec<Sel>,
}

enum Sel {
    Field(Field),
    /// `...FragmentName`
    Spread(String),
    /// `... on Type { … }` (type condition irrelevant to the policy)
    Inline(Vec<Sel>),
}

struct Field {
    name: String,
    args: Vec<(String, Val)>,
    sel: Vec<Sel>,
}

enum Val {
    Str(String),
    Var(String),
    /// Numbers, booleans, enums, null, lists, input objects — nothing
    /// the policy resolves through.
    Other,
}

// ─── lexer ────────────────────────────────────────────────────────────

#[derive(PartialEq)]
enum Tok {
    Name(String),
    Str(String),
    Var(String),
    Num,
    Punct(char),
    Spread,
}

/// Tokenize a GraphQL document. Returns `None` on anything malformed
/// — the caller then refuses authentication rather than guessing.
fn lex(src: &str) -> Option<Vec<Tok>> {
    let mut toks = Vec::new();
    let b = src.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        match c {
            // Insignificant: whitespace, commas, BOM handled by u8 skip.
            b' ' | b'\t' | b'\r' | b'\n' | b',' => i += 1,
            b'#' => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'"' => {
                if b[i..].starts_with(b"\"\"\"") {
                    // Block string: scan to closing """.
                    let rest = &src[i + 3..];
                    let end = rest.find("\"\"\"")?;
                    toks.push(Tok::Str(rest[..end].to_string()));
                    i += 3 + end + 3;
                } else {
                    let (s, consumed) = lex_string(&src[i + 1..])?;
                    toks.push(Tok::Str(s));
                    i += 1 + consumed;
                }
            }
            b'$' => {
                let start = i + 1;
                let mut j = start;
                while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
                    j += 1;
                }
                if j == start {
                    return None;
                }
                toks.push(Tok::Var(src[start..j].to_string()));
                i = j;
            }
            b'.' => {
                if b[i..].starts_with(b"...") {
                    toks.push(Tok::Spread);
                    i += 3;
                } else {
                    return None;
                }
            }
            b'{' | b'}' | b'(' | b')' | b'[' | b']' | b':' | b'=' | b'@' | b'!' | b'|' | b'&' => {
                toks.push(Tok::Punct(c as char));
                i += 1;
            }
            b'-' | b'0'..=b'9' => {
                let mut j = i + 1;
                while j < b.len()
                    && (b[j].is_ascii_digit()
                        || matches!(b[j], b'.' | b'e' | b'E' | b'+' | b'-'))
                {
                    j += 1;
                }
                toks.push(Tok::Num);
                i = j;
            }
            _ if c.is_ascii_alphabetic() || c == b'_' => {
                let mut j = i + 1;
                while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
                    j += 1;
                }
                toks.push(Tok::Name(src[i..j].to_string()));
                i = j;
            }
            _ => return None,
        }
    }
    Some(toks)
}

/// Lex a normal (non-block) string body starting *after* the opening
/// quote. Returns the decoded string and the number of source bytes
/// consumed including the closing quote.
fn lex_string(rest: &str) -> Option<(String, usize)> {
    let b = rest.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'"' => return Some((out, i + 1)),
            b'\\' => {
                let esc = *b.get(i + 1)?;
                match esc {
                    b'"' | b'\\' | b'/' => out.push(esc as char),
                    b'n' => out.push('\n'),
                    b't' => out.push('\t'),
                    b'r' => out.push('\r'),
                    b'b' => out.push('\u{8}'),
                    b'f' => out.push('\u{c}'),
                    b'u' => {
                        let hex = rest.get(i + 2..i + 6)?;
                        let code = u32::from_str_radix(hex, 16).ok()?;
                        out.push(char::from_u32(code)?);
                        i += 4;
                    }
                    _ => return None,
                }
                i += 2;
            }
            _ => {
                // Multi-byte UTF-8: copy the whole scalar.
                let ch = rest[i..].chars().next()?;
                out.push(ch);
                i += ch.len_utf8();
            }
        }
    }
    None // unterminated
}

// ─── parser ───────────────────────────────────────────────────────────

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

fn parse_document(src: &str) -> Option<Doc> {
    let mut p = Parser {
        toks: lex(src)?,
        pos: 0,
    };
    let mut doc = Doc {
        ops: Vec::new(),
        fragments: Vec::new(),
    };
    while !p.at_end() {
        match p.peek()? {
            Tok::Name(n) if n == "fragment" => {
                p.pos += 1;
                let name = p.name()?;
                p.expect_name("on")?;
                let _type = p.name()?;
                p.skip_directives()?;
                let sel = p.selection_set()?;
                doc.fragments.push(Fragment { name, sel });
            }
            Tok::Name(n) if matches!(n.as_str(), "query" | "mutation" | "subscription") => {
                let kind = match n.as_str() {
                    "query" => OpKind::Query,
                    "mutation" => OpKind::Mutation,
                    _ => OpKind::Subscription,
                };
                p.pos += 1;
                // Optional operation name.
                if let Some(Tok::Name(_)) = p.peek() {
                    p.pos += 1;
                }
                let var_defaults = if p.peek() == Some(&Tok::Punct('(')) {
                    p.variable_definitions()?
                } else {
                    HashMap::new()
                };
                p.skip_directives()?;
                let sel = p.selection_set()?;
                doc.ops.push(Op {
                    kind,
                    var_defaults,
                    sel,
                });
            }
            // Query shorthand: bare selection set.
            Tok::Punct('{') => {
                let sel = p.selection_set()?;
                doc.ops.push(Op {
                    kind: OpKind::Query,
                    var_defaults: HashMap::new(),
                    sel,
                });
            }
            _ => return None,
        }
    }
    Some(doc)
}

impl Parser {
    fn at_end(&self) -> bool {
        self.pos >= self.toks.len()
    }

    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn next(&mut self) -> Option<&Tok> {
        let t = self.toks.get(self.pos);
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn name(&mut self) -> Option<String> {
        match self.next()? {
            Tok::Name(n) => Some(n.clone()),
            _ => None,
        }
    }

    fn expect_name(&mut self, want: &str) -> Option<()> {
        match self.next()? {
            Tok::Name(n) if n == want => Some(()),
            _ => None,
        }
    }

    fn expect_punct(&mut self, want: char) -> Option<()> {
        match self.next()? {
            Tok::Punct(c) if *c == want => Some(()),
            _ => None,
        }
    }

    /// `( $name: Type = default … )` — collect string-literal defaults.
    fn variable_definitions(&mut self) -> Option<HashMap<String, String>> {
        self.expect_punct('(')?;
        let mut defaults = HashMap::new();
        loop {
            match self.next()? {
                Tok::Punct(')') => return Some(defaults),
                Tok::Var(name) => {
                    let name = name.clone();
                    self.expect_punct(':')?;
                    // Type: Name with arbitrary [ ] ! nesting.
                    loop {
                        match self.peek()? {
                            Tok::Name(_) | Tok::Punct('[') | Tok::Punct(']')
                            | Tok::Punct('!') => {
                                self.pos += 1;
                            }
                            _ => break,
                        }
                    }
                    if self.peek() == Some(&Tok::Punct('=')) {
                        self.pos += 1;
                        if let Val::Str(s) = self.value()? {
                            defaults.insert(name, s);
                        }
                    }
                    // Directives on variable definitions are legal.
                    self.skip_directives()?;
                }
                _ => return None,
            }
        }
    }

    fn selection_set(&mut self) -> Option<Vec<Sel>> {
        self.expect_punct('{')?;
        let mut sels = Vec::new();
        loop {
            match self.peek()? {
                Tok::Punct('}') => {
                    self.pos += 1;
                    return Some(sels);
                }
                Tok::Spread => {
                    self.pos += 1;
                    match self.peek()? {
                        Tok::Name(n) if n == "on" => {
                            self.pos += 1;
                            let _type = self.name()?;
                            self.skip_directives()?;
                            sels.push(Sel::Inline(self.selection_set()?));
                        }
                        Tok::Name(_) => {
                            let name = self.name()?;
                            self.skip_directives()?;
                            sels.push(Sel::Spread(name));
                        }
                        // `... @include(if:) { … }` — inline fragment
                        // without a type condition.
                        Tok::Punct('@') | Tok::Punct('{') => {
                            self.skip_directives()?;
                            sels.push(Sel::Inline(self.selection_set()?));
                        }
                        _ => return None,
                    }
                }
                Tok::Name(_) => sels.push(Sel::Field(self.field()?)),
                _ => return None,
            }
        }
    }

    fn field(&mut self) -> Option<Field> {
        let mut name = self.name()?;
        // Alias: `alias: real_name`.
        if self.peek() == Some(&Tok::Punct(':')) {
            self.pos += 1;
            name = self.name()?;
        }
        let mut args = Vec::new();
        if self.peek() == Some(&Tok::Punct('(')) {
            self.pos += 1;
            loop {
                match self.peek()? {
                    Tok::Punct(')') => {
                        self.pos += 1;
                        break;
                    }
                    Tok::Name(_) => {
                        let key = self.name()?;
                        self.expect_punct(':')?;
                        let val = self.value()?;
                        args.push((key, val));
                    }
                    _ => return None,
                }
            }
        }
        self.skip_directives()?;
        let sel = if self.peek() == Some(&Tok::Punct('{')) {
            self.selection_set()?
        } else {
            Vec::new()
        };
        Some(Field { name, args, sel })
    }

    /// Parse a value, returning only what the policy can resolve
    /// (string literals and variables); everything else collapses to
    /// `Val::Other` but is still consumed structurally.
    fn value(&mut self) -> Option<Val> {
        match self.next()? {
            Tok::Str(s) => Some(Val::Str(s.clone())),
            Tok::Var(v) => Some(Val::Var(v.clone())),
            Tok::Num => Some(Val::Other),
            Tok::Name(_) => Some(Val::Other), // enum / true / false / null
            Tok::Punct('[') => {
                loop {
                    if self.peek()? == &Tok::Punct(']') {
                        self.pos += 1;
                        return Some(Val::Other);
                    }
                    self.value()?;
                }
            }
            Tok::Punct('{') => {
                loop {
                    match self.next()? {
                        Tok::Punct('}') => return Some(Val::Other),
                        Tok::Name(_) => {
                            self.expect_punct(':')?;
                            self.value()?;
                        }
                        _ => return None,
                    }
                }
            }
            _ => None,
        }
    }

    fn skip_directives(&mut self) -> Option<()> {
        while self.peek() == Some(&Tok::Punct('@')) {
            self.pos += 1;
            self.name()?;
            if self.peek() == Some(&Tok::Punct('(')) {
                self.pos += 1;
                loop {
                    match self.peek()? {
                        Tok::Punct(')') => {
                            self.pos += 1;
                            break;
                        }
                        Tok::Name(_) => {
                            self.name()?;
                            self.expect_punct(':')?;
                            self.value()?;
                        }
                        _ => return None,
                    }
                }
            }
        }
        Some(())
    }
}

// ─── tests ────────────────────────────────────────────────────────────
//
// Bodies below mirror what gh CLI actually sends (captured via
// `GH_DEBUG=api`): repo enumeration must go anonymous, repo-scoped
// PR/issue/content queries on an allow-listed repo must keep the
// token, and everything unparseable fails to anonymous.

#[cfg(test)]
mod tests {
    use super::*;

    const ALLOWED: &[&str] = &["wirenboard/wb-agent-tools"];

    fn al() -> Vec<String> {
        ALLOWED.iter().map(|s| s.to_string()).collect()
    }

    fn body(query: &str, variables: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "query": query,
            "variables": variables,
        }))
        .unwrap()
    }

    fn access(query: &str, variables: serde_json::Value) -> GraphqlAccess {
        graphql_access(&body(query, variables), &al())
    }

    // ── the reported leak: gh repo list ───────────────────────────

    #[test]
    fn gh_repo_list_enumeration_is_anonymous() {
        // Shape of gh's RepositoryList query (the `gh repo list`
        // command) — repositoryOwner + repositories connection.
        let q = r#"query RepositoryList($owner: String!, $per_page: Int!, $endCursor: String, $privacy: RepositoryPrivacy, $fork: Boolean) {
            repositoryOwner(login: $owner) {
                login
                repositories(first: $per_page, after: $endCursor, privacy: $privacy, isFork: $fork, ownerAffiliations: OWNER, orderBy: { field: PUSHED_AT, direction: DESC }) {
                    totalCount
                    nodes { name nameWithOwner isPrivate }
                    pageInfo { hasNextPage endCursor }
                }
            }
        }"#;
        assert_eq!(
            access(q, serde_json::json!({"owner": "evgeny-boger", "per_page": 30})),
            GraphqlAccess::Anonymous
        );
    }

    #[test]
    fn viewer_repositories_is_anonymous() {
        let q = "query { viewer { repositories(first: 100) { nodes { nameWithOwner } } } }";
        assert_eq!(access(q, serde_json::json!({})), GraphqlAccess::Anonymous);
    }

    #[test]
    fn viewer_cross_repo_connections_are_anonymous() {
        // pullRequests on viewer spans private repos — not in the
        // scalar identity whitelist.
        let q = "query { viewer { login pullRequests(first: 10) { nodes { title } } } }";
        assert_eq!(access(q, serde_json::json!({})), GraphqlAccess::Anonymous);
    }

    // ── allowed-repo flows keep working ───────────────────────────

    #[test]
    fn gh_pr_list_on_allowed_repo_is_authenticated() {
        // Shape of gh's PullRequestList query (`gh pr list`).
        let q = r#"query PullRequestList($owner: String!, $repo: String!, $limit: Int!, $endCursor: String) {
            repository(owner: $owner, name: $repo) {
                pullRequests(first: $limit, after: $endCursor, orderBy: { field: CREATED_AT, direction: DESC }) {
                    totalCount
                    nodes { number title state headRefName author { login } }
                    pageInfo { hasNextPage endCursor }
                }
            }
        }"#;
        assert_eq!(
            access(q, serde_json::json!({"owner": "wirenboard", "repo": "wb-agent-tools", "limit": 30})),
            GraphqlAccess::Authenticated
        );
    }

    #[test]
    fn pr_list_on_other_repo_is_anonymous() {
        let q = r#"query($owner: String!, $repo: String!) {
            repository(owner: $owner, name: $repo) { pullRequests(first: 5) { nodes { title } } }
        }"#;
        assert_eq!(
            access(q, serde_json::json!({"owner": "wirenboard", "repo": "some-private"})),
            GraphqlAccess::Anonymous
        );
    }

    #[test]
    fn blob_read_scoping() {
        // Content download via object(expression:) — the "download
        // any repo" half of the leak. Inline fragment + literals.
        let q = r#"query {
            repository(owner: "wirenboard", name: "wb-agent-tools") {
                object(expression: "HEAD:README.md") { ... on Blob { text } }
            }
        }"#;
        assert_eq!(access(q, serde_json::json!({})), GraphqlAccess::Authenticated);
        let q_other = r#"query {
            repository(owner: "wirenboard", name: "secret-repo") {
                object(expression: "HEAD:README.md") { ... on Blob { text } }
            }
        }"#;
        assert_eq!(access(q_other, serde_json::json!({})), GraphqlAccess::Anonymous);
    }

    #[test]
    fn viewer_login_is_authenticated() {
        // gh resolves the current login constantly (`gh pr create`,
        // `gh pr status`, …). Equivalent to REST /user, which the
        // path policy forwards authenticated.
        assert_eq!(
            access("query UserCurrent { viewer { login } }", serde_json::json!({})),
            GraphqlAccess::Authenticated
        );
        // Query shorthand form.
        assert_eq!(
            access("{ viewer { login } }", serde_json::json!({})),
            GraphqlAccess::Authenticated
        );
    }

    #[test]
    fn allowed_slug_is_case_insensitive() {
        let q = r#"query { repository(owner: "WirenBoard", name: "WB-Agent-Tools") { name } }"#;
        assert_eq!(access(q, serde_json::json!({})), GraphqlAccess::Authenticated);
    }

    #[test]
    fn variable_defaults_resolve() {
        let q = r#"query($owner: String = "wirenboard", $name: String = "wb-agent-tools") {
            repository(owner: $owner, name: $name) { name }
        }"#;
        assert_eq!(access(q, serde_json::json!({})), GraphqlAccess::Authenticated);
        // Request variables override defaults — and must be checked.
        assert_eq!(
            access(q, serde_json::json!({"owner": "wirenboard", "name": "secret-repo"})),
            GraphqlAccess::Anonymous
        );
    }

    #[test]
    fn fragments_are_validated() {
        // gh uses named fragments heavily (fragment repo on
        // Repository { … }). A fragment reached from an allowed
        // subtree is checked with the same rules.
        let ok = r#"
            query { repository(owner: "wirenboard", name: "wb-agent-tools") { ...parts } }
            fragment parts on Repository { name issues(first: 5) { nodes { title } } }
        "#;
        assert_eq!(access(ok, serde_json::json!({})), GraphqlAccess::Authenticated);
        let leak = r#"
            query { repository(owner: "wirenboard", name: "wb-agent-tools") { owner { ...esc } } }
            fragment esc on RepositoryOwner { repositories(first: 5) { nodes { nameWithOwner } } }
        "#;
        assert_eq!(access(leak, serde_json::json!({})), GraphqlAccess::Anonymous);
        // Spread of an undefined fragment: refuse.
        let undef = r#"query { repository(owner: "wirenboard", name: "wb-agent-tools") { ...nope } }"#;
        assert_eq!(access(undef, serde_json::json!({})), GraphqlAccess::Anonymous);
    }

    #[test]
    fn owner_escape_inside_allowed_subtree_is_anonymous() {
        // repository → owner is a User/Organization: its repo
        // connections would re-open enumeration from inside an
        // allowed subtree.
        let q = r#"query { repository(owner: "wirenboard", name: "wb-agent-tools") {
            owner { ... on Organization { repositories(first: 10) { nodes { name } } } }
        } }"#;
        assert_eq!(access(q, serde_json::json!({})), GraphqlAccess::Anonymous);
    }

    // ── search scoping (gh pr status) ─────────────────────────────

    #[test]
    fn search_scoped_to_allowed_repo_is_authenticated() {
        let q = r#"query($q: String!) { search(query: $q, type: ISSUE, first: 30) {
            nodes { ... on PullRequest { number title repository { nameWithOwner } } }
        } }"#;
        assert_eq!(
            access(q, serde_json::json!({"q": "repo:wirenboard/wb-agent-tools is:pr is:open"})),
            GraphqlAccess::Authenticated
        );
        assert_eq!(
            access(q, serde_json::json!({"q": "repo:wirenboard/other is:pr"})),
            GraphqlAccess::Anonymous
        );
        // No repo: qualifier → global search under the user's token.
        assert_eq!(
            access(q, serde_json::json!({"q": "is:pr author:@me"})),
            GraphqlAccess::Anonymous
        );
        // Broadening qualifiers reject even alongside repo:.
        assert_eq!(
            access(
                q,
                serde_json::json!({"q": "repo:wirenboard/wb-agent-tools user:evgeny-boger"})
            ),
            GraphqlAccess::Anonymous
        );
    }

    // ── mutations ─────────────────────────────────────────────────

    #[test]
    fn pr_mutations_are_authenticated() {
        // gh pr create / merge operate on node IDs obtained through
        // already-filtered queries; keep them working.
        let create = r#"mutation CreatePullRequest($input: CreatePullRequestInput!) {
            createPullRequest(input: $input) { pullRequest { number url } }
        }"#;
        assert_eq!(access(create, serde_json::json!({})), GraphqlAccess::Authenticated);
        let merge = r#"mutation($id: ID!) { mergePullRequest(input: { pullRequestId: $id }) {
            pullRequest { merged } } }"#;
        assert_eq!(access(merge, serde_json::json!({})), GraphqlAccess::Authenticated);
    }

    #[test]
    fn mutation_result_subtree_is_still_checked() {
        let q = r#"mutation($id: ID!) { updateSubscription(input: { subscribableId: $id, state: SUBSCRIBED }) {
            subscribable { ... on Repository { owner { repositories(first: 5) { nodes { name } } } } }
        } }"#;
        assert_eq!(access(q, serde_json::json!({})), GraphqlAccess::Anonymous);
    }

    // ── fail-closed shapes ────────────────────────────────────────

    #[test]
    fn root_whitelist_rejects_everything_else() {
        for q in [
            "query { node(id: \"R_kgDOAbc\") { ... on Repository { name } } }",
            "query { nodes(ids: [\"R_kgDOAbc\"]) { id } }",
            "query { organization(login: \"wirenboard\") { name } }",
            "query { user(login: \"someone\") { name } }",
            "subscription { x { y } }",
        ] {
            assert_eq!(access(q, serde_json::json!({})), GraphqlAccess::Anonymous, "{q}");
        }
    }

    #[test]
    fn batched_operations_must_all_pass() {
        let q = r#"
            query A { repository(owner: "wirenboard", name: "wb-agent-tools") { name } }
            query B { viewer { repositories(first: 5) { nodes { name } } } }
        "#;
        assert_eq!(access(q, serde_json::json!({})), GraphqlAccess::Anonymous);
    }

    #[test]
    fn unparseable_bodies_are_anonymous() {
        for raw in [
            &b""[..],
            b"not json",
            b"{}",
            b"{\"query\": 1}",
            b"{\"query\": \"query { repository(owner: \\\"a\\\" }\"}", // bad syntax
        ] {
            assert_eq!(graphql_access(raw, &al()), GraphqlAccess::Anonymous);
        }
        // Variables that aren't strings can't prove an allowed slug.
        let q = "query($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { name } }";
        assert_eq!(
            access(q, serde_json::json!({"owner": ["wirenboard"], "name": 3})),
            GraphqlAccess::Anonymous
        );
    }

    #[test]
    fn aliases_do_not_hide_field_names() {
        // `x: repositories` still enumerates; the policy keys on the
        // real field name, not the alias.
        let q = "query { viewer { x: login } }";
        assert_eq!(access(q, serde_json::json!({})), GraphqlAccess::Authenticated);
        let leak = r#"query { repository(owner: "wirenboard", name: "wb-agent-tools") {
            o: owner { r: repositories(first: 1) { nodes { name } } } } }"#;
        assert_eq!(access(leak, serde_json::json!({})), GraphqlAccess::Anonymous);
    }

    #[test]
    fn empty_allowlist_still_permits_identity_only() {
        // With no repos allow-listed (e.g. --repo only launches
        // elsewhere), viewer{login} keeps working but nothing
        // repo-scoped authenticates.
        let none: Vec<String> = Vec::new();
        assert_eq!(
            graphql_access(&body("{ viewer { login } }", serde_json::json!({})), &none),
            GraphqlAccess::Authenticated
        );
        assert_eq!(
            graphql_access(
                &body(
                    r#"{ repository(owner: "wirenboard", name: "wb-agent-tools") { name } }"#,
                    serde_json::json!({})
                ),
                &none
            ),
            GraphqlAccess::Anonymous
        );
    }
}
