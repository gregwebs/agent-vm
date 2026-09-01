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
//!   identity scalars (the same information REST `/user` exposes,
//!   which the path policy already forwards authenticated); `search`
//!   whose `query:` argument is scoped by allow-listed `repo:`
//!   qualifiers; `rateLimit` and schema introspection.
//! * Inside a scoped subtree, a field with **no selection set** is
//!   free: GraphQL requires object-valued fields to carry one, so a
//!   leaf is necessarily a scalar or enum and cannot smuggle a
//!   `Repository` or `User`. Composite fields must be classified —
//!   see [`REPO_YIELDING_FIELDS`], [`ACTOR_YIELDING_FIELDS`] and
//!   [`COMPOSITE_ALLOWED_FIELDS`] — and anything unrecognised is
//!   refused.
//! * `mutation` and `subscription` operations are denied. Mutation
//!   inputs use opaque node IDs that cannot be soundly mapped back to an
//!   allow-listed repository, so authenticating them would let an agent
//!   mutate an off-list object.
//!
//! **Why an allowlist.** The first version of this filter used a
//! denylist of repo-enumerating field names. Review found nine
//! distinct escapes out of an allowed subtree in an afternoon —
//! `parent`/`source` to a fork's private upstream, `forks`,
//! `collaborators`/`mentionableUsers`/`watchers`/`stargazers` to a
//! `User` and from there to every repo the token can see,
//! `headRepository`/`baseRepository`, `hovercard` contexts and
//! mutation payloads to a full `viewer`. A name denylist cannot be
//! made complete against a schema this size, and each omission is a
//! silent leak. The allowlist inverts the failure mode: an omission
//! makes some query go anonymous, which is visible and recoverable.
//!
//! This deliberately reduces compatibility with `gh` workflows that
//! mutate through GraphQL. REST mutations for an allow-listed repository
//! remain available; GraphQL mutations require a future sound,
//! repository-scoped mutation design.
//!
//! Anything the parser doesn't understand — malformed JSON, GraphQL
//! syntax we don't model, variables that aren't plain strings —
//! resolves to **Anonymous**, never to Authenticated.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};

use serde_json::Value;

/// Decision for one buffered `/graphql` request body.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub enum GraphqlAccess {
    /// Forward with the host user's real token.
    Authenticated,
    /// Refuse, telling the guest why.
    ///
    /// Not "forward anonymously": GitHub's GraphQL endpoint has no
    /// anonymous tier, so a stripped-Authorization query always comes
    /// back `403 API rate limit exceeded for <host IP>`. That is a
    /// misleading answer to "your query wasn't scoped to an allowed
    /// repo" — it names an IP the user doesn't recognise and points at
    /// a limit they haven't hit. Same security posture, comprehensible
    /// failure.
    Denied(String),
}

/// Fields whose value is, or contains, a `Repository`.
///
/// Reaching one from inside an allowed subtree re-opens the whole
/// allow-list: `repository { parent { object { ... on Blob { text } } } }`
/// reads the (possibly private) upstream of a fork. Only `repository`
/// itself can be re-scoped by `owner:`/`name:` arguments; the rest have
/// no such arguments, so they can never name an allow-listed repo.
///
/// A repo-yielding field that is NOT argument-scoped is not rejected
/// outright — `search(...) { nodes { ... on PullRequest { repository
/// { nameWithOwner } } } }` is ordinary gh traffic. Instead its
/// selection set is restricted to scalar leaves, which cannot carry
/// file contents or another repo's inventory.
const REPO_YIELDING_FIELDS: &[&str] = &[
    "repository",
    "repositories",
    "repositoryOwner",
    "parent",
    "source",
    "templateRepository",
    "forks",
    "headRepository",
    "baseRepository",
    "repositoriesContributedTo",
    "topRepositories",
    "starredRepositories",
    "pinnedRepositories",
    "watching",
];

/// Fields whose value is a `User` / `Organization` / `Actor` /
/// `Enterprise` — account-scoped objects that reach across every repo
/// the token can see (`gists`, `pullRequests`, `issues`,
/// `organizations`, `membersWithRole`, …).
///
/// These are not rejected outright, because `author { login }` appears
/// in nearly every query gh sends. Their selection sets are instead
/// restricted to identity scalars, at ANY depth — the generalisation of
/// what used to be a root-only `viewer` rule that
/// `pullRequest { hovercard { contexts { ... on ViewerHovercardContext
/// { viewer { … } } } } }` walked straight around.
const ACTOR_YIELDING_FIELDS: &[&str] = &[
    "viewer",
    "owner",
    "author",
    "editor",
    "creator",
    "user",
    "actor",
    "organization",
    "enterprise",
    "mergedBy",
    "assignees",
    "collaborators",
    "mentionableUsers",
    "assignableUsers",
    "watchers",
    "stargazers",
    "participants",
    "reviewers",
    "requestedReviewer",
    "requestedReviewers",
    "suggestedReviewers",
    "members",
    "membersWithRole",
    "followers",
    "following",
    "contributors",
    "resourceOwner",
    "sponsor",
    "sponsorable",
    // gh sends these; identity-only keeps them cheap
    "headRepositoryOwner",
    "enabledBy",
    "users",
    "assignedActors",
    "authors",
];

/// The subset of [`ACTOR_YIELDING_FIELDS`] that names a *single*
/// account rather than a list of them.
///
/// Only these may nest inside another actor subtree. gh needs
/// `requestedReviewer { ... on Team { organization { login } } }`, but
/// allowing every actor field to nest would turn an actor subtree into
/// an enumeration engine — `owner { membersWithRole { nodes { login } } }`
/// lists a private org's membership, one identity scalar at a time.
const ACTOR_SINGULAR_FIELDS: &[&str] = &[
    "viewer",
    "owner",
    "author",
    "editor",
    "creator",
    "user",
    "actor",
    "organization",
    "enterprise",
    "mergedBy",
    "requestedReviewer",
    "resourceOwner",
    "sponsor",
    "sponsorable",
    "headRepositoryOwner",
    "enabledBy",
];

/// Scalar identity fields permitted under an [`ACTOR_YIELDING_FIELDS`]
/// field — the same information REST `/user` exposes, which the path
/// policy already forwards authenticated.
const IDENTITY_FIELDS: &[&str] = &[
    "login",
    "id",
    "name",
    "email",
    "url",
    "avatarUrl",
    "databaseId",
    "resourcePath",
    "isViewer",
    "slug",
    "__typename",
];

/// Connection plumbing, permitted inside an actor subtree so that
/// `assignees(first: 10) { nodes { login } }` still works.
const CONNECTION_FIELDS: &[&str] = &[
    "nodes",
    "edges",
    "node",
    "pageInfo",
    "totalCount",
    "hasNextPage",
    "hasPreviousPage",
    "endCursor",
    "startCursor",
];

/// Composite (object-valued) fields we are willing to walk into inside
/// an allow-listed repository subtree.
///
/// **This is an allowlist, and that is the point.** In GraphQL a field
/// returning an object type MUST carry a selection set, and a field
/// with no selection set is necessarily a scalar or enum. So scalars
/// are free — they cannot smuggle a `Repository` or a `User` — and
/// every field that *could* is either named here, or named in the two
/// lists above, or rejected. A denylist of "dangerous field names"
/// cannot be made complete against a schema this large; this inverts
/// it, and the cost of an omission is that a query goes anonymous
/// (visible, recoverable) rather than that it leaks (silent).
const COMPOSITE_ALLOWED_FIELDS: &[&str] = &[
    // connections
    "nodes", "edges", "node", "pageInfo",
    // issues / PRs
    "pullRequests", "pullRequest", "issues", "issue", "issueOrPullRequest",
    "comments", "reviews", "latestReviews", "latestOpinionatedReviews",
    "reviewRequests", "reviewThreads", "commits", "files", "closingIssuesReferences",
    "reactionGroups", "reactions", "labels", "milestone",
    "milestones", "projectCards", "assignedTo",
    // refs / git objects
    "ref", "refs", "defaultBranchRef", "target", "object", "commit", "history",
    "tree", "entries", "blob", "associatedPullRequests", "statusCheckRollup",
    "contexts", "checkSuites", "checkRuns", "status", "signature", "tag",
    // repo metadata
    "languages", "primaryLanguage", "licenseInfo", "repositoryTopics", "topic",
    "releases", "release", "releaseAssets", "codeOfConduct", "fundingLinks",
    "discussions", "discussion", "discussionCategories", "branchProtectionRules",
    "rulesets", "environments", "deployments", "vulnerabilityAlerts",
    "submodules", "packages",
    // PR/issue shapes gh sends that the first cut missed
    "autoMergeRequest", "baseRef", "branchProtectionRule", "mergeCommit",
    "potentialMergeCommit", "checkSuite", "workflowRun", "workflow",
    "checkRunCountsByState", "statusContextCountsByState",
    "project", "column", "projectItems", "projects", "projectsV2",
    "fieldValueByName", "latestRelease", "issueType", "subIssues",
    "subIssuesSummary", "blockedBy", "blocking", "closedByPullRequestsReferences",
    "issueTemplates", "pullRequestTemplates", "contactLinks", "label",
    // introspection, so the documented `__schema` allowance actually works
    "types", "fields", "inputFields", "interfaces", "enumValues",
    "possibleTypes", "ofType", "args", "type", "directives",
    "queryType", "mutationType", "subscriptionType",
];

/// Scalars that are credentials or capability handles rather than
/// display data. The "a leaf is only a scalar" reasoning is true but
/// insufficient for these: `Repository.tempCloneToken` is documented as
/// a "temporary authentication token for cloning this repository", so
/// letting it out of an *unscoped* repo subtree hands over clone access
/// to a repo that is not on the allow-list.
const CREDENTIAL_SCALARS: &[&str] = &["tempCloneToken", "tarballUrl", "zipballUrl"];

/// Node handles are withheld from an unscoped repository subtree along
/// with credential scalars. This preserves the conservative read policy
/// even though GraphQL mutations are currently denied.
const NODE_ID_SCALARS: &[&str] = &["id", "databaseId"];

/// Cap on selection-set / value nesting. Without it a hostile document
/// (`{a{a{a…`) overflows the stack and aborts the hook process — a
/// self-inflicted DoS on the guest's GitHub access, and an unhandled
/// crash in a security-critical subprocess.
const MAX_DEPTH: usize = 64;

/// The only search qualifiers that set *scope*. GitHub ANDs
/// qualifiers, so everything else can only narrow within the `repo:`
/// scope already checked and needs no allowlist — an allowlist here
/// just broke ordinary searches (`-label:wip`, `topic:cli`, or any
/// bare term containing a colon, such as an error message).
const SCOPE_QUALIFIERS: &[&str] = &["repo", "org", "user", "owner"];

/// Cap on fragment-spread nesting during validation; combined with
/// the visited-set cycle guard this bounds pathological documents.
const MAX_FRAGMENT_DEPTH: usize = 32;

/// Decide whether a `/graphql` request body may carry the user's
/// token. `allowed` is the per-launch `owner/repo` allow-list
/// (compared case-insensitively).
pub fn graphql_access(body: &[u8], allowed: &[String]) -> GraphqlAccess {
    evaluate(body, allowed)
}

fn evaluate(body: &[u8], allowed: &[String]) -> GraphqlAccess {
    let deny = |m: &str| GraphqlAccess::Denied(format!("agent-vm: {m}"));

    let Ok(json) = serde_json::from_slice::<Value>(body) else {
        return deny("GraphQL request body is not JSON");
    };
    let Some(query) = json.get("query").and_then(|q| q.as_str()) else {
        return deny("GraphQL request body has no string `query`");
    };
    // `variables` may be absent or null; non-string values only matter
    // if something we must resolve references them (then: denied).
    let variables: HashMap<String, String> = json
        .get("variables")
        .and_then(|v| v.as_object())
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    let Some(doc) = parse_document(query) else {
        return deny("GraphQL document could not be parsed");
    };
    if doc.ops.is_empty() {
        return deny("GraphQL document defines no operation");
    }
    let fragments: HashMap<&str, &Vec<Sel>> = doc
        .fragments
        .iter()
        .map(|f| (f.name.as_str(), &f.sel))
        .collect();

    // Every operation must pass — gh sends one, but a crafted body
    // could batch a benign op with a leaking one.
    for op in &doc.ops {
        let ctx = Ctx {
            allowed,
            variables: &variables,
            defaults: &op.var_defaults,
            fragments: &fragments,
            reason: RefCell::new(None),
            budget: Cell::new(VALIDATION_BUDGET),
        };
        let ok = match op.kind {
            OpKind::Query => validate_query_root(&op.sel, &ctx, 0),
            OpKind::Mutation => {
                ctx.deny("mutations are not permitted without repository-scoped inputs");
                false
            }
            OpKind::Subscription => {
                ctx.deny("subscriptions are not permitted");
                false
            }
        };
        if !ok {
            let why = ctx
                .reason
                .borrow()
                .clone()
                .unwrap_or_else(|| "query is not scoped to an allow-listed repository".into());
            let scope = if allowed.is_empty() {
                "no repositories are on the allow-list for this sandbox".to_string()
            } else {
                format!("allowed: {}", allowed.join(", "))
            };
            return GraphqlAccess::Denied(format!("agent-vm: {why} ({scope})"));
        }
    }
    GraphqlAccess::Authenticated
}

/// Validation steps allowed per operation. See `Ctx::budget`.
const VALIDATION_BUDGET: u32 = 20_000;

// ─── validation ───────────────────────────────────────────────────────

struct Ctx<'a> {
    allowed: &'a [String],
    variables: &'a HashMap<String, String>,
    defaults: &'a HashMap<String, String>,
    fragments: &'a HashMap<&'a str, &'a Vec<Sel>>,
    /// Why the first rejection happened, so the guest gets told which
    /// field cost it the token instead of GitHub's misleading
    /// "rate limit exceeded" (its GraphQL endpoint has no anonymous
    /// tier, so an unauthenticated query always 403s that way).
    reason: RefCell<Option<String>>,
    /// Remaining validation steps. Fragments are re-validated per
    /// spread, so `fragment Fi { ...F(i+1) ...F(i+1) }` costs 2^N —
    /// ~1 KB of query bought tens of minutes of HOST cpu, outside the
    /// guest's limits. A flat budget bounds it regardless of shape.
    budget: Cell<u32>,
}

impl Ctx<'_> {
    /// Record the first rejection reason and return `false`, so call
    /// sites read as `return ctx.deny(...)`.
    fn deny(&self, msg: impl Into<String>) -> bool {
        let mut r = self.reason.borrow_mut();
        if r.is_none() {
            *r = Some(msg.into());
        }
        false
    }

    /// Consume one unit of the validation budget.
    fn spend(&self) -> bool {
        let left = self.budget.get();
        if left == 0 {
            return self.deny("query is too complex to validate");
        }
        self.budget.set(left - 1);
        true
    }

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

/// True iff this field carries `owner:`/`name:` arguments that resolve
/// to an allow-listed slug. Both must be present and resolvable —
/// a half-specified pair rejects.
fn repository_is_scoped(field: &Field, ctx: &Ctx) -> bool {
    let (Some(owner), Some(name)) = (arg(field, "owner"), arg(field, "name")) else {
        return false;
    };
    match (ctx.resolve(owner), ctx.resolve(name)) {
        (Some(o), Some(n)) => ctx.slug_allowed(&o, &n),
        _ => false,
    }
}

/// `search(query: …)` is allowed only when the search string is
/// positively scoped by `repo:` qualifiers that are all allow-listed.
///
/// Quoting is rejected outright. GitHub treats a fully-quoted token as
/// a literal phrase rather than a qualifier, so `"repo:owner/name"`
/// reads as scoped to a naive parser while being a completely
/// unscoped, token-authenticated search to GitHub — and `NOT
/// "repo:owner/name"` makes the phrase filter vacuous on top. Boolean
/// operators and negated qualifiers reject for the same reason.
fn search_args_ok(field: &Field, ctx: &Ctx) -> bool {
    let Some(q) = arg(field, "query").and_then(|v| ctx.resolve(v)) else {
        return false;
    };
    let Some(tokens) = split_search_query(&q) else {
        return false; // unbalanced quote: we can't tell what GitHub sees
    };
    let mut saw_repo = false;
    for (token, was_quoted) in tokens {
        let lower = token.to_ascii_lowercase();
        // `OR` widens; a quoted operator is just a search term.
        if !was_quoted && matches!(lower.as_str(), "or") {
            return false;
        }
        let (qualifier, value) = match lower.split_once(':') {
            Some((q, v)) => (q, v),
            // A bare term is ANDed with the repo: scope and can only
            // narrow it — including a negated one.
            None => continue,
        };
        // A fully quoted token is a literal phrase to GitHub, not a
        // qualifier: `"repo:o/n"` scopes nothing while looking scoped.
        if was_quoted {
            continue;
        }
        let bare = qualifier.strip_prefix('-').unwrap_or(qualifier);
        if SCOPE_QUALIFIERS.contains(&bare) {
            // Only a positive `repo:` naming an allow-listed repo is
            // acceptable; `org:`/`user:`/`owner:` and any negated form
            // widen or invert the scope.
            if qualifier != "repo" {
                return false;
            }
            if !ctx.allowed.iter().any(|a| a.eq_ignore_ascii_case(value)) {
                return false;
            }
            saw_repo = true;
        }
        // Every other qualifier only narrows within the repo: scope
        // (GitHub ANDs them), so it needs no allowlist.
    }
    saw_repo
}

/// Split a GitHub search query into tokens, tracking whether each was
/// quoted. Returns `None` on an unbalanced quote.
///
/// Quote-awareness matters in both directions: `label:"help wanted"` is
/// one qualifier (gh generates it from `--label`), while a *fully*
/// quoted `"repo:o/n"` is a literal phrase that scopes nothing.
fn split_search_query(q: &str) -> Option<Vec<(String, bool)>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut quoted_at_start = false;
    let mut saw_quote = false;
    for ch in q.chars() {
        match ch {
            '"' => {
                if !in_quotes && cur.is_empty() {
                    quoted_at_start = true;
                }
                saw_quote = true;
                in_quotes = !in_quotes;
            }
            c if c.is_whitespace() && !in_quotes => {
                if !cur.is_empty() {
                    out.push((std::mem::take(&mut cur), quoted_at_start && saw_quote));
                }
                quoted_at_start = false;
                saw_quote = false;
            }
            c => cur.push(c),
        }
    }
    if in_quotes {
        return None;
    }
    if !cur.is_empty() {
        out.push((cur, quoted_at_start && saw_quote));
    }
    Some(out)
}

/// Selection set of a field we will not walk into: every member must
/// be a scalar leaf (no sub-selection). Used for a repo-yielding field
/// that isn't argument-scoped, so `repository { nameWithOwner }` keeps
/// working while `repository { object { ... on Blob { text } } }` and
/// `forks { nodes { … } }` do not.
fn validate_restricted_subtree(
    sel: &[Sel],
    ctx: &Ctx,
    depth: usize,
    visiting: &mut HashSet<String>,
) -> bool {
    if !ctx.spend() || depth > MAX_FRAGMENT_DEPTH || sel.is_empty() {
        return false;
    }
    sel.iter().all(|s| match s {
        Sel::Field(f) => {
            if f.sel.is_empty() {
                // A leaf is a scalar — but not every scalar is display
                // data. See CREDENTIAL_SCALARS.
                if CREDENTIAL_SCALARS.contains(&f.name.as_str())
                    || NODE_ID_SCALARS.contains(&f.name.as_str())
                {
                    return ctx.deny(format!(
                        "`{}` is a credential or node handle and is not readable for a repository outside the allow-list",
                        f.name
                    ));
                }
                true
            } else if ACTOR_YIELDING_FIELDS.contains(&f.name.as_str()) {
                // `parent { owner { login } }` — identity only, and we
                // already hand out `parent { nameWithOwner }`.
                validate_actor_subtree(&f.sel, ctx, depth, visiting)
            } else if matches!(f.name.as_str(), "ref" | "defaultBranchRef") {
                validate_restricted_subtree(&f.sel, ctx, depth, visiting)
            } else {
                ctx.deny(format!(
                    "`{}` cannot be traversed on a repository outside the allow-list",
                    f.name
                ))
            }
        }
        Sel::Inline(inner) => validate_restricted_subtree(inner, ctx, depth, visiting),
        Sel::Spread(name) => match ctx.fragments.get(name.as_str()) {
            Some(frag) if visiting.insert(name.clone()) => {
                let ok = validate_restricted_subtree(frag, ctx, depth + 1, visiting);
                visiting.remove(name);
                ok
            }
            _ => ctx.deny(format!("fragment `{name}` is undefined or cyclic")),
        },
    })
}

/// Selection set under an actor-typed field: identity scalars only,
/// plus connection plumbing so `assignees { nodes { login } }` works.
fn validate_actor_subtree(sel: &[Sel], ctx: &Ctx, depth: usize, visiting: &mut HashSet<String>) -> bool {
    if !ctx.spend() || depth > MAX_FRAGMENT_DEPTH || sel.is_empty() {
        return false;
    }
    sel.iter().all(|s| match s {
        Sel::Field(f) => {
            if f.sel.is_empty() {
                // A leaf is a scalar; it must still be an identity
                // field, since `gists`-style connections would 404
                // without a selection set anyway and we prefer the
                // explicit list.
                IDENTITY_FIELDS.contains(&f.name.as_str())
                    || CONNECTION_FIELDS.contains(&f.name.as_str())
                    || ctx.deny(format!(
                        "`{}` is not an identity field; only identity scalars are readable on an account object",
                        f.name
                    ))
            } else if CONNECTION_FIELDS.contains(&f.name.as_str())
                || ACTOR_SINGULAR_FIELDS.contains(&f.name.as_str())
            {
                // A nested *singular* actor (gh sends
                // `requestedReviewer { ... on Team { organization
                // { login } } }`) stays identity-only. Member-listing
                // connections are not allowed to nest — see
                // ACTOR_SINGULAR_FIELDS.
                validate_actor_subtree(&f.sel, ctx, depth, visiting)
            } else {
                ctx.deny(format!(
                    "`{}` is not an identity field; only identity scalars are readable on an account object",
                    f.name
                ))
            }
        }
        Sel::Inline(inner) => validate_actor_subtree(inner, ctx, depth, visiting),
        Sel::Spread(name) => match ctx.fragments.get(name.as_str()) {
            Some(frag) if visiting.insert(name.clone()) => {
                let ok = validate_actor_subtree(frag, ctx, depth + 1, visiting);
                visiting.remove(name);
                ok
            }
            _ => false,
        },
    })
}

/// Walk a selection set inside an already-scoped subtree.
///
/// Scalar leaves pass unconditionally (a field with no selection set
/// cannot be an object). Composite fields must be classified: repo-
/// yielding, actor-yielding, or explicitly allow-listed. Anything else
/// rejects.
fn validate_generic(sel: &[Sel], ctx: &Ctx, depth: usize, visiting: &mut HashSet<String>) -> bool {
    if !ctx.spend() || depth > MAX_FRAGMENT_DEPTH {
        return false;
    }
    for s in sel {
        match s {
            Sel::Field(f) => {
                let repo_yielding = REPO_YIELDING_FIELDS.contains(&f.name.as_str());
                let actor_yielding = ACTOR_YIELDING_FIELDS.contains(&f.name.as_str());

                if f.name == "search" && !search_args_ok(f, ctx) {
                    return ctx.deny(
                        "`search` must be scoped by a repo: qualifier naming an allow-listed repository",
                    );
                }
                if repo_yielding {
                    // Argument-scoped to an allow-listed repo: walk it
                    // like any other allowed subtree. Otherwise it may
                    // only expose scalars.
                    let ok = if repository_is_scoped(f, ctx) {
                        validate_generic(&f.sel, ctx, depth, visiting)
                    } else {
                        validate_restricted_subtree(&f.sel, ctx, depth, visiting)
                    };
                    if !ok {
                        return false;
                    }
                    continue;
                }
                if actor_yielding {
                    if !validate_actor_subtree(&f.sel, ctx, depth, visiting) {
                        return false;
                    }
                    continue;
                }
                if f.sel.is_empty() {
                    // Scalar leaf: cannot carry an object.
                    continue;
                }
                if !COMPOSITE_ALLOWED_FIELDS.contains(&f.name.as_str())
                    && f.name != "search"
                {
                    return ctx.deny(format!(
                        "`{}` is not in the set of fields readable inside an allow-listed repository",
                        f.name
                    ));
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
                    "repository" => {
                        repository_is_scoped(f, ctx)
                            && validate_generic(&f.sel, ctx, depth, &mut visiting)
                    }
                    // `viewer` and `user(login:)` expose the same
                    // identity surface REST `/user` already forwards
                    // authenticated; gh needs `user` for --assignee.
                    "viewer" | "user" => {
                        validate_actor_subtree(&f.sel, ctx, depth, &mut visiting)
                    }
                    "search" => {
                        search_args_ok(f, ctx)
                            && validate_generic(&f.sel, ctx, depth, &mut visiting)
                    }
                    "rateLimit" | "__typename" | "__schema" | "__type" => {
                        validate_generic(&f.sel, ctx, depth, &mut visiting)
                    }
                    other => ctx.deny(format!(
                        "`{other}` is not a permitted query root; scope the query with repository(owner:, name:)"
                    )),
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
                        // Exactly four hex digits. `from_str_radix`
                        // alone would accept `+041`/`-041`, which
                        // GitHub's lexer rejects — a divergence is a
                        // divergence even when it fails safe.
                        let hex = rest.get(i + 2..i + 6)?;
                        if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                            return None;
                        }
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
    /// Current nesting depth, bounded by [`MAX_DEPTH`]. Plain
    /// selection-set and list-value nesting recurse, so without this a
    /// 64 KB `{a{a{a…` body overflows the stack and aborts the hook
    /// process — fail-closed, but an unhandled crash and a trivial
    /// self-inflicted DoS on the guest's GitHub access.
    depth: usize,
}

fn parse_document(src: &str) -> Option<Doc> {
    let mut p = Parser {
        toks: lex(src)?,
        pos: 0,
        depth: 0,
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
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return None;
        }
        let out = self.selection_set_inner();
        self.depth -= 1;
        out
    }

    fn selection_set_inner(&mut self) -> Option<Vec<Sel>> {
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
                        // GraphQL requires argument names to be unique
                        // (spec 5.4.2). Ours takes the first match, so a
                        // document repeating `owner:`/`name:` would be
                        // judged on one pair and executed on another if
                        // any server were lax. Refuse instead of relying
                        // on someone else's validator.
                        if args.iter().any(|(k, _)| *k == key) {
                            return None;
                        }
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
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return None;
        }
        let out = self.value_inner();
        self.depth -= 1;
        out
    }

    fn value_inner(&mut self) -> Option<Val> {
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

    /// Verdict without the reason string, so assertions stay readable.
    #[derive(Debug, PartialEq, Eq)]
    enum V {
        Auth,
        Denied,
    }
    const AUTH: V = V::Auth;
    const DENIED: V = V::Denied;

    fn v(a: GraphqlAccess) -> V {
        match a {
            GraphqlAccess::Authenticated => V::Auth,
            GraphqlAccess::Denied(_) => V::Denied,
        }
    }

    fn access(query: &str, variables: serde_json::Value) -> V {
        v(graphql_access(&body(query, variables), &al()))
    }

    /// The reason text handed back to the guest.
    fn why(query: &str, variables: serde_json::Value) -> String {
        match graphql_access(&body(query, variables), &al()) {
            GraphqlAccess::Denied(r) => r,
            GraphqlAccess::Authenticated => panic!("expected a denial"),
        }
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
            DENIED
        );
    }

    #[test]
    fn viewer_repositories_is_anonymous() {
        let q = "query { viewer { repositories(first: 100) { nodes { nameWithOwner } } } }";
        assert_eq!(access(q, serde_json::json!({})), DENIED);
    }

    #[test]
    fn viewer_cross_repo_connections_are_anonymous() {
        // pullRequests on viewer spans private repos — not in the
        // scalar identity whitelist.
        let q = "query { viewer { login pullRequests(first: 10) { nodes { title } } } }";
        assert_eq!(access(q, serde_json::json!({})), DENIED);
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
            AUTH
        );
    }

    #[test]
    fn pr_list_on_other_repo_is_anonymous() {
        let q = r#"query($owner: String!, $repo: String!) {
            repository(owner: $owner, name: $repo) { pullRequests(first: 5) { nodes { title } } }
        }"#;
        assert_eq!(
            access(q, serde_json::json!({"owner": "wirenboard", "repo": "some-private"})),
            DENIED
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
        assert_eq!(access(q, serde_json::json!({})), AUTH);
        let q_other = r#"query {
            repository(owner: "wirenboard", name: "secret-repo") {
                object(expression: "HEAD:README.md") { ... on Blob { text } }
            }
        }"#;
        assert_eq!(access(q_other, serde_json::json!({})), DENIED);
    }

    #[test]
    fn viewer_login_is_authenticated() {
        // gh resolves the current login constantly (`gh pr create`,
        // `gh pr status`, …). Equivalent to REST /user, which the
        // path policy forwards authenticated.
        assert_eq!(
            access("query UserCurrent { viewer { login } }", serde_json::json!({})),
            AUTH
        );
        // Query shorthand form.
        assert_eq!(
            access("{ viewer { login } }", serde_json::json!({})),
            AUTH
        );
    }

    #[test]
    fn allowed_slug_is_case_insensitive() {
        let q = r#"query { repository(owner: "WirenBoard", name: "WB-Agent-Tools") { name } }"#;
        assert_eq!(access(q, serde_json::json!({})), AUTH);
    }

    #[test]
    fn variable_defaults_resolve() {
        let q = r#"query($owner: String = "wirenboard", $name: String = "wb-agent-tools") {
            repository(owner: $owner, name: $name) { name }
        }"#;
        assert_eq!(access(q, serde_json::json!({})), AUTH);
        // Request variables override defaults — and must be checked.
        assert_eq!(
            access(q, serde_json::json!({"owner": "wirenboard", "name": "secret-repo"})),
            DENIED
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
        assert_eq!(access(ok, serde_json::json!({})), AUTH);
        let leak = r#"
            query { repository(owner: "wirenboard", name: "wb-agent-tools") { owner { ...esc } } }
            fragment esc on RepositoryOwner { repositories(first: 5) { nodes { nameWithOwner } } }
        "#;
        assert_eq!(access(leak, serde_json::json!({})), DENIED);
        // Spread of an undefined fragment: refuse.
        let undef = r#"query { repository(owner: "wirenboard", name: "wb-agent-tools") { ...nope } }"#;
        assert_eq!(access(undef, serde_json::json!({})), DENIED);
    }

    #[test]
    fn owner_escape_inside_allowed_subtree_is_anonymous() {
        // repository → owner is a User/Organization: its repo
        // connections would re-open enumeration from inside an
        // allowed subtree.
        let q = r#"query { repository(owner: "wirenboard", name: "wb-agent-tools") {
            owner { ... on Organization { repositories(first: 10) { nodes { name } } } }
        } }"#;
        assert_eq!(access(q, serde_json::json!({})), DENIED);
    }

    // ── search scoping (gh pr status) ─────────────────────────────

    #[test]
    fn search_scoped_to_allowed_repo_is_authenticated() {
        let q = r#"query($q: String!) { search(query: $q, type: ISSUE, first: 30) {
            nodes { ... on PullRequest { number title repository { nameWithOwner } } }
        } }"#;
        assert_eq!(
            access(q, serde_json::json!({"q": "repo:wirenboard/wb-agent-tools is:pr is:open"})),
            AUTH
        );
        assert_eq!(
            access(q, serde_json::json!({"q": "repo:wirenboard/other is:pr"})),
            DENIED
        );
        // No repo: qualifier → global search under the user's token.
        assert_eq!(
            access(q, serde_json::json!({"q": "is:pr author:@me"})),
            DENIED
        );
        // Broadening qualifiers reject even alongside repo:.
        assert_eq!(
            access(
                q,
                serde_json::json!({"q": "repo:wirenboard/wb-agent-tools user:evgeny-boger"})
            ),
            DENIED
        );
    }

    // ── mutations ─────────────────────────────────────────────────

    #[test]
    fn mutations_are_denied_without_a_repository_scoped_design() {
        // GraphQL mutation inputs are opaque node IDs, so they cannot be
        // proved to name an allow-listed repository.
        let create = r#"mutation CreatePullRequest($input: CreatePullRequestInput!) {
            createPullRequest(input: $input) { pullRequest { number url } }
        }"#;
        assert_eq!(access(create, serde_json::json!({})), DENIED);
        let merge = r#"mutation($id: ID!) { mergePullRequest(input: { pullRequestId: $id }) {
            pullRequest { merged } } }"#;
        assert_eq!(access(merge, serde_json::json!({})), DENIED);
    }

    #[test]
    fn mutation_result_subtree_is_still_checked() {
        let q = r#"mutation($id: ID!) { updateSubscription(input: { subscribableId: $id, state: SUBSCRIBED }) {
            subscribable { ... on Repository { owner { repositories(first: 5) { nodes { name } } } } }
        } }"#;
        assert_eq!(access(q, serde_json::json!({})), DENIED);
    }

    // ── fail-closed shapes ────────────────────────────────────────

    #[test]
    fn root_whitelist_rejects_everything_else() {
        for q in [
            "query { node(id: \"R_kgDOAbc\") { ... on Repository { name } } }",
            "query { nodes(ids: [\"R_kgDOAbc\"]) { id } }",
            "query { organization(login: \"wirenboard\") { name } }",
            // `user(login:)` IS permitted now, but identity-only — gh
            // needs it for --assignee. Anything richer still refuses.
            "query { user(login: \"someone\") { gists(first: 5) { nodes { name } } } }",
            "subscription { x { y } }",
        ] {
            assert_eq!(access(q, serde_json::json!({})), DENIED, "{q}");
        }
    }

    #[test]
    fn batched_operations_must_all_pass() {
        let q = r#"
            query A { repository(owner: "wirenboard", name: "wb-agent-tools") { name } }
            query B { viewer { repositories(first: 5) { nodes { name } } } }
        "#;
        assert_eq!(access(q, serde_json::json!({})), DENIED);
    }

    // ── attacks confirmed against the first version of this filter ──
    //
    // Each of these returned Authenticated before the policy was
    // inverted from a name denylist to an allowlist. They are the
    // regression suite for that inversion.

    #[test]
    fn quoted_repo_qualifier_in_search_is_refused() {
        // GitHub treats a fully-quoted token as a literal phrase, not a
        // qualifier: `"repo:o/r"` reads as scoped to a naive parser and
        // is a global, token-authenticated search to GitHub. Adding NOT
        // makes the phrase filter vacuous on top.
        let q = r#"query($q: String!) { search(query: $q, type: REPOSITORY, first: 100) {
            repositoryCount nodes { ... on Repository { nameWithOwner isPrivate } } } }"#;
        for probe in [
            "\"repo:wirenboard/wb-agent-tools\"",
            "NOT \"repo:wirenboard/wb-agent-tools\" is:private",
            "repo:wirenboard/wb-agent-tools OR repo:other/thing",
            "-repo:wirenboard/wb-agent-tools",
            "repo:wirenboard/wb-agent-tools org:wirenboard",
        ] {
            assert_eq!(
                access(q, serde_json::json!({ "q": probe })),
                DENIED,
                "search query {probe:?} must not authenticate"
            );
        }
        // The legitimate scoped form still works.
        assert_eq!(
            access(
                q,
                serde_json::json!({"q": "repo:wirenboard/wb-agent-tools is:pr is:open"})
            ),
            AUTH
        );
    }

    #[test]
    fn repository_yielding_fields_cannot_escape_the_allowed_subtree() {
        // Every one of these reaches a different Repository from inside
        // an allow-listed one. `parent`/`source` reach a fork's (maybe
        // private) upstream; `forks`/`headRepository`/`baseRepository`
        // reach arbitrary repos — and from any of them, file contents.
        for field in [
            "parent { object(expression: \"HEAD:.env\") { ... on Blob { text } } }",
            "source { object(expression: \"HEAD:.env\") { ... on Blob { text } } }",
            "templateRepository { object(expression: \"HEAD:.env\") { ... on Blob { text } } }",
            "forks(first: 100) { nodes { nameWithOwner isPrivate } }",
            "pullRequests(first: 1) { nodes { headRepository { object(expression: \"HEAD:.env\") { ... on Blob { text } } } } }",
            "pullRequests(first: 1) { nodes { baseRepository { object(expression: \"HEAD:.env\") { ... on Blob { text } } } } }",
        ] {
            let q = format!(
                r#"query {{ repository(owner: "wirenboard", name: "wb-agent-tools") {{ {field} }} }}"#
            );
            assert_eq!(
                access(&q, serde_json::json!({})),
                DENIED,
                "escape via {field} must not authenticate"
            );
        }
    }

    #[test]
    fn actor_fields_are_identity_only_at_any_depth() {
        // A User reached from anywhere spans every repo the token can
        // see: gists, pullRequests, issues, organizations. The old rule
        // restricted `viewer` at the query root only, so any User
        // reached at depth was unrestricted.
        for field in [
            "collaborators(first: 100) { nodes { pullRequests(first: 1) { nodes { title } } } }",
            "mentionableUsers(first: 100) { nodes { gists(first: 10, privacy: ALL) { nodes { name } } } }",
            "assignableUsers(first: 10) { nodes { organizations(first: 5) { nodes { login } } } }",
            "watchers(first: 10) { nodes { issues(first: 5) { nodes { title } } } }",
            "stargazers(first: 10) { nodes { gists(first: 5) { nodes { name } } } }",
            "owner { ... on Organization { membersWithRole(first: 10) { nodes { login } } } }",
            "pullRequests(first: 1) { nodes { author { ... on User { gists(first: 5) { nodes { name } } } } } }",
        ] {
            let q = format!(
                r#"query {{ repository(owner: "wirenboard", name: "wb-agent-tools") {{ {field} }} }}"#
            );
            assert_eq!(
                access(&q, serde_json::json!({})),
                DENIED,
                "escape via {field} must not authenticate"
            );
        }
        // Identity selections on the same fields still work — this is
        // what gh actually needs.
        let ok = r#"query { repository(owner: "wirenboard", name: "wb-agent-tools") {
            pullRequests(first: 5) { nodes { number title author { login } assignees(first: 5) { nodes { login } } } } } }"#;
        assert_eq!(access(ok, serde_json::json!({})), AUTH);
    }

    #[test]
    fn viewer_reached_at_depth_is_restricted_too() {
        // `hovercard` contexts carry a full `viewer: User`, and mutation
        // payloads do the same — both walked around the old root-only
        // viewer rule.
        let hovercard = r#"query { repository(owner: "wirenboard", name: "wb-agent-tools") {
            pullRequest(number: 1) { hovercard { contexts { ... on ViewerHovercardContext {
                viewer { gists(first: 10, privacy: ALL) { nodes { name } } } } } } } } }"#;
        assert_eq!(access(hovercard, serde_json::json!({})), DENIED);

        let mutation = r#"mutation($input: CreateUserListInput!) {
            createUserList(input: $input) { viewer { gists(first: 10) { nodes { name } } } } }"#;
        assert_eq!(access(mutation, serde_json::json!({})), DENIED);
    }

    #[test]
    fn argless_repository_is_scalar_only() {
        // `PullRequest.repository` reached from an unscoped parent used
        // to be waved through as "already scoped by its parent". Scalars
        // are fine (gh prints nameWithOwner); traversal is not.
        let scalars = r#"query($q: String!) { search(query: $q, type: ISSUE, first: 10) {
            nodes { ... on PullRequest { number repository { nameWithOwner } } } } }"#;
        assert_eq!(
            access(
                scalars,
                serde_json::json!({"q": "repo:wirenboard/wb-agent-tools is:pr"})
            ),
            AUTH
        );
        let traverse = r#"query($q: String!) { search(query: $q, type: ISSUE, first: 10) {
            nodes { ... on PullRequest { repository {
                object(expression: "HEAD:.env") { ... on Blob { text } } } } } } }"#;
        assert_eq!(
            access(
                traverse,
                serde_json::json!({"q": "repo:wirenboard/wb-agent-tools is:pr"})
            ),
            DENIED
        );
    }

    #[test]
    fn unknown_composite_fields_are_refused() {
        // The allowlist's whole point: a field we don't know about, but
        // which returns an object, must not be walked. Scalars stay free.
        let unknown = r#"query { repository(owner: "wirenboard", name: "wb-agent-tools") {
            someFutureConnection(first: 10) { nodes { secret } } } }"#;
        assert_eq!(access(unknown, serde_json::json!({})), DENIED);
        let scalar = r#"query { repository(owner: "wirenboard", name: "wb-agent-tools") {
            someFutureScalar diskUsage isPrivate } }"#;
        assert_eq!(access(scalar, serde_json::json!({})), AUTH);
    }

    #[test]
    fn duplicate_arguments_are_refused() {
        // Spec 5.4.2 makes this invalid, but ours took the first match
        // while a lax server could take the last.
        let q = r#"query { repository(owner: "wirenboard", name: "wb-agent-tools",
            owner: "victim", name: "private") { nameWithOwner } }"#;
        assert_eq!(access(q, serde_json::json!({})), DENIED);
    }

    #[test]
    fn deep_nesting_is_refused_not_a_stack_overflow() {
        // `{a{a{a…` used to overflow the stack and abort the hook — a
        // self-inflicted DoS on the guest's own GitHub access.
        let deep = format!(
            "query {{ repository(owner: \"wirenboard\", name: \"wb-agent-tools\") {{ {}{} }} }}",
            "nodes { ".repeat(5000),
            "}".repeat(5000)
        );
        assert_eq!(access(&deep, serde_json::json!({})), DENIED);
        let deep_list = format!(
            "query {{ repository(owner: \"wirenboard\", name: \"wb-agent-tools\", x: {}{}) {{ name }} }}",
            "[".repeat(5000),
            "]".repeat(5000)
        );
        assert_eq!(access(&deep_list, serde_json::json!({})), DENIED);
    }

    #[test]
    fn unicode_escape_requires_four_hex_digits() {
        let q = r#"query { repository(owner: "wirenboard", name: "\u+041b-agent-tools") { name } }"#;
        assert_eq!(access(q, serde_json::json!({})), DENIED);
    }

    // ── from the over-restriction review: real gh traffic ──────────

    #[test]
    fn gh_label_search_with_a_quoted_value_still_works() {
        // gh generates `label:"help wanted"` from `--label`. Rejecting
        // every quote broke every multi-word label.
        let q = r#"query($q: String!) { search(query: $q, type: ISSUE, first: 10) {
            nodes { ... on Issue { number title } } } }"#;
        for probe in [
            "repo:wirenboard/wb-agent-tools label:\"help wanted\" state:open",
            "repo:wirenboard/wb-agent-tools \"null pointer\"",
            "repo:wirenboard/wb-agent-tools -label:wip",
            "repo:wirenboard/wb-agent-tools error: cannot find",
            "repo:wirenboard/wb-agent-tools topic:cli path:api",
            "repo:wirenboard/wb-agent-tools don't",
        ] {
            assert_eq!(
                access(q, serde_json::json!({ "q": probe })),
                AUTH,
                "search {probe:?} narrows within the repo and should work"
            );
        }
        // An unbalanced quote is still refused: we can't tell what
        // GitHub would see.
        assert_eq!(
            access(q, serde_json::json!({"q": "repo:wirenboard/wb-agent-tools \"oops"})),
            DENIED
        );
    }

    #[test]
    fn gh_pr_and_repo_metadata_queries_work() {
        // Shapes captured from real gh: the fork's parent is read for
        // `gh repo clone` / `gh pr create`, and reviewers/labels for
        // `gh pr view`.
        let parent = r#"query { repository(owner: "wirenboard", name: "wb-agent-tools") {
            name nameWithOwner defaultBranchRef { name }
            parent { name nameWithOwner owner { login } defaultBranchRef { name } } } }"#;
        assert_eq!(access(parent, serde_json::json!({})), AUTH);

        let pr = r#"query { repository(owner: "wirenboard", name: "wb-agent-tools") {
            pullRequests(first: 10) { nodes {
                number title headRefName
                headRepositoryOwner { login }
                baseRef { name branchProtectionRule { requiresApprovingReviews } }
                autoMergeRequest { enabledBy { login } }
                reviewRequests(first: 5) { nodes { requestedReviewer {
                    ... on User { login } ... on Team { slug organization { login } } } } }
                reactionGroups { content users(first: 3) { nodes { login } } }
            } } } }"#;
        assert_eq!(access(pr, serde_json::json!({})), AUTH);

        let assignee = r#"query { user(login: "evgeny-boger") { id login } }"#;
        assert_eq!(access(assignee, serde_json::json!({})), AUTH);
    }

    #[test]
    fn actor_connections_still_cannot_nest_inside_an_actor() {
        // The nesting relaxation above must not re-open enumeration:
        // a member-listing connection under an actor lists a private
        // org's membership one login at a time.
        let q = r#"query { repository(owner: "wirenboard", name: "wb-agent-tools") {
            owner { ... on Organization { membersWithRole(first: 100) { nodes { login } } } } } }"#;
        assert_eq!(access(q, serde_json::json!({})), DENIED);
    }

    #[test]
    fn credential_scalars_do_not_ride_out_on_an_unscoped_repo() {
        // `tempCloneToken` is documented as a clone credential, and
        // node IDs are what mutation roots take. A leaf being "just a
        // scalar" does not make it display data.
        for field in ["tempCloneToken", "id", "databaseId", "tarballUrl", "zipballUrl"] {
            let q = format!(
                r#"query {{ repository(owner: "wirenboard", name: "wb-agent-tools") {{
                    parent {{ nameWithOwner {field} }} }} }}"#
            );
            assert_eq!(
                access(&q, serde_json::json!({})),
                DENIED,
                "{field} must not be readable on a repo outside the allow-list"
            );
        }
        // Display metadata on the same unscoped parent is still fine.
        let ok = r#"query { repository(owner: "wirenboard", name: "wb-agent-tools") {
            parent { nameWithOwner isPrivate description } } }"#;
        assert_eq!(access(ok, serde_json::json!({})), AUTH);
    }

    #[test]
    fn mutation_payloads_are_not_a_read_channel() {
        // A full walk of the payload made every mutation a read
        // primitive: createRef hands back a ref you can walk to
        // Blob.text, updateIssue hands back the issue body.
        let read_via_ref = r#"mutation($i: CreateRefInput!) { createRef(input: $i) {
            ref { target { ... on Commit { tree { entries {
                object { ... on Blob { text } } } } } } } } }"#;
        assert_eq!(access(read_via_ref, serde_json::json!({})), DENIED);
        let read_via_issue = r#"mutation($i: UpdateIssueInput!) { updateIssue(input: $i) {
            issue { title comments(first: 100) { nodes { body } } } } }"#;
        assert_eq!(access(read_via_issue, serde_json::json!({})), DENIED);
        let otherwise_minimal = r#"mutation($i: CreatePullRequestInput!) { createPullRequest(input: $i) {
            pullRequest { id number url } } }"#;
        assert_eq!(access(otherwise_minimal, serde_json::json!({})), DENIED);
    }

    #[test]
    fn exponential_fragment_expansion_is_bounded() {
        // Fragments are re-validated per spread, so
        // `fragment Fi { ...F(i+1) ...F(i+1) }` costs 2^N — about 1 KB
        // of query bought tens of minutes of HOST cpu.
        let mut doc = String::from(
            "query { repository(owner: \"wirenboard\", name: \"wb-agent-tools\") { ...F0 } }\n",
        );
        for i in 0..24 {
            doc.push_str(&format!(
                "fragment F{i} on Repository {{ ...F{} ...F{} }}\n",
                i + 1,
                i + 1
            ));
        }
        doc.push_str("fragment F24 on Repository { name }\n");
        let start = std::time::Instant::now();
        assert_eq!(access(&doc, serde_json::json!({})), DENIED);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "validation should be bounded, took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn denial_says_which_field_was_the_problem() {
        // Going anonymous made GitHub answer "rate limit exceeded for
        // <host IP>", which is not a debuggable answer. The denial
        // names the field and the allow-list instead.
        let msg = why(
            r#"query { repository(owner: "wirenboard", name: "wb-agent-tools") {
                someFutureConnection(first: 1) { nodes { x } } } }"#,
            serde_json::json!({}),
        );
        assert!(msg.contains("someFutureConnection"), "unhelpful denial: {msg}");
        assert!(msg.contains("wirenboard/wb-agent-tools"), "denial omits scope: {msg}");

        let msg = why(
            r#"query { repository(owner: "other", name: "repo") { name } }"#,
            serde_json::json!({}),
        );
        assert!(msg.contains("repository"), "unhelpful denial: {msg}");
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
            assert_eq!(v(graphql_access(raw, &al())), DENIED);
        }
        // Variables that aren't strings can't prove an allowed slug.
        let q = "query($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { name } }";
        assert_eq!(
            access(q, serde_json::json!({"owner": ["wirenboard"], "name": 3})),
            DENIED
        );
    }

    #[test]
    fn aliases_do_not_hide_field_names() {
        // `x: repositories` still enumerates; the policy keys on the
        // real field name, not the alias.
        let q = "query { viewer { x: login } }";
        assert_eq!(access(q, serde_json::json!({})), AUTH);
        let leak = r#"query { repository(owner: "wirenboard", name: "wb-agent-tools") {
            o: owner { r: repositories(first: 1) { nodes { name } } } } }"#;
        assert_eq!(access(leak, serde_json::json!({})), DENIED);
    }

    #[test]
    fn empty_allowlist_still_permits_identity_only() {
        // With no repos allow-listed (e.g. --repo only launches
        // elsewhere), viewer{login} keeps working but nothing
        // repo-scoped authenticates.
        let none: Vec<String> = Vec::new();
        assert_eq!(
            v(graphql_access(
                &body("{ viewer { login } }", serde_json::json!({})),
                &none
            )),
            AUTH
        );
        assert_eq!(
            v(graphql_access(
                &body(
                    r#"{ repository(owner: "wirenboard", name: "wb-agent-tools") { name } }"#,
                    serde_json::json!({})
                ),
                &none
            )),
            DENIED
        );
    }
}
