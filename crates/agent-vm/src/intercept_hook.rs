//! `agent-vm _intercept-hook` is the subprocess adapter for matched OAuth and
//! scoped GitHub interception rules. It reads one request from stdin, selects the
//! GitHub policy path or the private OAuth-refresh deep module, and writes one
//! hook-protocol response to stdout. Stdout is protocol transport, not logging.
//!
//! OAuth validation, provider dispatch, locking, host CLI execution, host
//! credential parsing, bearer installation, and placeholder synthesis are kept
//! behind `oauth_refresh::handle`. That module completes validation before any
//! refresh side effect and returns only a response that contains guest-safe data.

use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use crate::secrets;

mod http;
mod oauth_refresh;

#[derive(ClapArgs)]
pub struct Args {
    /// Per-project state directory (same one used by the launcher).
    /// We need it to know where to write the freshly-rotated token file.
    #[arg(long)]
    state_dir: PathBuf,

    /// Repo allow-list for the GitHub forwarding path. Repeated:
    /// `--allowed-repo owner/name` (case-insensitive). Requests to
    /// `api.github.com` paths outside this list get a synthesized 403.
    /// Built from `git remote -v` in the cwd plus `--repo` overrides
    /// at launcher time.
    #[arg(long = "allowed-repo")]
    allowed_repos: Vec<String>,

    /// SNI of the intercepted connection. Provided by microsandbox via
    /// the `MSB_INTERCEPT_SNI` env var the proxy sets on the hook.
    #[arg(env = "MSB_INTERCEPT_SNI")]
    sni: String,
}

pub async fn run(args: Args) -> Result<()> {
    let mut request = Vec::new();
    std::io::stdin()
        .read_to_end(&mut request)
        .context("reading request from stdin")?;

    // GitHub gets its own dispatch — the request is forwarded upstream
    // after path-based allow-listing, not synthesized.
    if args.sni.eq_ignore_ascii_case(secrets::GITHUB_API_HOST) {
        let response = forward_github_api(&request, &args.allowed_repos, &args.state_dir)
            .await
            .unwrap_or_else(|_| {
                http::Response::error(502, "agent-vm github forwarder failed")
                    .expect("fixed response")
            });
        write_response(response.as_bytes())?;
        return Ok(());
    }

    // The git-smart-HTTP hosts (github.com, codeload, raw, objects)
    // are wired with `streaming_rule` upstream so the hook sees only
    // headers, not the (potentially MB-sized) pack body. We decide
    // based on the path alone: in-allow-list → empty stdout
    // (passthrough — proxy streams the rest to upstream with the
    // network secret layer substituting the placeholder bearer);
    // out-of-list → synthesized 403.
    let github_smart_hosts: [&str; 4] = [
        secrets::GITHUB_HOST,
        secrets::GITHUB_CODELOAD_HOST,
        secrets::GITHUB_RAW_HOST,
        secrets::GITHUB_OBJECTS_HOST,
    ];
    if github_smart_hosts
        .iter()
        .any(|h| args.sni.eq_ignore_ascii_case(h))
    {
        let response = match github_smart_decision(&request, &args.allowed_repos) {
            // Allow-listed: forward the request unchanged EXCEPT we
            // inject `Connection: close` so the upstream tears down
            // the TCP after responding. This prevents the
            // keep-alive bypass: msb's Interceptor goes to
            // State::Disabled after one dispatch, so any subsequent
            // HTTP/1.1 request on the same connection would be
            // forwarded with the secret-substituted Authorization
            // (real token) directly to upstream, even if it
            // targets a different (non-allow-listed) repo.
            GithubSmartOutcome::Authenticated => set_connection_close(&request),
            // Not allow-listed: passthrough with Authorization
            // stripped. Non-empty, non-`HTTP/` stdout tells the
            // proxy "forward THESE bytes instead." Also injects
            // `Connection: close` for the same reason (otherwise
            // the next request on the same connection — e.g. a
            // libcurl retry — bypasses the hook). GitHub treats
            // the request as third-party.
            GithubSmartOutcome::Anonymous => {
                set_connection_close(&strip_authorization_from_request(&request))
            }
            GithubSmartOutcome::Deny(msg) => http::Response::error(403, &msg)?.as_bytes().to_vec(),
            GithubSmartOutcome::Malformed => {
                http::Response::error(400, "agent-vm github smart-HTTP filter: malformed request")?
                    .as_bytes()
                    .to_vec()
            }
        };
        write_response(&response)?;
        return Ok(());
    }

    let response = oauth_refresh::handle(&request, &args.sni, &args.state_dir)?;
    write_response(response.as_bytes())?;
    Ok(())
}

/// Forward an `api.github.com` request to the real upstream after
/// allow-list filtering. Workflow:
///
/// 1. Parse the buffered HTTP/1.1 request bytes (method + path +
///    headers + body).
/// 2. Extract the `owner/repo` slug from the path and check against
///    `allowed_repos`. Paths that don't fit the
///    `/repos/<owner>/<repo>/...` shape are still allowed if they're
///    user-scoped (`/user`, `/user/repos`) since gh CLI needs those
///    to function — those don't expose other-repo state.
/// 3. Read the real gh token from `<state>.secrets/gh` (written by
///    the launcher) and replace `GH_TOKEN_PLACEHOLDER` in the
///    `Authorization` header with it before forwarding.
/// 4. Make the upstream HTTPS request via `reqwest`, then format the
///    response as HTTP/1.1 bytes for the proxy to encrypt back to
///    the guest.
///
/// Bodies (request + response) are buffered in memory; OK for the gh
/// CLI / API use cases (JSON, tens of KB at most). Not suitable for
/// pack streams or large file uploads — those require streaming hook
/// support upstream (deferred).
async fn forward_github_api(
    request: &[u8],
    allowed_repos: &[String],
    state_dir: &Path,
) -> Result<http::Response> {
    let request = http::Request::parse(request).context("parsing intercepted github request")?;
    let method = request.method();
    let raw_target = request.target();
    let headers = request.headers();
    let body = request.body().to_vec();
    let target =
        parse_github_target(raw_target).context("validating intercepted github request target")?;
    let path = target.origin_form;

    // `/graphql` carries its repo references in the body, not the
    // path — gh CLI does most reads (repo list/view, pr, issue) over
    // GraphQL, so it gets its own body-level allow-list filter. Only
    // POST with the strict GraphQL envelope can receive authentication.
    let (path_no_query, query_string) = match path.split_once('?') {
        Some((p, q)) => (p, q),
        None => (path.as_str(), ""),
    };
    let access = if path_no_query == "/graphql" {
        // Our verdict comes from the body, so the body must be the only
        // thing GitHub can execute. Two guards on that:
        //
        //  * A query string is refused. We do not know that GitHub's
        //    GraphQL endpoint ignores `?query=`, and if it ever reads it
        //    (the graphql-ruby / Rails `params[:query]` idiom) the whole
        //    filter is bypassed by a benign-looking body. gh never sends
        //    one, so refusing costs nothing.
        //  * A non-JSON content type is refused, so a body encoding
        //    GitHub accepts but `serde_json` doesn't can't be judged on
        //    a parse failure of a different grammar.
        let content_type_is_json = headers.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("content-type")
                && v.to_ascii_lowercase().starts_with("application/json")
        });
        if method.eq_ignore_ascii_case("POST") && query_string.is_empty() && content_type_is_json {
            match crate::github_graphql::graphql_access(&body, allowed_repos) {
                crate::github_graphql::GraphqlAccess::Authenticated => GithubAccess::Authenticated,
                // Deny, not Anonymous. GitHub's GraphQL endpoint has no
                // anonymous tier: a stripped-Authorization query comes
                // back `403 API rate limit exceeded for <host IP>`,
                // which tells the agent nothing true. Same posture — no
                // token leaves — with a failure someone can act on.
                crate::github_graphql::GraphqlAccess::Denied(why) => GithubAccess::Deny(why),
            }
        } else {
            GithubAccess::Deny(
                "agent-vm: /graphql requires POST, no query string, and a JSON content type"
                    .to_string(),
            )
        }
    } else {
        github_access(method, &path, allowed_repos)
    };
    if let GithubAccess::Deny(reason) = &access {
        return http::Response::error(403, reason);
    }
    let real_token = read_gh_token(state_dir).context("reading <state>.secrets/gh")?;

    let url = format!("https://{}{}", secrets::GITHUB_API_HOST, path);

    let client = reqwest::Client::builder()
        // Bounded upstream timeout so a hung api.github.com call
        // doesn't freeze the in-VM agent indefinitely (review #7).
        .timeout(std::time::Duration::from_secs(60))
        // Reflect 3xx back to the guest verbatim rather than
        // following — protects against unexpected redirect targets
        // and lets the agent decide (review #7).
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("building reqwest client")?;
    let method_obj =
        reqwest::Method::from_bytes(method.as_bytes()).context("invalid HTTP method")?;
    let mut req = client.request(method_obj, &url);
    let mut had_authorization = false;
    for (name, value) in headers {
        // Strip hop-by-hop + protocol-level headers; reqwest will
        // re-emit appropriate ones. `Host` is required to point at
        // api.github.com (overrides whatever the guest sent).
        let lower = name.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "host"
                | "content-length"
                | "connection"
                | "transfer-encoding"
                | "te"
                | "keep-alive"
                | "proxy-authorization"
                | "proxy-authenticate"
                | "trailer"
                | "upgrade"
        ) {
            continue;
        }
        if lower == "authorization" {
            had_authorization = true;
            // Substitute the placeholder → real token. Two forms:
            //   - `token <PLACEHOLDER>` / `Bearer <PLACEHOLDER>` —
            //     literal substring, handled by `replace`.
            //   - `Basic base64(x-access-token:<PLACEHOLDER>)` —
            //     the placeholder is base64-encoded, so a literal
            //     replace finds nothing. Decode, substitute, re-
            //     encode.
            let v = substitute_authorization_header(value, &real_token);
            req = req.header("Authorization", v);
            continue;
        }
        req = req.header(name, value);
    }
    if !had_authorization {
        // An authenticated route with no guest Authorization still gets
        // the bearer rather than a misleading anonymous upstream 401.
        req = req.header("Authorization", format!("Bearer {real_token}"));
    }
    if !body.is_empty() {
        req = req.body(body);
    }

    let resp = req
        .send()
        .await
        .context("upstream send to api.github.com")?;

    let status = resp.status();
    let mut out_headers: Vec<(String, String)> = Vec::new();
    for (k, v) in resp.headers() {
        let k_lower = k.as_str().to_ascii_lowercase();
        // Strip hop-by-hop headers (we set Content-Length below) AND
        // anything that lets the guest re-authenticate as the host
        // user without going through the substitution proxy. Review
        // finding #3: Set-Cookie + WWW-Authenticate would otherwise
        // let an in-VM agent harvest GitHub session cookies and
        // drive github.com directly.
        if matches!(
            k_lower.as_str(),
            "transfer-encoding"
                | "content-length"
                | "connection"
                | "keep-alive"
                | "set-cookie"
                | "set-cookie2"
                | "www-authenticate"
                | "proxy-authenticate"
        ) {
            continue;
        }
        out_headers.push((k.as_str().to_string(), v.to_str().unwrap_or("").to_string()));
    }
    let body_bytes = resp
        .bytes()
        .await
        .context("reading upstream response body")?;

    let headers: Vec<_> = out_headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    http::Response::from_parts(
        status.as_u16(),
        status.canonical_reason().unwrap_or(""),
        &headers,
        &body_bytes,
    )
}

struct GithubTarget {
    /// The exact origin-form target whose repository scope was authorized.
    /// This same string is appended to the fixed upstream authority.
    origin_form: String,
}

fn parse_github_target(target: &str) -> Result<GithubTarget> {
    if target.contains('\\') || target.contains('#') || http::contains_escaped_path_escape(target) {
        anyhow::bail!("request target contains a forbidden path escape");
    }
    if target.starts_with('/') {
        if url::Url::parse(&format!("https://{}{}", secrets::GITHUB_API_HOST, target)).is_err() {
            anyhow::bail!("origin-form request target is invalid");
        }
        return Ok(GithubTarget {
            origin_form: target.to_string(),
        });
    }

    let url = url::Url::parse(target).context("absolute-form request target is invalid")?;
    if !url.scheme().eq_ignore_ascii_case("https")
        || !url
            .host_str()
            .is_some_and(|host| host.eq_ignore_ascii_case(secrets::GITHUB_API_HOST))
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        anyhow::bail!("absolute-form request authority does not match api.github.com");
    }
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    let origin_form = match url.query() {
        Some(query) => format!("{path}?{query}"),
        None => path.to_string(),
    };
    Ok(GithubTarget { origin_form })
}

#[cfg(test)]
mod target_tests {
    use super::*;

    #[test]
    fn github_target_rejects_normalization_and_authority_ambiguity() {
        for target in [
            "/repos/allowed/repo/%2e%2e/victim",
            "/repos/allowed/repo/%2Fvictim",
            "/repos/allowed/repo/%5cvictim",
            "/repos/allowed\\repo",
            "/repos/allowed/repo#fragment",
            "/repos/allowed/%zz",
            "https://attacker.invalid/repos/allowed/repo",
            "https://user@api.github.com/repos/allowed/repo",
            "https://api.github.com:444/repos/allowed/repo",
        ] {
            assert!(
                parse_github_target(target).is_err(),
                "{target} must be rejected"
            );
        }
    }

    #[test]
    fn github_target_authorizes_and_forwards_the_same_origin_form() {
        let target = parse_github_target("https://api.github.com/repos/allowed/repo?ref=main")
            .expect("valid absolute-form target");
        assert_eq!(target.origin_form, "/repos/allowed/repo?ref=main");
    }
}

/// Result of a GitHub access-policy decision.
///
/// - `Authenticated` — forward with the user's real token (the proxy
///   substitutes `GH_TOKEN_PLACEHOLDER` for the host bearer on the
///   wire).
/// - `Anonymous` — retained only for the smart-HTTP policy, where an
///   off-list request is deliberately forwarded without Authorization.
/// - `Deny(reason)` — synthesize a 403 with `reason`. Buffered GitHub
///   REST requests use this for every route outside the explicit policy.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
enum GithubAccess {
    Authenticated,
    Deny(String),
}

/// Policy decision for an api.github.com request.
///
/// **Spec:** allow-listed repositories receive host authentication;
/// off-list, malformed, and unknown REST routes receive a proxy 403.
///
/// The authenticated utility surface is intentionally method-specific:
/// `GET /user`, `GET /user/orgs[/...]`, `GET /rate_limit`, `GET /meta`,
/// and `POST /markdown`. In particular, account-wide mutations such as
/// `PATCH /user` cannot inherit the bearer.
fn github_access(method: &str, path: &str, allowed: &[String]) -> GithubAccess {
    let p = path.split_once('?').map(|(p, _)| p).unwrap_or(path);

    // Reject `..` traversal anywhere. GitHub server-normalises `..`,
    // so a crafted `/repos/<allowed>/.../../<victim>/private` could
    // otherwise resolve upstream to a different repo than we
    // approved. Cheap to reject up front for any method.
    for seg in p.split('/') {
        if seg == ".." {
            return GithubAccess::Deny(format!(
                "agent-vm: path {path:?} contains '..' (traversal rejected)"
            ));
        }
    }

    // Repo-scoped: allow-list determines auth.
    if let Some(rest) = p.strip_prefix("/repos/") {
        let mut it = rest.split('/');
        let owner = it.next().unwrap_or("");
        let repo = it.next().unwrap_or("");
        if owner.is_empty() || repo.is_empty() {
            return GithubAccess::Deny("agent-vm: malformed repository route".to_string());
        }
        let slug = format!("{owner}/{repo}");
        if allowed.iter().any(|a| a.eq_ignore_ascii_case(&slug)) {
            return GithubAccess::Authenticated;
        }
        return GithubAccess::Deny(format!(
            "agent-vm: repository {slug} is not on the allow-list"
        ));
    }

    // Identity / org-membership probe: keep auth so gh CLI works.
    if method.eq_ignore_ascii_case("GET")
        && (p == "/user" || p == "/user/orgs" || p.starts_with("/user/orgs/"))
    {
        return GithubAccess::Authenticated;
    }
    if method.eq_ignore_ascii_case("GET") && matches!(p, "/rate_limit" | "/meta") {
        return GithubAccess::Authenticated;
    }
    if method.eq_ignore_ascii_case("POST") && p == "/markdown" {
        return GithubAccess::Authenticated;
    }

    GithubAccess::Deny(format!(
        "agent-vm: GitHub REST route {method} {p} is not permitted"
    ))
}

/// Outcome of the smart-HTTP filter pass:
/// - `Authenticated`: passthrough verbatim (empty hook stdout — the
///   network secret-substitution layer swaps the placeholder for the
///   real bearer on the wire).
/// - `Anonymous`: passthrough with the buffered request's
///   Authorization header stripped (the new "modified passthrough"
///   verdict). GitHub then serves what an unauthenticated visitor
///   would see — public refs / blobs, 401 on private repos and
///   pushes.
/// - `Deny(reason)`: synthesized 403 (only on `..` traversal).
/// - `Malformed`: synthesized 400.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
enum GithubSmartOutcome {
    Authenticated,
    Anonymous,
    Deny(String),
    Malformed,
}

/// Decide what to do with a git-smart-HTTP request to github.com /
/// codeload / raw / objects.
///
/// **Spec:** allow-listed repo → my access (Authenticated); any other
/// repo → third-party access (Anonymous). GitHub itself then enforces
/// public-vs-private: clone of a public repo works, clone of a
/// private non-allow-listed repo gets 401, push to any non-allow-
/// listed repo gets 401.
///
/// URL shapes that we look at:
///   GET  /<owner>/<repo>.git/info/refs?service=git-{upload,receive}-pack
///   POST /<owner>/<repo>.git/git-{upload,receive}-pack
///   GET  /<owner>/<repo>/...                      (codeload / raw / objects)
fn github_smart_decision(request: &[u8], allowed_repos: &[String]) -> GithubSmartOutcome {
    let line_end = match request.windows(2).position(|w| w == b"\r\n") {
        Some(p) => p,
        None => return GithubSmartOutcome::Malformed,
    };
    let line = match std::str::from_utf8(&request[..line_end]) {
        Ok(s) => s,
        Err(_) => return GithubSmartOutcome::Malformed,
    };
    let mut parts = line.split_ascii_whitespace();
    let _method = match parts.next() {
        Some(m) => m,
        None => return GithubSmartOutcome::Malformed,
    };
    let path = match parts.next() {
        Some(p) => p,
        None => return GithubSmartOutcome::Malformed,
    };
    let path_no_query = path.split_once('?').map(|(p, _)| p).unwrap_or(path);
    if path_no_query.contains(['\\', '#']) || http::contains_escaped_path_escape(path_no_query) {
        return GithubSmartOutcome::Deny(
            "agent-vm: smart-HTTP path contains a forbidden escape".to_string(),
        );
    }
    let trimmed = path_no_query.trim_start_matches('/');

    for seg in trimmed.split('/') {
        if seg == ".." {
            return GithubSmartOutcome::Deny(format!(
                "agent-vm: path {path:?} contains '..' (traversal rejected)"
            ));
        }
    }

    // Extract owner/repo from the first two path segments. Strip a
    // single trailing `.git` (git smart paths are `<repo>.git/...`).
    let mut it = trimmed.split('/');
    let owner = it.next().unwrap_or("");
    let repo_raw = it.next().unwrap_or("");
    if owner.is_empty() || repo_raw.is_empty() {
        // Can't tell which repo — go anonymous, GitHub serves whatever
        // is public at that URL (typically 404 for malformed paths).
        return GithubSmartOutcome::Anonymous;
    }
    let repo = repo_raw.strip_suffix(".git").unwrap_or(repo_raw);
    let slug = format!("{owner}/{repo}");
    if allowed_repos.iter().any(|a| a.eq_ignore_ascii_case(&slug)) {
        GithubSmartOutcome::Authenticated
    } else {
        GithubSmartOutcome::Anonymous
    }
}

/// Return `request` with the `Authorization` header line removed.
/// Used to convert a buffered authenticated request into an
/// "anonymous" request that we can hand back to the proxy via the
/// passthrough-with-modified-bytes verdict.
///
/// Operates byte-precise on the header block (terminator
/// `\r\n\r\n`), preserves the request body verbatim, doesn't try to
/// re-parse anything else. Case-insensitive on the header name.
/// Inject (or overwrite) a `Connection: close` header in the request.
///
/// **Why:** msb's Interceptor handles one request per connection.
/// After dispatch its state becomes Disabled and subsequent HTTP/1.1
/// requests on the same TCP/TLS connection bypass the hook entirely
/// — the proxy forwards the secret-substitution layer's output
/// (with the real token already in the Authorization header) straight
/// to upstream. Forcing `Connection: close` makes the server tear
/// down the connection after responding, so any follow-up request
/// opens a fresh TCP, creating a fresh Interceptor that re-evaluates
/// the policy. This is the dominant real-world bypass: libcurl
/// (git's HTTP backend) reuses connections aggressively, and gh /
/// git clone do multiple requests per connection.
///
/// Operates byte-precise on the header block (terminator `\r\n\r\n`),
/// preserves the request body verbatim, doesn't try to re-parse
/// anything else.
fn set_connection_close(request: &[u8]) -> Vec<u8> {
    let hdr_end = match request.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(p) => p,
        None => return request.to_vec(), // malformed; pass through
    };
    let (head, rest) = request.split_at(hdr_end);

    // Collect kept lines, skipping any existing Connection / Keep-Alive
    // / Proxy-Connection headers — we replace them with our own
    // single `Connection: close`.
    let mut kept: Vec<&[u8]> = Vec::new();
    let mut cursor = 0usize;
    while cursor < head.len() {
        let (line, next_cursor) = match head[cursor..].windows(2).position(|w| w == b"\r\n") {
            Some(p) => (&head[cursor..cursor + p], cursor + p + 2),
            None => (&head[cursor..], head.len()),
        };
        let should_drop = line
            .iter()
            .position(|&b| b == b':')
            .map(|colon| {
                let name = &line[..colon];
                name.eq_ignore_ascii_case(b"connection")
                    || name.eq_ignore_ascii_case(b"keep-alive")
                    || name.eq_ignore_ascii_case(b"proxy-connection")
            })
            .unwrap_or(false);
        if !should_drop {
            kept.push(line);
        }
        cursor = next_cursor;
    }

    let mut out: Vec<u8> = Vec::with_capacity(request.len() + 32);
    for (i, line) in kept.iter().enumerate() {
        if i > 0 {
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(line);
    }
    // Always emit the Connection: close header (after the last kept
    // line, before the rest's \r\n\r\n). If `kept` is empty (no
    // request line — malformed), skip prepending the join \r\n.
    if !kept.is_empty() {
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"Connection: close");
    out.extend_from_slice(rest);
    out
}

fn strip_authorization_from_request(request: &[u8]) -> Vec<u8> {
    let hdr_end = match request.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(p) => p,
        None => return request.to_vec(), // malformed; pass through
    };
    let (head, rest) = request.split_at(hdr_end);
    // rest starts with "\r\n\r\n"; keep that + body verbatim.

    // Collect lines (request line + headers) that we want to keep.
    // Note: the LAST line in `head` has no trailing \r\n in `head`
    // (that \r\n is part of the \r\n\r\n in `rest`). We collect lines
    // verbatim then join with \r\n at the end — that way dropping the
    // last line is naturally handled: the previous line we kept does
    // not get a trailing \r\n, and `rest` supplies the \r\n that
    // terminates the last kept header.
    let mut kept: Vec<&[u8]> = Vec::new();
    let mut cursor = 0usize;
    while cursor < head.len() {
        let (line, next_cursor) = match head[cursor..].windows(2).position(|w| w == b"\r\n") {
            Some(p) => (&head[cursor..cursor + p], cursor + p + 2),
            None => (&head[cursor..], head.len()),
        };
        let is_auth = line
            .iter()
            .position(|&b| b == b':')
            .map(|colon| line[..colon].eq_ignore_ascii_case(b"authorization"))
            .unwrap_or(false);
        if !is_auth {
            kept.push(line);
        }
        cursor = next_cursor;
    }

    let mut out: Vec<u8> = Vec::with_capacity(request.len());
    for (i, line) in kept.iter().enumerate() {
        if i > 0 {
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(line);
    }
    // Append the body separator + body unchanged.
    out.extend_from_slice(rest);
    out
}

fn read_gh_token(state_dir: &Path) -> Result<String> {
    let p = secrets::gh_token_path(state_dir);
    let s = std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
    Ok(s.trim().to_string())
}

/// Substitute `GH_TOKEN_PLACEHOLDER` in an Authorization header value
/// with `real_token`, handling both:
/// - `token <PLACEHOLDER>` / `Bearer <PLACEHOLDER>` — literal
///   substring, simple `replace`.
/// - `Basic base64(x-access-token:<PLACEHOLDER>)` — git's HTTP basic
///   auth scheme. The placeholder is base64-encoded inside the value,
///   so a literal replace would miss it; decode, substitute, re-encode.
///
/// Falls back to the literal-replace result for any value that isn't
/// recognisable as Basic auth, so non-GitHub callers' headers are
/// touched as little as possible.
fn substitute_authorization_header(value: &str, real_token: &str) -> String {
    if let Some(b64) = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))
    {
        use base64::Engine as _;
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) {
            if let Ok(s) = std::str::from_utf8(&decoded) {
                if s.contains(secrets::GH_TOKEN_PLACEHOLDER) {
                    let sub = s.replace(secrets::GH_TOKEN_PLACEHOLDER, real_token);
                    let re = base64::engine::general_purpose::STANDARD.encode(sub.as_bytes());
                    return format!("Basic {re}");
                }
            }
        }
    }
    value.replace(secrets::GH_TOKEN_PLACEHOLDER, real_token)
}

fn write_response(bytes: &[u8]) -> Result<()> {
    let mut out = std::io::stdout().lock();
    out.write_all(bytes).context("writing response to stdout")?;
    out.flush().ok();
    Ok(())
}

// ─── tests ────────────────────────────────────────────────────────────
//
// Focus: the per-launch GitHub allow-list policy. This is the security
// surface — getting it wrong silently lets an in-VM agent push to or
// mutate repos the user didn't list. Cover the matrix:
//
//   axis            | values
//   ----------------|-----------------------------------------------
//   method          | GET, HEAD, POST, PATCH, PUT, DELETE
//   path category   | /repos/<o>/<r>/..., /graphql, /user, /user/repos,
//                   |   /user/keys, /markdown, /search, /admin, /...
//   allow-list      | empty, contains slug, contains other slug
//   traversal       | clean, .. anywhere
//   case            | uppercase/lowercase owner/repo
//
// For git smart-HTTP: discriminate clone/fetch (allow) from push
// (allow-list). Method+path+query distinguish them.

#[cfg(test)]
mod tests {
    use super::*;

    fn al(slugs: &[&str]) -> Vec<String> {
        slugs.iter().map(|s| s.to_string()).collect()
    }

    // ── github_access: allow-listed = my access ───────────────────

    #[test]
    fn gh_access_allow_listed_repo_is_authenticated() {
        let allowed = al(&["wirenboard/agent-vm"]);
        for m in ["GET", "HEAD", "POST", "PATCH", "PUT", "DELETE"] {
            assert_eq!(
                github_access(m, "/repos/wirenboard/agent-vm", &allowed),
                GithubAccess::Authenticated,
                "{m} /repos/wirenboard/agent-vm should be Authenticated"
            );
            assert_eq!(
                github_access(m, "/repos/wirenboard/agent-vm/issues", &allowed),
                GithubAccess::Authenticated,
            );
        }
    }

    #[test]
    fn gh_access_off_list_and_unknown_rest_routes_are_denied() {
        let allowed = al(&["wirenboard/agent-vm"]);
        for (method, path) in [
            ("GET", "/repos/octocat/Hello-World"),
            ("POST", "/repos/private/something/issues"),
            ("GET", "/search/code?q=foo"),
            ("GET", "/users/octocat"),
            ("POST", "/graphql"),
            ("GET", "/repos/"),
        ] {
            assert!(
                matches!(github_access(method, path, &allowed), GithubAccess::Deny(_)),
                "{method} {path} must receive a proxy denial"
            );
        }
    }

    #[test]
    fn gh_access_allow_list_match_is_case_insensitive() {
        let allowed = al(&["WirenBoard/Agent-VM"]);
        assert_eq!(
            github_access("POST", "/repos/wirenboard/agent-vm/issues", &allowed),
            GithubAccess::Authenticated,
        );
        assert_eq!(
            github_access("DELETE", "/repos/WIRENBOARD/AGENT-VM", &allowed),
            GithubAccess::Authenticated,
        );
    }

    #[test]
    fn gh_access_only_authenticates_safe_utility_methods() {
        let allowed = al(&[]);
        for (method, path) in [
            ("GET", "/user"),
            ("GET", "/user/orgs"),
            ("GET", "/user/orgs/123"),
            ("GET", "/rate_limit"),
            ("GET", "/meta"),
            ("POST", "/markdown"),
        ] {
            assert_eq!(
                github_access(method, path, &allowed),
                GithubAccess::Authenticated,
                "{method} {path} should be authenticated"
            );
        }
        for (method, path) in [
            ("PATCH", "/user"),
            ("POST", "/user/keys"),
            ("DELETE", "/user/orgs/123"),
            ("POST", "/rate_limit"),
            ("GET", "/markdown"),
        ] {
            assert!(
                matches!(github_access(method, path, &allowed), GithubAccess::Deny(_)),
                "{method} {path} must not receive host authentication"
            );
        }
    }

    #[test]
    fn gh_access_traversal_is_denied() {
        let allowed = al(&["allowed/repo"]);
        for path in ["/repos/allowed/repo/../../victim/private", "/../etc/passwd"] {
            assert!(matches!(
                github_access("GET", path, &allowed),
                GithubAccess::Deny(_)
            ));
        }
    }

    // ── github_smart_decision: smart-HTTP ─────────────────────────

    fn req(line: &str) -> Vec<u8> {
        format!("{line}\r\nHost: github.com\r\n\r\n").into_bytes()
    }

    #[test]
    fn smart_allow_listed_repo_is_authenticated_for_clone_and_push() {
        let allowed = al(&["wirenboard/agent-vm"]);
        // Clone handshake.
        assert_eq!(
            github_smart_decision(
                &req("GET /wirenboard/agent-vm.git/info/refs?service=git-upload-pack HTTP/1.1"),
                &allowed,
            ),
            GithubSmartOutcome::Authenticated,
        );
        // Push handshake.
        assert_eq!(
            github_smart_decision(
                &req("GET /wirenboard/agent-vm.git/info/refs?service=git-receive-pack HTTP/1.1"),
                &allowed,
            ),
            GithubSmartOutcome::Authenticated,
        );
        // Push data.
        assert_eq!(
            github_smart_decision(
                &req("POST /wirenboard/agent-vm.git/git-receive-pack HTTP/1.1"),
                &allowed,
            ),
            GithubSmartOutcome::Authenticated,
        );
    }

    #[test]
    fn smart_other_repo_is_anonymous_for_any_operation() {
        // Third-party model: clone of a public repo works (GitHub
        // serves it), private 401s, push always 401s. We hand back
        // the same "Anonymous" verdict for every op and let GitHub
        // enforce.
        let allowed = al(&["wirenboard/agent-vm"]);
        for line in [
            "GET /octocat/Hello-World.git/info/refs?service=git-upload-pack HTTP/1.1",
            "POST /octocat/Hello-World.git/git-upload-pack HTTP/1.1",
            "GET /octocat/Hello-World.git/info/refs?service=git-receive-pack HTTP/1.1",
            "POST /octocat/Hello-World.git/git-receive-pack HTTP/1.1",
            "GET /octocat/Hello-World/zip/refs/heads/master HTTP/1.1",
            "GET /octocat/Hello-World/main/README.md HTTP/1.1",
        ] {
            assert_eq!(
                github_smart_decision(&req(line), &allowed),
                GithubSmartOutcome::Anonymous,
                "expected Anonymous for: {line}"
            );
        }
    }

    #[test]
    fn smart_dot_git_suffix_is_stripped_once_only() {
        let allowed = al(&["owner/repo.git"]);
        // Allow-list is literally `owner/repo.git` (silly but legal).
        // smart path is `/owner/repo.git.git/...`. After stripping
        // ONE `.git`, slug = `owner/repo.git`, matches the allow-list.
        assert_eq!(
            github_smart_decision(
                &req("POST /owner/repo.git.git/git-receive-pack HTTP/1.1"),
                &allowed,
            ),
            GithubSmartOutcome::Authenticated,
        );
    }

    #[test]
    fn smart_traversal_and_encoded_separators_are_denied() {
        let allowed = al(&["allowed/repo"]);
        for target in [
            "/allowed/repo.git/../../victim/private.git/git-receive-pack",
            "/allowed/repo.git/%2e%2e/victim/private.git/git-receive-pack",
            "/allowed/repo.git/%2Fvictim/private.git/git-receive-pack",
        ] {
            assert!(matches!(
                github_smart_decision(&req(&format!("POST {target} HTTP/1.1")), &allowed),
                GithubSmartOutcome::Deny(_),
            ));
        }
    }

    #[test]
    fn smart_case_insensitive_allow_list() {
        let allowed = al(&["WirenBoard/Agent-VM"]);
        assert_eq!(
            github_smart_decision(
                &req("POST /wirenboard/agent-vm.git/git-receive-pack HTTP/1.1"),
                &allowed,
            ),
            GithubSmartOutcome::Authenticated,
        );
    }

    #[test]
    fn smart_malformed_request_is_flagged() {
        for r in [
            b"GET /foo HTTP/1.1".as_slice(),
            b"".as_slice(),
            b"GET\r\n".as_slice(),
        ] {
            assert!(matches!(
                github_smart_decision(r, &al(&["x/y"])),
                GithubSmartOutcome::Malformed,
            ));
        }
    }

    #[test]
    fn smart_malformed_owner_repo_path_is_anonymous() {
        // `/just-one-segment` doesn't name owner/repo. Old policy
        // denied; new policy goes Anonymous and lets GitHub 404.
        let allowed = al(&["x/y"]);
        assert_eq!(
            github_smart_decision(&req("GET /just-one-segment HTTP/1.1"), &allowed,),
            GithubSmartOutcome::Anonymous,
        );
    }

    // ── strip_authorization_from_request ─────────────────────────

    #[test]
    fn strip_auth_removes_the_header_keeps_body() {
        let r = format!(
            "POST /repos/x/y/issues HTTP/1.1\r\n\
             Host: api.github.com\r\n\
             Authorization: token {placeholder}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: 11\r\n\
             \r\n\
             {{\"title\":1}}",
            placeholder = secrets::GH_TOKEN_PLACEHOLDER,
        );
        let out = strip_authorization_from_request(r.as_bytes());
        let s = std::str::from_utf8(&out).unwrap();
        // Authorization line gone.
        assert!(!s.to_ascii_lowercase().contains("authorization:"));
        // Other headers preserved.
        assert!(s.contains("Host: api.github.com"));
        assert!(s.contains("Content-Type: application/json"));
        assert!(s.contains("Content-Length: 11"));
        // Body preserved verbatim.
        assert!(s.ends_with("\r\n\r\n{\"title\":1}"));
        // Placeholder absent at any layer.
        assert!(!s.contains(secrets::GH_TOKEN_PLACEHOLDER));
    }

    #[test]
    fn strip_auth_case_insensitive_on_header_name() {
        let r = b"GET /x HTTP/1.1\r\n\
                  authorization: Bearer X\r\n\
                  AUTHORIZATION: Bearer Y\r\n\
                  AuThOrIzAtIoN: Bearer Z\r\n\
                  Host: api.github.com\r\n\r\n";
        let out = strip_authorization_from_request(r);
        let s = std::str::from_utf8(&out).unwrap();
        assert!(!s.to_ascii_lowercase().contains("authorization:"));
        assert!(s.contains("Host: api.github.com"));
    }

    #[test]
    fn strip_auth_no_auth_present_is_noop() {
        let r = b"GET /x HTTP/1.1\r\nHost: api.github.com\r\nUser-Agent: gh\r\n\r\n";
        let out = strip_authorization_from_request(r);
        assert_eq!(out, r);
    }

    #[test]
    fn strip_auth_malformed_no_separator_returns_input() {
        let r = b"GET /x HTTP/1.1\r\nAuthorization: Bearer X";
        let out = strip_authorization_from_request(r);
        // We don't try to parse beyond the separator; if it's
        // missing, pass through unchanged so the proxy at least
        // forwards SOMETHING.
        assert_eq!(out, r);
    }

    /// Regression: when Authorization is the LAST header (its line
    /// has no trailing \r\n in `head` — that \r\n is part of the
    /// \r\n\r\n separator in `rest`), an earlier implementation
    /// dropped the line but kept the previous header's trailing \r\n,
    /// and then appended `rest` which itself starts with \r\n\r\n.
    /// Result: three consecutive \r\n between headers and body,
    /// shifting body content by 2 bytes and breaking Content-Length
    /// or poisoning the next request on a keep-alive connection.
    #[test]
    fn strip_auth_when_authorization_is_last_header_no_extra_crlf() {
        let r = b"GET / HTTP/1.1\r\n\
                  Host: api.github.com\r\n\
                  Authorization: Bearer LAST\r\n\
                  \r\n\
                  body-bytes";
        let out = strip_authorization_from_request(r);
        let s = std::str::from_utf8(&out).unwrap();
        // Header/body separator must be exactly one \r\n\r\n.
        assert!(
            s.contains("Host: api.github.com\r\n\r\nbody-bytes"),
            "expected exactly one CRLFCRLF between headers and body; got:\n{s:?}"
        );
        assert!(!s.contains("\r\n\r\n\r\n"), "no triple CRLF; got:\n{s:?}");
        assert!(!s.to_ascii_lowercase().contains("authorization:"));
        // Body is preserved verbatim and starts immediately after the
        // single \r\n\r\n.
        assert!(s.ends_with("\r\n\r\nbody-bytes"));
    }

    #[test]
    fn strip_auth_preserves_request_line_and_other_colons() {
        // Some header values contain `:` (e.g. Cookie name=URL). The
        // split-on-first-`:` for the header NAME must not be tricked.
        let r = b"POST /repos/x/y HTTP/1.1\r\n\
                  Cookie: a=b; url=http://example.com/path\r\n\
                  Authorization: token PLACEHOLDER\r\n\
                  \r\n";
        let out = strip_authorization_from_request(r);
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.starts_with("POST /repos/x/y HTTP/1.1\r\n"));
        assert!(s.contains("Cookie: a=b; url=http://example.com/path"));
        assert!(!s.to_ascii_lowercase().contains("authorization:"));
    }

    // ── substitute_authorization_header ───────────────────────────

    #[test]
    fn auth_substitute_bearer_is_literal_replace() {
        let out = substitute_authorization_header(
            &format!("Bearer {}", secrets::GH_TOKEN_PLACEHOLDER),
            "real_token_xyz",
        );
        assert_eq!(out, "Bearer real_token_xyz");
    }

    #[test]
    fn auth_substitute_token_form_is_literal_replace() {
        let out = substitute_authorization_header(
            &format!("token {}", secrets::GH_TOKEN_PLACEHOLDER),
            "real_token_xyz",
        );
        assert_eq!(out, "token real_token_xyz");
    }

    #[test]
    fn auth_substitute_basic_decodes_encodes() {
        use base64::Engine as _;
        let basic_value = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("x-access-token:{}", secrets::GH_TOKEN_PLACEHOLDER).as_bytes())
        );
        let out = substitute_authorization_header(&basic_value, "real_xyz");
        // Round-trip: decode the result and check it contains the real token.
        let stripped = out.strip_prefix("Basic ").expect("Basic prefix preserved");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(stripped.as_bytes())
            .expect("output is valid base64");
        let s = std::str::from_utf8(&decoded).expect("utf8");
        assert_eq!(s, "x-access-token:real_xyz");
        // And the placeholder is NOT in the output at any layer.
        assert!(!out.contains(secrets::GH_TOKEN_PLACEHOLDER));
        assert!(!s.contains(secrets::GH_TOKEN_PLACEHOLDER));
    }

    #[test]
    fn auth_substitute_basic_no_placeholder_passes_through() {
        // A `Basic ...` value that doesn't carry our placeholder
        // should not be re-encoded; preserve verbatim so we don't
        // silently mangle the caller's credentials.
        use base64::Engine as _;
        let untouched_basic = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(b"alice:hunter2")
        );
        let out = substitute_authorization_header(&untouched_basic, "real_xyz");
        assert_eq!(out, untouched_basic);
    }

    // ── set_connection_close ──────────────────────────────────────

    #[test]
    fn connection_close_injected_when_header_absent() {
        let r = b"GET / HTTP/1.1\r\nHost: github.com\r\n\r\n";
        let out = set_connection_close(r);
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.contains("Connection: close\r\n\r\n"), "got: {s:?}");
        assert!(s.starts_with("GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn connection_close_replaces_existing_keep_alive() {
        // RFC 7230 says proxies must remove hop-by-hop headers
        // (Connection, Keep-Alive, Proxy-Connection) — we strip all
        // three and emit our own single Connection: close.
        let r = b"GET / HTTP/1.1\r\n\
                  Host: github.com\r\n\
                  Connection: keep-alive\r\n\
                  Keep-Alive: timeout=60\r\n\
                  Proxy-Connection: keep-alive\r\n\
                  \r\n";
        let out = set_connection_close(r);
        let s = std::str::from_utf8(&out).unwrap();
        // All three hop-by-hop headers must be removed; only our
        // single Connection: close remains.
        let lower = s.to_ascii_lowercase();
        assert_eq!(
            lower.matches("connection:").count(),
            1,
            "should have exactly one Connection header; got: {s:?}"
        );
        assert!(s.contains("Connection: close"));
        assert!(!lower.contains("keep-alive:"));
        assert!(!lower.contains("proxy-connection:"));
        assert!(s.contains("Host: github.com"));
    }

    #[test]
    fn connection_close_preserves_body_verbatim() {
        let r = b"POST /x HTTP/1.1\r\n\
                  Host: github.com\r\n\
                  Content-Length: 5\r\n\
                  \r\n\
                  hello";
        let out = set_connection_close(r);
        let s = std::str::from_utf8(&out).unwrap();
        assert!(
            s.contains("\r\n\r\nhello"),
            "body must follow exactly one \\r\\n\\r\\n; got: {s:?}"
        );
        assert!(s.ends_with("hello"));
    }

    /// End-to-end: after the hook runs on a non-allow-listed clone,
    /// the bytes that reach upstream MUST contain `Connection: close`
    /// (to prevent the keep-alive bypass for any follow-up requests
    /// libcurl/git would do on the same TCP connection). This is the
    /// regression assertion for the bug behind real-world private
    /// repo clone-through.
    #[test]
    fn anonymous_passthrough_forces_connection_close() {
        use base64::Engine as _;
        use microsandbox_network::secrets::handler::SecretsHandler;

        let placeholder = secrets::GH_TOKEN_PLACEHOLDER;
        let real_token = "REAL_TOKEN_KEEPALIVE_DEFENSE_CANARY";

        let config = build_github_secrets_config(placeholder, real_token);
        let mut handler = SecretsHandler::new(&config, "github.com", true);

        let creds = format!("x-access-token:{placeholder}");
        let b64 = base64::engine::general_purpose::STANDARD.encode(creds.as_bytes());
        let req = format!(
            "GET /evgeny-boger/mitsubishi-ac-ir.git/info/refs?service=git-upload-pack HTTP/1.1\r\n\
             Host: github.com\r\n\
             Connection: keep-alive\r\n\
             User-Agent: git/2.47\r\n\
             Authorization: Basic {b64}\r\n\
             \r\n"
        );
        let substituted = handler.substitute(req.as_bytes()).expect("not a violation");
        let allowed: Vec<String> = Vec::new();
        assert!(matches!(
            github_smart_decision(&substituted, &allowed),
            GithubSmartOutcome::Anonymous
        ));

        // What the hook would write to stdout for Anonymous:
        let hook_out = set_connection_close(&strip_authorization_from_request(&substituted));
        let s = std::str::from_utf8(&hook_out).unwrap();

        let expected_creds = format!("x-access-token:{real_token}");
        let expected_b64 =
            base64::engine::general_purpose::STANDARD.encode(expected_creds.as_bytes());
        // No real token of any flavor.
        assert!(!s.contains(real_token), "raw real token leaked: {s}");
        assert!(!s.contains(&expected_b64), "base64 real token leaked: {s}");
        // No keep-alive — the defining property of the fix.
        assert!(
            s.contains("Connection: close"),
            "Connection: close missing — keep-alive bypass still possible: {s}"
        );
        let lower = s.to_ascii_lowercase();
        assert_eq!(lower.matches("connection:").count(), 1);
        assert!(!lower.contains("keep-alive:"));
    }

    /// End-to-end: same for the allow-listed (Authenticated) path.
    /// The real token IS allowed through (that's the point), but the
    /// connection still MUST be torn down after responding so that
    /// a subsequent (potentially non-allow-listed) request on the
    /// same TCP doesn't bypass the hook.
    #[test]
    fn authenticated_passthrough_forces_connection_close() {
        use base64::Engine as _;
        use microsandbox_network::secrets::handler::SecretsHandler;

        let placeholder = secrets::GH_TOKEN_PLACEHOLDER;
        let real_token = "REAL_TOKEN_ALLOWED_REPO";

        let config = build_github_secrets_config(placeholder, real_token);
        let mut handler = SecretsHandler::new(&config, "github.com", true);

        let creds = format!("x-access-token:{placeholder}");
        let b64 = base64::engine::general_purpose::STANDARD.encode(creds.as_bytes());
        let req = format!(
            "POST /wirenboard/agent-vm.git/git-upload-pack HTTP/1.1\r\n\
             Host: github.com\r\n\
             Connection: keep-alive\r\n\
             Authorization: Basic {b64}\r\n\
             Content-Length: 0\r\n\
             \r\n"
        );
        let substituted = handler.substitute(req.as_bytes()).expect("not a violation");
        let allowed = vec!["wirenboard/agent-vm".to_string()];
        assert!(matches!(
            github_smart_decision(&substituted, &allowed),
            GithubSmartOutcome::Authenticated
        ));

        let hook_out = set_connection_close(&substituted);
        let s = std::str::from_utf8(&hook_out).unwrap();

        // Real token IS in here — Authenticated means it's allowed.
        let expected_creds = format!("x-access-token:{real_token}");
        let expected_b64 =
            base64::engine::general_purpose::STANDARD.encode(expected_creds.as_bytes());
        assert!(
            s.contains(&expected_b64),
            "auth must reach upstream for allow-listed repo"
        );
        // Connection must be close — the connection-reset is the
        // entire point even for the allowed path.
        assert!(
            s.contains("Connection: close"),
            "Connection: close missing on Authenticated: {s}"
        );
        let lower = s.to_ascii_lowercase();
        assert_eq!(lower.matches("connection:").count(), 1);
        assert!(!lower.contains("keep-alive:"));
    }

    // ── full pipeline (secrets → hook) end-to-end regression ──────
    //
    // These tests wire up the SAME pipeline order as
    // `vendor/microsandbox/.../tls/proxy.rs:forward_plaintext`:
    //
    //   1. SecretsHandler.substitute(guest_bytes)
    //         → inject_basic_auth base64-decodes the Authorization,
    //           swaps GH_TOKEN_PLACEHOLDER for the real token, re-encodes.
    //   2. github_smart_decision(substituted_bytes, allowed_repos)
    //         → Authenticated / Anonymous / Deny / Malformed.
    //   3. If Anonymous: strip_authorization_from_request(substituted_bytes)
    //         is the bytes the proxy actually writes to upstream.
    //
    // The invariant under test: for a NON-allow-listed private repo,
    // the bytes that would reach GitHub must NOT contain the real
    // token. If this test ever fails, a private repo clone would
    // succeed against the proxy.

    #[allow(dead_code)] // helper used only by the test below
    fn build_github_secrets_config(
        placeholder: &str,
        real_token: &str,
    ) -> microsandbox_network::secrets::config::SecretsConfig {
        use microsandbox_network::secrets::config::{
            HostPattern, SecretEntry, SecretInjection, SecretsConfig,
        };
        SecretsConfig {
            secrets: vec![SecretEntry {
                env_var: "GH_TOKEN".into(),
                // This isolated proxy-pipeline fixture uses a synthetic
                // static bearer; launch configuration uses `SecretSource::File`.
                value: real_token.to_string().into(),
                source: None,
                placeholder: placeholder.into(),
                allowed_hosts: vec![
                    HostPattern::Exact("github.com".into()),
                    HostPattern::Exact("api.github.com".into()),
                    HostPattern::Exact("codeload.github.com".into()),
                    HostPattern::Exact("raw.githubusercontent.com".into()),
                    HostPattern::Exact("objects.githubusercontent.com".into()),
                ],
                injection: SecretInjection {
                    headers: true,
                    basic_auth: true,
                    query_params: false,
                    body: false,
                },
                on_violation: None,
                require_tls_identity: true,
            }],
            on_violation: Default::default(),
        }
    }

    /// E2E: git's first request to clone a private, NON-allow-listed
    /// repo. Pipeline: secrets-substitute(real token in Basic auth) →
    /// hook returns Anonymous (strip auth). Real token MUST NOT
    /// appear in the bytes the proxy would forward to GitHub.
    #[test]
    fn private_repo_clone_does_not_leak_real_token_through_pipeline() {
        use base64::Engine as _;
        use microsandbox_network::secrets::handler::SecretsHandler;

        // Sentinel values: if either string shows up in the final
        // upstream bytes, the test fails — we'd be leaking a real
        // token to the network.
        let placeholder = secrets::GH_TOKEN_PLACEHOLDER;
        let real_token = "REAL_TOKEN_MUST_NEVER_REACH_UPSTREAM_42";

        let config = build_github_secrets_config(placeholder, real_token);
        let mut handler = SecretsHandler::new(&config, "github.com", true);

        // What git actually sends when cloning a private repo via
        // HTTPS with the credential helper: Basic auth carrying
        // `x-access-token:<placeholder>` base64-encoded. Authorization
        // is the LAST header (the bug we fixed earlier hit exactly
        // this shape).
        let creds = format!("x-access-token:{placeholder}");
        let b64 = base64::engine::general_purpose::STANDARD.encode(creds.as_bytes());
        let request = format!(
            "GET /evgeny-boger/mitsubishi-ac-ir/info/refs?service=git-upload-pack HTTP/1.1\r\n\
             Host: github.com\r\n\
             User-Agent: git/2.47\r\n\
             Accept: */*\r\n\
             Authorization: Basic {b64}\r\n\
             \r\n"
        );
        let request_bytes = request.as_bytes();

        // Step 1: secrets layer substitutes the placeholder with the
        // real token (decoded basic creds, replaced, re-encoded).
        let substituted = handler.substitute(request_bytes).expect("not a violation");
        let substituted_bytes: &[u8] = &substituted;

        // Sanity check: the real token IS in the substituted bytes
        // (base64-encoded inside the Basic value). If this fails the
        // SecretsHandler isn't doing its job — different bug.
        let expected_creds = format!("x-access-token:{real_token}");
        let expected_b64 =
            base64::engine::general_purpose::STANDARD.encode(expected_creds.as_bytes());
        let substituted_str = std::str::from_utf8(substituted_bytes)
            .expect("substituted output should still be UTF-8 for this ASCII request");
        assert!(
            substituted_str.contains(&expected_b64),
            "secrets layer should have substituted the placeholder with the real token; \
             expected Basic value {expected_b64:?} in:\n{substituted_str}"
        );

        // Step 2: hook decides. Repo evgeny-boger/mitsubishi-ac-ir is
        // NOT in the (empty) allow-list → Anonymous.
        let allowed: Vec<String> = Vec::new();
        let decision = github_smart_decision(substituted_bytes, &allowed);
        assert!(
            matches!(decision, GithubSmartOutcome::Anonymous),
            "non-allow-listed repo must route to Anonymous (third-party access)"
        );

        // Step 3: stripped bytes are what hits upstream.
        let upstream_bytes = strip_authorization_from_request(substituted_bytes);
        let upstream_str =
            std::str::from_utf8(&upstream_bytes).expect("stripped request should still be UTF-8");

        // INVARIANT: real token bytes (raw AND base64) must not be
        // anywhere in what we send upstream.
        assert!(
            !upstream_str.contains(real_token),
            "raw real token leaked to upstream:\n{upstream_str}"
        );
        assert!(
            !upstream_str.contains(&expected_b64),
            "base64-encoded real token leaked to upstream:\n{upstream_str}"
        );

        // And no Authorization header at all should reach upstream.
        assert!(
            !upstream_str.to_ascii_lowercase().contains("authorization:"),
            "Authorization header reached upstream:\n{upstream_str}"
        );
    }

    /// Two requests on the SAME connection (HTTP/1.1 keep-alive),
    /// which is what git+libcurl actually do during clone (info/refs
    /// then git-upload-pack). The SecretsHandler is created once per
    /// connection and reused for both requests. This test asserts
    /// that the substitution layer + naive hook-style filtering
    /// alone do NOT close the leak: a second request's real token
    /// can reach upstream if the hook isn't re-invoked.
    ///
    /// This is a hypothesis-confirmation test — it reproduces the
    /// keep-alive bypass that the unit-level pipeline test misses.
    /// If this test shows the second request's bytes contain the
    /// real token without going through the hook, we've found the
    /// real-world leak.
    #[test]
    fn keep_alive_second_request_bytes_contain_real_token_pre_hook() {
        use base64::Engine as _;
        use microsandbox_network::secrets::handler::SecretsHandler;

        let placeholder = secrets::GH_TOKEN_PLACEHOLDER;
        let real_token = "REAL_TOKEN_KEEPALIVE_LEAK_CANARY";

        let config = build_github_secrets_config(placeholder, real_token);
        // ONE handler per "connection".
        let mut handler = SecretsHandler::new(&config, "github.com", true);

        let creds = format!("x-access-token:{placeholder}");
        let b64 = base64::engine::general_purpose::STANDARD.encode(creds.as_bytes());

        // Request 1 — info/refs (the request the hook intercepts).
        let req1 = format!(
            "GET /evgeny-boger/mitsubishi-ac-ir.git/info/refs?service=git-upload-pack HTTP/1.1\r\n\
             Host: github.com\r\n\
             Authorization: Basic {b64}\r\n\
             \r\n"
        );
        let sub1 = handler
            .substitute(req1.as_bytes())
            .expect("not a violation");
        // The hook would run here and strip auth for non-allow-listed.
        // Asserting that part is the other test.

        // Request 2 — second request on the SAME connection (e.g.
        // a retry, or libcurl's pipelined follow-up). In the real
        // proxy, after the first dispatch the Interceptor goes to
        // State::Disabled and returns Verdict::Forward for every
        // subsequent chunk — which means the substituted bytes go
        // STRAIGHT to upstream, unfiltered.
        let req2 = format!(
            "POST /evgeny-boger/mitsubishi-ac-ir.git/git-upload-pack HTTP/1.1\r\n\
             Host: github.com\r\n\
             Content-Type: application/x-git-upload-pack-request\r\n\
             Authorization: Basic {b64}\r\n\
             Content-Length: 0\r\n\
             \r\n"
        );
        let sub2 = handler
            .substitute(req2.as_bytes())
            .expect("not a violation");
        let sub2_str = std::str::from_utf8(&sub2).unwrap();

        let expected_creds = format!("x-access-token:{real_token}");
        let expected_b64 =
            base64::engine::general_purpose::STANDARD.encode(expected_creds.as_bytes());

        // INVARIANT (currently FAILS for keep-alive): if the hook
        // isn't re-engaged for request 2, the substituted bytes
        // (with real token) are what hits the wire. This assertion
        // documents the leak — if it passes (i.e., real token IS
        // in sub2), we've confirmed the bypass.
        let leaked = sub2_str.contains(&expected_b64);
        assert!(
            leaked,
            "expected the keep-alive bypass to manifest: secret-substitution \
             puts the real token in the bytes of request 2 on the same connection, \
             and the proxy's interceptor goes to Disabled after request 1's \
             dispatch — so these bytes go upstream unfiltered. \
             If this assertion fails the leak may already be plugged."
        );

        // For completeness: prove request 1 alone is properly stripped by the hook.
        let allowed: Vec<String> = Vec::new();
        let decision1 = github_smart_decision(&sub1, &allowed);
        assert!(matches!(decision1, GithubSmartOutcome::Anonymous));
        let stripped1 = strip_authorization_from_request(&sub1);
        let stripped1_str = std::str::from_utf8(&stripped1).unwrap();
        assert!(
            !stripped1_str.contains(&expected_b64),
            "request 1 strip should remove the real token from the wire"
        );
    }

    /// E2E: same pipeline, but the repo IS allow-listed → hook
    /// returns Authenticated (empty stdout → proxy forwards the
    /// post-substitution bytes verbatim). Real token SHOULD appear
    /// upstream in this case (legitimate clone).
    #[test]
    fn allowlisted_repo_clone_does_pass_real_token_through_pipeline() {
        use base64::Engine as _;
        use microsandbox_network::secrets::handler::SecretsHandler;

        let placeholder = secrets::GH_TOKEN_PLACEHOLDER;
        let real_token = "REAL_TOKEN_FOR_ALLOWED_REPO";

        let config = build_github_secrets_config(placeholder, real_token);
        let mut handler = SecretsHandler::new(&config, "github.com", true);

        let creds = format!("x-access-token:{placeholder}");
        let b64 = base64::engine::general_purpose::STANDARD.encode(creds.as_bytes());
        let request = format!(
            "GET /wirenboard/agent-vm/info/refs?service=git-upload-pack HTTP/1.1\r\n\
             Host: github.com\r\n\
             Authorization: Basic {b64}\r\n\
             \r\n"
        );
        let substituted = handler
            .substitute(request.as_bytes())
            .expect("not a violation");

        let allowed = vec!["wirenboard/agent-vm".to_string()];
        let decision = github_smart_decision(&substituted, &allowed);
        assert!(
            matches!(decision, GithubSmartOutcome::Authenticated),
            "allow-listed repo must route to Authenticated"
        );

        // In the proxy, Authenticated means hook returns empty stdout
        // → `Verdict::ForwardBuffered(substituted)`. So the real token
        // (in the substituted bytes) IS what reaches upstream — this
        // is the intended path for legitimate auth on allowed repos.
        let upstream_str = std::str::from_utf8(&substituted).unwrap();
        let expected_creds = format!("x-access-token:{real_token}");
        let expected_b64 =
            base64::engine::general_purpose::STANDARD.encode(expected_creds.as_bytes());
        assert!(
            upstream_str.contains(&expected_b64),
            "for allow-listed repo, real token should reach upstream; got:\n{upstream_str}"
        );
    }
}
