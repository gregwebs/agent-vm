//! Host-rooted credentials.
//!
//! At launch we snapshot the host's Claude / Codex credential files,
//! write placeholder credentials into the guest-side state directory,
//! and return the per-project token-file *paths* to the launcher. The
//! launcher registers them as microsandbox `SecretSource::File`
//! entries; the microsandbox proxy re-reads the file on every TLS-intercepted
//! connection so a host-side rotation is picked up on the next request.
//!
//! The same token files are rewritten by the hook's private OAuth-refresh
//! module when an in-VM agent's OAuth refresh attempt fires.
//!
//! Placeholders are stable per-version so credentials JSON written by
//! a prior invocation is still valid for the current one.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::host_paths::{
    GuestStateDir, MAX_HOST_CREDENTIAL_FILE_BYTES, atomic_write, host_claude_creds_path,
    host_codex_auth_path, host_copilot_token_path, host_opencode_auth_path,
    read_bounded_regular_file,
};

// ---------------------------------------------------------------------------
// Placeholder strings the guest sees instead of real tokens. Substituted
// for the real value at the network layer on the way out, and forged
// into OAuth refresh responses by `intercept_hook`.

pub const ANTHROPIC_ACCESS_PLACEHOLDER: &str = "msb-anthropic-placeholder-a-v2";
pub const ANTHROPIC_REFRESH_PLACEHOLDER: &str = "msb-anthropic-placeholder-r-v2";
pub const OPENAI_ACCESS_PLACEHOLDER: &str = "msb-openai-placeholder-a-v2";
pub const OPENAI_REFRESH_PLACEHOLDER: &str = "msb-openai-placeholder-r-v2";
/// Synthetic JWT (alg:none) carrying only placeholder fields. Codex
/// parses `tokens.id_token` client-side at startup, so the placeholder
/// has to be structurally a JWT or codex refuses to load — but it has
/// no real PII. `email`, `chatgpt_account_id`, `chatgpt_plan_type`,
/// `chatgpt_subscription_active_until`, `chatgpt_user_id` are the
/// fields codex reads from the payload; values here are clearly-fake
/// so they're obvious in logs.
///
/// header  = base64url('{"alg":"none","typ":"JWT"}')
/// payload = base64url('{"email":"placeholder@msb.local","exp":9999999999,"iat":1700000000,
///                       "https://api.openai.com/auth":{"chatgpt_account_id":"00000000-0000-0000-0000-000000000000",
///                       "chatgpt_plan_type":"placeholder","chatgpt_subscription_active_until":"9999-12-31T00:00:00+00:00",
///                       "chatgpt_user_id":"user-placeholder"},"sub":"placeholder|0"}')
/// sig     = "msb-openai-placeholder-id-v2". Keep this marker
///           non-token-shaped: Claude/Anthropic may reset requests that
///           contain token-looking sentinel values copied from shell output
///           into a transcript.
pub const OPENAI_ID_PLACEHOLDER: &str = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJlbWFpbCI6InBsYWNlaG9sZGVyQG1zYi5sb2NhbCIsImV4cCI6OTk5OTk5OTk5OSwiaWF0IjoxNzAwMDAwMDAwLCJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9hY2NvdW50X2lkIjoiMDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwIiwiY2hhdGdwdF9wbGFuX3R5cGUiOiJwbGFjZWhvbGRlciIsImNoYXRncHRfc3Vic2NyaXB0aW9uX2FjdGl2ZV91bnRpbCI6Ijk5OTktMTItMzFUMDA6MDA6MDArMDA6MDAiLCJjaGF0Z3B0X3VzZXJfaWQiOiJ1c2VyLXBsYWNlaG9sZGVyIn0sInN1YiI6InBsYWNlaG9sZGVyfDAifQ.msb-openai-placeholder-id-v2";
/// Synthetic JWT used as the placeholder for OpenCode's OAuth `access`
/// field. OpenCode sends `Authorization: Bearer <access>` to
/// api.openai.com, so this string is the exact byte sequence the proxy
/// scans for and substitutes with the real OpenAI access token (kept
/// in the same host-only token file as Codex uses). Must be distinct
/// from `OPENAI_ID_PLACEHOLDER` so that substituting one doesn't
/// accidentally substitute the other in unrelated request bytes.
///
/// header  = base64url('{"alg":"none","typ":"JWT"}')
/// payload = base64url('{"exp":9999999999,
///                       "chatgpt_account_id":"00000000-0000-0000-0000-000000000000"}')
/// sig     = "msb-opencode-placeholder-av2"  (28 chars; non-token-
///           shaped to match the rest of the placeholder family; see
///           the warning on `OPENAI_ID_PLACEHOLDER`). Length is
///           deliberately ≡ 0 mod 4 so the segment is still a valid
///           unpadded base64url string — strict JWT parsers
///           (`jose` v6 in strict mode, `jsonwebtoken`) reject the
///           29-char `…-a-v2` form with "invalid base64" because
///           `len % 4 == 1` is structurally impossible. OpenCode's
///           current parser is lax and tolerates that, but the
///           defensive length is one char away.
///
/// **Kept short on purpose:** an earlier ~480-char payload (with
/// iss/aud/scp/email/sub claims) triggered upstream issue #8 — long
/// placeholders fail sandbox boot with `handshake read id_offset:
/// timed out before relay sent bytes`. Add fields here only if
/// OpenCode actually parses them and chokes on absence.
pub const OPENCODE_OPENAI_ACCESS_PLACEHOLDER: &str = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJleHAiOjk5OTk5OTk5OTksImNoYXRncHRfYWNjb3VudF9pZCI6IjAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMCJ9.msb-opencode-placeholder-av2";
pub const OPENCODE_OPENAI_REFRESH_PLACEHOLDER: &str = "msb-opencode-placeholder-r-v2";
/// Placeholder for the host's `gh auth token`. The in-guest `gh` /
/// git credential helper sees this string; the proxy substitutes the
/// real bearer on outbound traffic to GitHub.
pub const GH_TOKEN_PLACEHOLDER: &str = "msb-gh-placeholder-v2";
/// Placeholder for the host's GitHub Copilot token. The in-guest
/// Copilot CLI sees this string (exported as `COPILOT_GITHUB_TOKEN`
/// via `/etc/profile.d` and stored in `~/.copilot/config.json`); the
/// proxy substitutes the real GitHub OAuth token on outbound traffic
/// to the Copilot API. Kept distinct from `GH_TOKEN_PLACEHOLDER` so
/// substituting one can't accidentally rewrite the other in unrelated
/// request bytes — even though both happen to resolve to the same
/// host gh token, they're registered against different allow-host
/// sets (GitHub API vs Copilot API). Mirrors the original Bash
/// agent-vm's `placeholder-copilot-token-injected-by-proxy`.
pub const COPILOT_TOKEN_PLACEHOLDER: &str = "msb-copilot-placeholder-v2";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpencodeApiProvider {
    pub id: &'static str,
    pub placeholder: &'static str,
    pub host: &'static str,
}

impl OpencodeApiProvider {
    pub fn env_var(self) -> String {
        format!(
            "MSB_AGENT_VM_OPENCODE_{}_UNUSED",
            self.id.to_ascii_uppercase().replace('-', "_")
        )
    }
}

pub const OPENCODE_API_PROVIDERS: [OpencodeApiProvider; 7] = [
    OpencodeApiProvider {
        id: "zai",
        placeholder: "msb-zai-placeholder-k-v1",
        host: "api.z.ai",
    },
    OpencodeApiProvider {
        id: "zai-coding-plan",
        placeholder: "msb-zai-coding-placeholder-k-v1",
        host: "api.z.ai",
    },
    OpencodeApiProvider {
        id: "zhipuai",
        placeholder: "msb-zhipuai-placeholder-k-v1",
        host: "open.bigmodel.cn",
    },
    OpencodeApiProvider {
        id: "zhipuai-coding-plan",
        placeholder: "msb-zhipuai-coding-placeholder-k-v1",
        host: "open.bigmodel.cn",
    },
    OpencodeApiProvider {
        id: "kimi-for-coding",
        placeholder: "msb-kimi-coding-placeholder-k-v1",
        host: "api.kimi.com",
    },
    OpencodeApiProvider {
        id: "moonshotai",
        placeholder: "msb-moonshot-placeholder-k-v1",
        host: "api.moonshot.ai",
    },
    OpencodeApiProvider {
        id: "moonshotai-cn",
        placeholder: "msb-moonshot-cn-placeholder-k-v1",
        host: "api.moonshot.cn",
    },
];

#[cfg_attr(not(test), allow(dead_code))]
pub const ALL_PLACEHOLDERS: &[&str] = &[
    ANTHROPIC_ACCESS_PLACEHOLDER,
    ANTHROPIC_REFRESH_PLACEHOLDER,
    OPENAI_ACCESS_PLACEHOLDER,
    OPENAI_REFRESH_PLACEHOLDER,
    OPENAI_ID_PLACEHOLDER,
    OPENCODE_OPENAI_ACCESS_PLACEHOLDER,
    OPENCODE_OPENAI_REFRESH_PLACEHOLDER,
    GH_TOKEN_PLACEHOLDER,
    COPILOT_TOKEN_PLACEHOLDER,
    "msb-zai-placeholder-k-v1",
    "msb-zai-coding-placeholder-k-v1",
    "msb-zhipuai-placeholder-k-v1",
    "msb-zhipuai-coding-placeholder-k-v1",
    "msb-kimi-coding-placeholder-k-v1",
    "msb-moonshot-placeholder-k-v1",
    "msb-moonshot-cn-placeholder-k-v1",
];

// Hostnames the secret-substitution proxy + interceptor key off. Kept
// here so the launcher (`run.rs`), the hook (`intercept_hook`), and any
// docs stay in lockstep.

pub const ANTHROPIC_API_HOST: &str = "api.anthropic.com";
pub const ANTHROPIC_OAUTH_HOST: &str = "platform.claude.com";
/// Claude Code's MCP relay endpoint. Claude Code's HTTP client sends
/// the same Anthropic access token here, so the secret substitution
/// has to allow this destination too — otherwise the placeholder
/// trips the violation scan and the conn gets dropped, breaking MCP.
pub const ANTHROPIC_MCP_PROXY_HOST: &str = "mcp-proxy.anthropic.com";
pub const OPENAI_API_HOST: &str = "api.openai.com";
pub const OPENAI_CHATGPT_HOST: &str = "chatgpt.com";
pub const OPENAI_OAUTH_HOST: &str = "auth.openai.com";

pub const GITHUB_API_HOST: &str = "api.github.com";
pub const GITHUB_HOST: &str = "github.com";
pub const GITHUB_CODELOAD_HOST: &str = "codeload.github.com";
pub const GITHUB_RAW_HOST: &str = "raw.githubusercontent.com";
pub const GITHUB_OBJECTS_HOST: &str = "objects.githubusercontent.com";

/// GitHub Copilot API endpoints. The Copilot CLI sends
/// `Authorization: Bearer <token>` to these; the proxy substitutes
/// [`COPILOT_TOKEN_PLACEHOLDER`] for the real GitHub OAuth token.
/// Both are needed: `api.githubcopilot.com` for business/enterprise
/// seats and `api.individual.githubcopilot.com` for individual ones.
/// Mirrors the original Bash agent-vm's credential-proxy domains.
#[allow(dead_code)] // see the Phase 6 note above ANTHROPIC_API_HOST
pub const COPILOT_API_HOST: &str = "api.githubcopilot.com";
#[allow(dead_code)] // see the Phase 6 note above ANTHROPIC_API_HOST
pub const COPILOT_API_INDIVIDUAL_HOST: &str = "api.individual.githubcopilot.com";

#[allow(dead_code)] // see the Phase 6 note above ANTHROPIC_API_HOST
pub const ANTHROPIC_OAUTH_TOKEN_PATH: &str = "/v1/oauth/token";
#[allow(dead_code)] // see the Phase 6 note above ANTHROPIC_API_HOST
pub const OPENAI_OAUTH_TOKEN_PATH: &str = "/oauth/token";

/// Result of [`refresh`]. `*_token_file` paths only exist if the host
/// credential file was found and parsed successfully.
///
/// `opencode_openai_access_token_file` shares the same on-disk file as
/// `openai_token_file` (both substitute to the same real OpenAI access
/// token) — it's `Some` whenever the launcher should register a
/// proxy-substitution entry for OpenCode's synthetic-JWT placeholder.
#[derive(Debug, Default, Clone)]
pub struct CredsState {
    pub anthropic_token_file: Option<PathBuf>,
    pub openai_token_file: Option<PathBuf>,
    // OpenCode receives a distinct placeholder, but the proxy reads the
    // same host-only OpenAI bearer file as Codex. `refresh()` also writes
    // guest placeholder auth.json so the first OpenCode launch skips its
    // interactive wizard.
    pub opencode_openai_access_token_file: Option<PathBuf>,
    pub opencode_api_token_files: Vec<(OpencodeApiProvider, PathBuf)>,
    /// File holding the host's `gh auth token` (a GitHub user OAuth
    /// token). The proxy substitutes `GH_TOKEN_PLACEHOLDER` for this
    /// on outbound traffic to GitHub. Only `Some` when the user has
    /// `gh` logged in *and* `--no-git` was not passed.
    pub gh_token_file: Option<PathBuf>,
    /// File holding the host's GitHub Copilot token (a GitHub OAuth
    /// token with Copilot access). The proxy substitutes
    /// `COPILOT_TOKEN_PLACEHOLDER` for this on outbound traffic to the
    /// Copilot API hosts. Sourced from the original Bash agent-vm's
    /// device-flow cache (`~/.cache/claude-vm/copilot-token.json`) if
    /// present, else falls back to the captured `gh auth token` (a gh
    /// login with the Copilot scope works against the Copilot API).
    ///
    /// `Some` whenever a usable token was found and either the Copilot
    /// agent is being launched (`want_copilot`) or GitHub egress is
    /// already enabled for another agent (`use_github`). Crucially this
    /// is NOT gated on `--no-git` for a Copilot launch: the Copilot API
    /// is not repo-scoped, so `agent-vm copilot` must work even in a
    /// non-GitHub project.
    ///
    /// **Known limitation (no in-session refresh):** unlike the
    /// Anthropic/OpenAI access tokens, the Copilot token is not
    /// round-tripped through `intercept_hook`'s OAuth-refresh path. If
    /// the captured token expires mid-session, the proxy keeps
    /// substituting the stale value and Copilot requests start failing
    /// with 401 until the next `agent-vm` launch re-captures from the
    /// host. gh user tokens are typically long-lived, so the practical
    /// impact is low; re-launch to recover.
    pub copilot_token_file: Option<PathBuf>,
    pub snapshot: Option<HostCredsSnapshot>,
}

/// SHA-256 of each host credential file at launcher start. Compared
/// after the sandbox exits to flag unexpected mutations — the Phase 4
/// refresh hook may legitimately rewrite these files; anything else
/// touching them is a smell. See `verify_snapshot`.
#[derive(Debug, Default, Clone)]
pub struct HostCredsSnapshot {
    pub claude: Option<(PathBuf, String)>,
    pub codex: Option<(PathBuf, String)>,
    pub opencode: Option<(PathBuf, String)>,
}

/// Host-only directory holding the real access-token files the proxy
/// re-reads via `SecretSource::File`.
///
/// **Must live outside `state_dir`.** The launcher bind-mounts
/// `state_dir` into the guest at `/agent-vm-state` (a single mount, to
/// stay under libkrun's virtio-IRQ cap), so anything written *under*
/// `state_dir` is readable from inside the VM — a `cat
/// /agent-vm-state/tokens/anthropic` would hand the in-VM agent the
/// host's real token and defeat the entire point of Phase 3/4. The
/// microsandbox proxy reads these files on the *host* side, so they
/// never need to be mounted; we keep them in a sibling `<hash>.secrets/`
/// directory that is never bind-mounted anywhere.
pub(crate) fn host_secret_dir_path(state_dir: &Path) -> PathBuf {
    let name = state_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("default");
    let parent = state_dir.parent().unwrap_or(state_dir);
    parent.join(format!("{name}.secrets"))
}

pub(crate) fn ensure_host_secret_dir(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("host secret path has no parent"))?;
    std::fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub(crate) fn attempt_stamp_path_for(state_dir: &Path, provider: &str) -> PathBuf {
    host_secret_dir_path(state_dir).join(format!(".refresh.{provider}.stamp"))
}

/// Per-project location of the token file the proxy re-reads. Lives in
/// the host-only [`host_secret_dir`], never inside the guest mount.
pub fn anthropic_token_path(state_dir: &Path) -> PathBuf {
    host_secret_dir_path(state_dir).join("anthropic")
}

pub fn openai_token_path(state_dir: &Path) -> PathBuf {
    host_secret_dir_path(state_dir).join("openai")
}

pub fn gh_token_path(state_dir: &Path) -> PathBuf {
    host_secret_dir_path(state_dir).join("gh")
}

/// Per-provider advisory lock file serializing host-side OAuth refreshes
/// for one provider within a single project. The in-VM agent's
/// `_intercept-hook` acquires an exclusive `flock` on this path before
/// spawning a host `claude -p` / `codex exec` to drive a token rotation,
/// so two racing in-guest refreshes of the *same* provider don't each
/// launch their own host CLI.
///
/// Keyed per provider (`name` is e.g. [`REFRESH_LOCK_ANTHROPIC`]) so a
/// concurrent Anthropic and OpenAI in-guest refresh don't serialize
/// against each other — they rotate independent host credential files
/// and write distinct token files, so there is no shared state to guard
/// across providers. Lives in the host-only [`host_secret_dir`] (never
/// bind-mounted into the guest), alongside the token files the refresh
/// rewrites.
///
/// Note: the launcher's [`refresh`] uses a *different*, single shared
/// lock ([`ProjectRefreshLock`]) because it does read-modify-write on
/// per-project state files shared across all providers (`claude.json`,
/// `claude/settings.json`, `opencode-config/opencode.json`), so its
/// critical section genuinely spans every provider.
pub fn refresh_lock_path_for(state_dir: &Path, name: &str) -> PathBuf {
    host_secret_dir_path(state_dir).join(name)
}

/// Lock basename for the Anthropic in-guest refresh single-flight.
pub const REFRESH_LOCK_ANTHROPIC: &str = ".refresh.anthropic.lock";
/// Lock basename for the OpenAI in-guest refresh single-flight.
pub const REFRESH_LOCK_OPENAI: &str = ".refresh.openai.lock";

fn with_provider_lock<T>(
    state_dir: &Path,
    name: &str,
    work: impl FnOnce() -> Result<T>,
) -> Result<T> {
    use std::os::fd::AsRawFd as _;
    let path = refresh_lock_path_for(state_dir, name);
    ensure_host_secret_dir(&path)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)?;
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
            break;
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return Err(anyhow::Error::new(std::io::Error::last_os_error()));
        }
    }
    let result = work();
    unsafe {
        libc::flock(file.as_raw_fd(), libc::LOCK_UN);
    }
    result
}

#[cfg(test)]
mod refresh_lock_tests {
    use super::*;

    #[test]
    fn per_provider_lock_paths_are_distinct_and_in_secret_dir() {
        let state = Path::new("/home/u/.cache/agent-vm/abc123");
        let anthropic = refresh_lock_path_for(state, REFRESH_LOCK_ANTHROPIC);
        let openai = refresh_lock_path_for(state, REFRESH_LOCK_OPENAI);
        // Two providers must not share a lock file.
        assert_ne!(anthropic, openai);
        // Expected concrete paths in the sibling `<name>.secrets/` dir.
        assert_eq!(
            anthropic,
            Path::new("/home/u/.cache/agent-vm/abc123.secrets/.refresh.anthropic.lock")
        );
        assert_eq!(
            openai,
            Path::new("/home/u/.cache/agent-vm/abc123.secrets/.refresh.openai.lock")
        );
        // Both live in the host-only secrets dir, never under state_dir
        // (which is bind-mounted into the guest).
        assert_eq!(anthropic.parent(), anthropic_token_path(state).parent());
        assert_eq!(openai.parent(), anthropic_token_path(state).parent());
        assert!(!anthropic.starts_with(state));
        assert!(!openai.starts_with(state));
    }
}

/// Per-project location of the Copilot token file the proxy re-reads.
/// Lives in the host-only [`host_secret_dir`], never inside the guest
/// mount (it holds the real GitHub OAuth token).
pub fn copilot_token_path(state_dir: &Path) -> PathBuf {
    host_secret_dir_path(state_dir).join("copilot")
}

/// OpenCode reuses the same OpenAI access token file: both Codex and
/// OpenCode hit api.openai.com / chatgpt.com and the proxy substitutes
/// each provider's distinct placeholder string for the same real
/// bearer. Same file, two registered placeholders.
pub fn opencode_openai_token_path(state_dir: &Path) -> PathBuf {
    openai_token_path(state_dir)
}

/// Read host credentials, write the token file (atomically, 0600) and
/// the guest-side placeholder credentials.json. Returns the paths to
/// the written token files so the launcher can plumb them into
/// microsandbox's SecretSource::File config.
///
/// Serialized across concurrent launchers by a sibling host-only project
/// lock. Guest state is writable by the VM, so the lock must never live below
/// `state_dir`; provider locks additionally serialize launch capture with OAuth
/// installation for that provider.
pub fn refresh(
    state_dir: &Path,
    project_guest_path: &str,
    use_github: bool,
    want_copilot: bool,
    want_opencode: bool,
) -> Result<CredsState> {
    let _lock =
        ProjectRefreshLock::acquire(state_dir).context("acquiring per-project refresh lock")?;
    // The token files hold the host's *real* access tokens, so their
    // directory must never be bind-mounted into the guest. Create it
    // 0700 in the host-only sibling location (see `host_secret_dir`).
    let secret_dir = host_secret_dir_path(state_dir);
    std::fs::create_dir_all(&secret_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&secret_dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 700 {}", secret_dir.display()))?;
    }
    let guest = GuestStateDir::open(state_dir)?;
    for legacy in [Path::new("tokens/anthropic"), Path::new("tokens/openai")] {
        if let Err(error) = guest.remove_file(legacy) {
            tracing::warn!(path = %legacy.display(), error = %error, "leaving unsafe legacy guest entry");
        }
    }
    if let Err(error) = guest.remove_empty_dir(Path::new("tokens")) {
        tracing::warn!(error = %error, "leaving non-empty legacy guest token directory");
    }

    // First-run bypasses, run regardless of whether the user has host
    // credentials for the provider. Without these the in-VM agent
    // blocks on a terminal-style wizard at first launch.
    write_agent_config_defaults(&guest, project_guest_path, want_copilot)?;

    let anthropic_token_file = with_provider_lock(state_dir, REFRESH_LOCK_ANTHROPIC, || {
        refresh_anthropic(state_dir, &guest)
    })
    .unwrap_or_else(|e| {
        tracing::warn!(error = %e, "anthropic credential refresh failed; skipping");
        None
    });
    clear_stale_anthropic_placeholder(&guest, anthropic_token_file.is_some());
    let openai_token_file = with_provider_lock(state_dir, REFRESH_LOCK_OPENAI, || {
        refresh_openai(state_dir, &guest)
    })
    .unwrap_or_else(|e| {
        tracing::warn!(error = %e, "openai credential refresh failed; skipping");
        None
    });
    // OpenCode auths against OpenAI like Codex does. If the user has
    // host Codex/OpenAI credentials, we synthesize an OpenCode-shaped
    // `auth.json` whose `access` field is a placeholder JWT — the
    // proxy substitutes that placeholder for the same real OpenAI
    // access token on outbound traffic. So OpenCode shares the
    // `openai_token_file` with Codex.
    let opencode_oauth = if want_opencode && openai_token_file.is_some() {
        match opencode_oauth_entry() {
            Ok(entry) => entry,
            Err(error) => {
                // Static OpenCode credentials remain independently usable.
                tracing::warn!(error = %error, "OpenCode OAuth credential refresh failed; skipping");
                None
            }
        }
    } else {
        None
    };

    // Phase 6: capture the user's `gh auth token` (if any and not
    // suppressed via `--no-git`). The launcher passes
    // `--no-git`/use_github=false when the user opted out or when no
    // GitHub remote was found and no `--repo` overrides were given.
    let gh_token_file = if use_github {
        refresh_gh(state_dir).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "gh credential capture failed; skipping");
            None
        })
    } else {
        None
    };

    // D1: capture the host's GitHub Copilot token. Prefer the
    // device-flow cache the original Bash agent-vm wrote
    // (`~/.cache/claude-vm/copilot-token.json`); fall back to the
    // `gh auth token` we just captured (a gh login carries the
    // Copilot scope for users with a Copilot seat).
    //
    // Unlike the gh capture, this is NOT gated on `use_github`. The
    // Copilot API is reached with a GitHub OAuth token, but it is not
    // repo-scoped the way `api.github.com` push is — so the reason to
    // run `agent-vm copilot` (GitHub-backed AI) must not be switched off
    // just because the project has no detected GitHub remote or the user
    // passed `--no-git`. We capture the token whenever the Copilot agent
    // is the one being launched (`want_copilot`), or when GitHub egress
    // is already enabled for another agent (`use_github`) so an existing
    // gh login still flows through. When `want_copilot && !use_github`
    // there is no gh fallback token, so capture succeeds only via the
    // device-flow cache; the caller surfaces a clear error if nothing
    // was obtained rather than letting the guest send an unsubstituted
    // placeholder bearer.
    let copilot_token_file = if use_github || want_copilot {
        refresh_copilot(state_dir, gh_token_file.as_deref()).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "copilot credential capture failed; skipping");
            None
        })
    } else {
        None
    };

    // SHA-256 snapshot of host credential files for post-run mutation
    // detection. Phase 4's refresh hook *legitimately* rewrites these;
    // anything else doing so is a bug to investigate. See
    // `verify_snapshot`.
    let snapshot = Some(snapshot_host_creds());

    let opencode_refresh = refresh_opencode_with_paths(
        state_dir,
        &guest,
        want_opencode,
        host_opencode_auth_path().as_deref(),
        opencode_oauth,
    )
    .unwrap_or_else(|error| {
        tracing::warn!(error = %error, "OpenCode credential refresh failed; skipping");
        OpencodeRefresh::default()
    });
    let opencode_openai_access_token_file = opencode_refresh
        .openai_wired
        .then(|| opencode_openai_token_path(state_dir));
    let opencode_api_token_files = opencode_refresh.api_providers;
    write_opencode_model_default(
        &guest,
        opencode_openai_access_token_file.is_some() || opencode_api_token_files.is_empty(),
    )?;

    Ok(CredsState {
        anthropic_token_file,
        openai_token_file,
        opencode_openai_access_token_file,
        opencode_api_token_files,
        gh_token_file,
        copilot_token_file,
        snapshot,
    })
}

/// Author identity to bake into the guest's `~/.gitconfig` so commits
/// made *inside* the VM are attributed to the real user, not the
/// `agent-vm` placeholder. Resolved from the host by
/// [`discover_host_git_identity`].
#[derive(Debug, Clone)]
pub struct HostGitIdentity {
    pub name: String,
    pub email: String,
    /// gh login (e.g. `evgeny-boger`). Used to populate
    /// `gh-config/hosts.yml` `user:` field — kept distinct from `name`
    /// because gh's local `user:` is a *login*, not a display name.
    /// `None` when the identity came from host gitconfig fallback.
    pub gh_login: Option<String>,
}

/// Best-effort discovery of the user's git author identity *from the
/// host*. Tries `gh api user` first (most reliable — bypasses any
/// host-side `git config user.*` that itself was left behind by a
/// previous nested agent-vm). Falls back to the host's `git config
/// --global user.name/email` if gh isn't available.
///
/// Returns `None` if neither source yields a usable identity; in that
/// case the guest gitconfig is written without a `[user]` section,
/// which makes git refuse to commit rather than silently attribute to
/// `agent-vm`.
pub fn discover_host_git_identity() -> Option<HostGitIdentity> {
    // `gh api user` is an HTTPS round-trip to api.github.com that costs
    // ~0.3–1.3s and runs on the *pre-boot critical path* of every
    // launch — yet the answer (your name/email/login) almost never
    // changes. Cache the resolved identity with a short TTL so only the
    // first launch in the window pays the network cost; subsequent
    // launches resolve it instantly. The cache holds only display-level
    // strings (already validated by `is_config_safe`), never tokens.
    if let Some(id) = read_identity_cache() {
        return Some(id);
    }
    let id = gh_api_user_identity().or_else(host_git_config_identity);
    if let Some(ref id) = id {
        write_identity_cache(id);
    }
    id
}

/// TTL for the cached host git identity. Long enough to take the
/// `gh api user` round-trip off essentially every launch, short enough
/// that switching `gh` accounts / editing `git config user.*` is
/// reflected the same day.
const GIT_IDENTITY_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

fn identity_cache_path() -> Option<PathBuf> {
    Some(
        crate::host_paths::state_root()?
            .join("cache")
            .join("host-git-identity"),
    )
}

/// Read the cached identity if present and fresher than
/// [`GIT_IDENTITY_CACHE_TTL`]. Re-validates with [`is_config_safe`] so a
/// tampered cache file can't smuggle gitconfig sections into the guest.
fn read_identity_cache() -> Option<HostGitIdentity> {
    let p = identity_cache_path()?;
    let age = std::fs::metadata(&p)
        .ok()?
        .modified()
        .ok()?
        .elapsed()
        .ok()?;
    if age > GIT_IDENTITY_CACHE_TTL {
        return None;
    }
    let data = std::fs::read_to_string(&p).ok()?;
    let mut lines = data.lines();
    let name = lines.next()?.to_string();
    let email = lines.next()?.to_string();
    let gh = lines.next().unwrap_or("");
    if name.is_empty() || email.is_empty() || !is_config_safe(&name) || !is_config_safe(&email) {
        return None;
    }
    Some(HostGitIdentity {
        name,
        email,
        gh_login: (!gh.is_empty()).then(|| gh.to_string()),
    })
}

/// Persist the resolved identity (best-effort; cache misses are cheap).
fn write_identity_cache(id: &HostGitIdentity) {
    let Some(p) = identity_cache_path() else {
        return;
    };
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let body = format!(
        "{}\n{}\n{}\n",
        id.name,
        id.email,
        id.gh_login.as_deref().unwrap_or("")
    );
    let _ = atomic_write(&p, body.as_bytes(), 0o600);
}

/// Cap on how long we'll wait for `gh api user`. The call is an HTTPS
/// round-trip to api.github.com; on a flaky network gh's own retries
/// can stall launch for tens of seconds with no progress output, so
/// we bound it tightly and fall through to the local gitconfig.
const GH_API_USER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Run `gh api user` on the host and parse the response. Bounded by
/// [`GH_API_USER_TIMEOUT`] — if gh hangs (offline, captive portal,
/// hung credential helper) we abandon and let the caller fall back
/// to host gitconfig.
fn gh_api_user_identity() -> Option<HostGitIdentity> {
    let cmd = std::process::Command::new("gh");
    let out = spawn_with_timeout(cmd, &["api", "user"], GH_API_USER_TIMEOUT)?;
    if !out.status.success() {
        return None;
    }
    parse_gh_user_json(&out.stdout)
}

/// Spawn a subprocess with stdin closed and stdout/stderr piped, then
/// wait up to `timeout` for completion. On timeout, send SIGKILL by
/// pid and return None; the reader thread will observe child exit
/// and clean up its end.
///
/// Returns `None` if spawn fails, the process can't be waited on, or
/// the timeout elapses.
fn spawn_with_timeout(
    mut cmd: std::process::Command,
    args: &[&str],
    timeout: std::time::Duration,
) -> Option<std::process::Output> {
    use std::sync::mpsc;
    cmd.args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let child = cmd.spawn().ok()?;
    let pid = child.id();
    let (tx, rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        // `wait_with_output` consumes the child; if the outer thread
        // hit timeout and killed pid, this returns promptly.
        let _ = tx.send(child.wait_with_output());
    });
    match rx.recv_timeout(timeout) {
        Ok(Ok(out)) => Some(out),
        _ => {
            // Best-effort kill. PID reuse window is microseconds; the
            // child we just spawned is overwhelmingly the right one.
            #[cfg(unix)]
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGKILL);
            }
            None
        }
    }
}

/// Pure parser for the `gh api user` JSON response. Split out so it
/// can be unit-tested against representative GitHub payloads (public
/// email, hidden email, missing name, …) without spawning `gh`.
fn parse_gh_user_json(bytes: &[u8]) -> Option<HostGitIdentity> {
    let json: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let login_raw = json.get("login")?.as_str()?.trim();
    if !is_valid_gh_login(login_raw) {
        return None;
    }
    let login = login_raw.to_string();
    // GitHub user ids are u64 on the wire; `as_u64` handles the full
    // range. (Previously used `as_i64` with a comment claiming a 2^53
    // limit, conflating JSON-as-double with i64.) Used to synthesize
    // the noreply email when `email` is private.
    let id = json.get("id").and_then(|v| v.as_u64());
    let name_raw = json
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(login_raw);
    if !is_config_safe(name_raw) {
        return None;
    }
    // GitHub returns `email: null` when the user has email privacy on.
    // The `<id>+<login>@users.noreply.github.com` form is the
    // canonical no-leak address GitHub itself recommends for commits.
    let email_raw_owned: String = match json.get("email").and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => s.trim().to_string(),
        _ => format!("{}+{}@users.noreply.github.com", id?, login_raw),
    };
    if !is_config_safe(&email_raw_owned) {
        return None;
    }
    Some(HostGitIdentity {
        name: name_raw.to_string(),
        email: email_raw_owned,
        gh_login: Some(login),
    })
}

/// Fallback: read `user.name`/`user.email` from the host's
/// `~/.gitconfig`. Filters out the very placeholder this module
/// previously wrote (the nested-agent-vm case): without the filter,
/// a VM-inside-a-VM would inherit `agent-vm`/`agent-vm@msb.local`
/// transitively, defeating the fix.
fn host_git_config_identity() -> Option<HostGitIdentity> {
    let name = git_global_value("user.name")?;
    let email = git_global_value("user.email")?;
    if name == "agent-vm" && email == "agent-vm@msb.local" {
        return None;
    }
    // Same gitconfig-injection guard as the gh path — host gitconfig
    // is normally clean, but a poisoned `~/.gitconfig` (or a value
    // surreptitiously set by another tool) shouldn't be able to
    // smuggle in new sections via `\n[core]…`.
    if !is_config_safe(&name) || !is_config_safe(&email) {
        return None;
    }
    Some(HostGitIdentity {
        name,
        email,
        gh_login: None,
    })
}

fn git_global_value(key: &str) -> Option<String> {
    let cmd = std::process::Command::new("git");
    // Local read on the host gitconfig — a 1s timeout is generous
    // even on slow disks, and bounds the worst case if git itself
    // hangs (e.g. a `core.editor` hook misbehaving in a credential
    // helper triggered by config read).
    let out = spawn_with_timeout(
        cmd,
        &["config", "--global", "--get", key],
        std::time::Duration::from_secs(1),
    )?;
    if !out.status.success() {
        return None;
    }
    // Git config values are byte strings — a user.name in Latin-1 or
    // any non-UTF-8 encoding (legitimate on legacy dev boxes) would
    // make a strict `from_utf8` return None and drop the identity.
    // Lossy decode preserves the value; downstream `is_config_safe`
    // still rejects control chars.
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

/// True iff `s` is safe to interpolate into a gitconfig value or YAML
/// scalar without escaping. We reject any ASCII control character —
/// in particular `\n`/`\r`, which would terminate the current value
/// and allow injection of a new gitconfig section / hosts.yml field.
/// Tab is also rejected since gitconfig uses leading-tab as the
/// key/value indent and we'd rather refuse than confuse the parser.
///
/// This is intentionally conservative — printable unicode (including
/// `[`, `]`, `=`, quotes, non-ASCII) is allowed, because those are
/// harmless inside a `key = VALUE` line whose terminator is a
/// newline.
fn is_config_safe(s: &str) -> bool {
    !s.is_empty() && !s.bytes().any(|b| b < 0x20 || b == 0x7f)
}

/// GitHub logins are constrained to `[A-Za-z0-9-]`, max 39 chars, no
/// leading/trailing hyphen. We enforce that before interpolating the
/// login into `hosts.yml` (or the noreply email), so a future API
/// surprise can't smuggle in a colon, newline, or other YAML-breaking
/// character.
fn is_valid_gh_login(s: &str) -> bool {
    if s.is_empty() || s.len() > 39 || s.starts_with('-') || s.ends_with('-') {
        return false;
    }
    s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Capture `gh auth token` from the host into a 0600 file under
/// `<state>.secrets/gh`. Returns `None` if `gh` isn't installed or the
/// user isn't logged in. The proxy substitutes `GH_TOKEN_PLACEHOLDER`
/// for this file's content on outbound GitHub traffic.
fn refresh_gh(state_dir: &Path) -> Result<Option<PathBuf>> {
    let out = std::process::Command::new("gh")
        .args(["auth", "token"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();
    let out = match out {
        Ok(o) => o,
        // gh not on PATH — fine, just skip
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).context("running `gh auth token`"),
    };
    if !out.status.success() {
        // Most likely "not logged in" — non-fatal.
        return Ok(None);
    }
    let token = String::from_utf8(out.stdout).context("`gh auth token` output is not UTF-8")?;
    let token = token.trim();
    if token.is_empty() {
        return Ok(None);
    }
    let token_file = gh_token_path(state_dir);
    atomic_write(&token_file, token.as_bytes(), 0o600)?;
    Ok(Some(token_file))
}

/// Parse the original Bash agent-vm's Copilot token cache file. The
/// cache is JSON `{"access_token": "<gho_…>"}` (see
/// `copilot_token.py`); return the non-empty `access_token` string.
/// Split out so it can be unit-tested without touching `$HOME`.
fn extract_copilot_token(raw: &str) -> Option<String> {
    let json: Value = serde_json::from_str(raw).ok()?;
    let tok = json.get("access_token").and_then(|v| v.as_str())?.trim();
    if tok.is_empty() {
        None
    } else {
        Some(tok.to_string())
    }
}

/// Capture the host's GitHub Copilot token into a 0600 file under
/// `<state>.secrets/copilot`. The proxy substitutes
/// [`COPILOT_TOKEN_PLACEHOLDER`] for this file's content on outbound
/// traffic to the Copilot API.
///
/// Two sources, in priority order:
///  1. The device-flow cache the original Bash agent-vm wrote at
///     `~/.cache/claude-vm/copilot-token.json` (JSON
///     `{"access_token": …}`). Reusing it means an existing host
///     Copilot login is honoured without re-running the OAuth device
///     flow inside this Rust launcher.
///  2. The `gh auth token` we already captured this launch
///     (`gh_token_file`). A gh user OAuth token carries the Copilot
///     scope for accounts with a Copilot seat, so it works against
///     `api.githubcopilot.com`.
///
/// Returns `None` (non-fatal) when neither source yields a token —
/// Copilot is then simply unavailable in the guest, same as the
/// original's "could not obtain Copilot token" warning.
fn refresh_copilot(state_dir: &Path, gh_token_file: Option<&Path>) -> Result<Option<PathBuf>> {
    // 1. Device-flow cache from the original Bash agent-vm.
    if let Some(cache) = host_copilot_token_path() {
        match read_bounded_regular_file(&cache, MAX_HOST_CREDENTIAL_FILE_BYTES)
            .and_then(|raw| String::from_utf8(raw).context("Copilot cache is not UTF-8"))
        {
            Ok(raw) => {
                if let Some(token) = extract_copilot_token(&raw) {
                    let token_file = copilot_token_path(state_dir);
                    atomic_write(&token_file, token.as_bytes(), 0o600)?;
                    return Ok(Some(token_file));
                }
                // Present but unparseable/empty → fall through to gh.
            }
            Err(_error) if !cache.exists() => {}
            Err(error) => {
                return Err(error).with_context(|| format!("reading {}", cache.display()));
            }
        }
    }

    // 2. Fall back to the gh token captured this launch.
    if let Some(gh_file) = gh_token_file {
        let token = String::from_utf8(read_bounded_regular_file(
            gh_file,
            MAX_HOST_CREDENTIAL_FILE_BYTES,
        )?)
        .with_context(|| format!("reading {}", gh_file.display()))?;
        let token = token.trim();
        if !token.is_empty() {
            let token_file = copilot_token_path(state_dir);
            atomic_write(&token_file, token.as_bytes(), 0o600)?;
            return Ok(Some(token_file));
        }
    }

    Ok(None)
}

/// SHA-256 the three host credential files. Files that don't exist or
/// can't be read are recorded as `None` — only files that successfully
/// hash become anchors for [`verify_snapshot`].
pub fn snapshot_host_creds() -> HostCredsSnapshot {
    HostCredsSnapshot {
        claude: host_claude_creds_path().and_then(|p| hash_file(&p).map(|h| (p, h))),
        codex: host_codex_auth_path().and_then(|p| hash_file(&p).map(|h| (p, h))),
        opencode: host_opencode_auth_path().and_then(|p| hash_file(&p).map(|h| (p, h))),
    }
}

/// Diff the saved [`HostCredsSnapshot`] against the current file
/// state. Emits a one-line summary to stderr listing the host cred
/// files that mutated during the session — the Phase 4 OAuth refresh
/// hook may legitimately rewrite them, but any other mutation is
/// worth surfacing. Non-fatal.
pub fn verify_snapshot(before: &HostCredsSnapshot) {
    let mut changed: Vec<&str> = Vec::new();
    for (label, entry) in [
        ("claude", &before.claude),
        ("codex", &before.codex),
        ("opencode", &before.opencode),
    ] {
        if let Some((path, before_hash)) = entry {
            let now = hash_file(path);
            match now.as_deref() {
                Some(after) if after == before_hash => {}
                Some(_) => changed.push(label),
                None => changed.push(label), // disappeared
            }
        }
    }
    if !changed.is_empty() {
        // A `Drop` impl (`SnapshotGuard` in run.rs) has nowhere to propagate
        // to and must never panic — which `eprintln` does on a stderr write
        // error, converting a clean launch failure back into an abrupt
        // exit-101 panic instead (issue #70). This safety-net notice is
        // best-effort by construction.
        use std::io::Write as _;
        let _ = writeln!(
            std::io::stderr(),
            "==> host credential file(s) changed during sandbox: {} (expected only on Phase 4 OAuth refresh; investigate if you didn't trigger one)",
            changed.join(", "),
        );
    }
}

fn hash_file(path: &Path) -> Option<String> {
    let bytes = read_bounded_regular_file(path, MAX_HOST_CREDENTIAL_FILE_BYTES).ok()?;
    let mut h = Sha256::new();
    h.update(&bytes);
    let digest = h.finalize();
    Some(digest.iter().map(|b| format!("{b:02x}")).collect())
}

/// Drop the per-agent bypass files (Claude's onboarding flags + Codex's
/// trust/approval settings) into the per-project state dir. Idempotent
/// across launches; merges instead of overwrites so user tweaks
/// survive.
fn write_agent_config_defaults(
    guest: &GuestStateDir,
    project_guest_path: &str,
    want_copilot: bool,
) -> Result<()> {
    let mut settings = read_guest_json_object(guest, Path::new("claude/settings.json"));
    settings
        .entry("theme")
        .or_insert(Value::String("dark".into()));
    settings.insert("hasCompletedOnboarding".into(), Value::Bool(true));
    settings.insert(
        "skipDangerousModePermissionPrompt".into(),
        Value::Bool(true),
    );
    settings
        .entry("effortLevel")
        .or_insert(Value::String("xhigh".into()));
    guest.atomic_write(
        Path::new("claude/settings.json"),
        &serde_json::to_vec(&Value::Object(settings))?,
        0o644,
    )?;

    let mut root = read_guest_json_object(guest, Path::new("claude.json"));
    root.insert("hasCompletedOnboarding".into(), Value::Bool(true));
    root.insert("bypassPermissionsModeAccepted".into(), Value::Bool(true));
    let projects = root
        .entry("projects")
        .or_insert_with(|| serde_json::json!({}));
    let projects = projects
        .as_object_mut()
        .context("guest claude projects is not an object")?;
    let project = projects
        .entry(project_guest_path.to_owned())
        .or_insert_with(|| serde_json::json!({}));
    let project = project
        .as_object_mut()
        .context("guest claude project is not an object")?;
    project.insert("hasTrustDialogAccepted".into(), Value::Bool(true));
    project.insert("hasCompletedProjectOnboarding".into(), Value::Bool(true));
    project
        .entry("history")
        .or_insert_with(|| serde_json::json!([]));
    guest.atomic_write(
        Path::new("claude.json"),
        &serde_json::to_vec(&Value::Object(root))?,
        0o644,
    )?;

    let codex = b"sandbox_mode = \"danger-full-access\"\napproval_policy = \"never\"\n";
    let _ = guest.create(Path::new("codex/config.toml"), codex, 0o644)?;
    let mut opencode = read_guest_json_object(guest, Path::new("opencode-config/opencode.json"));
    opencode
        .entry("$schema")
        .or_insert(Value::String("https://opencode.ai/config.json".into()));
    opencode
        .entry("model")
        .or_insert(Value::String("openai/gpt-5.5".into()));
    opencode.entry("autoupdate").or_insert(Value::Bool(false));
    guest.atomic_write(
        Path::new("opencode-config/opencode.json"),
        &serde_json::to_vec(&Value::Object(opencode))?,
        0o644,
    )?;
    if want_copilot {
        let mut copilot = read_guest_json_object(guest, Path::new("copilot/config.json"));
        copilot.insert("trusted_folders".into(), serde_json::json!(["/"]));
        copilot.insert(
            "github_token".into(),
            Value::String(COPILOT_TOKEN_PLACEHOLDER.into()),
        );
        guest.atomic_write(
            Path::new("copilot/config.json"),
            &serde_json::to_vec(&Value::Object(copilot))?,
            0o600,
        )?;
    }
    let _ = guest.create(Path::new("bash_history"), b"", 0o600)?;
    Ok(())
}

fn write_opencode_model_default(guest: &GuestStateDir, pin_openai_model: bool) -> Result<()> {
    let relative = Path::new("opencode-config/opencode.json");
    let mut config = read_guest_json_object(guest, relative);
    if pin_openai_model {
        config
            .entry("model")
            .or_insert(Value::String("openai/gpt-5.5".into()));
    } else if config.get("model").and_then(Value::as_str) == Some("openai/gpt-5.5") {
        config.remove("model");
    }
    guest.atomic_write(
        relative,
        &serde_json::to_vec(&Value::Object(config))?,
        0o644,
    )
}

/// Drop a guest Claude placeholder left over from an earlier, successful
/// launch when *this* launch captured nothing.
///
/// The guest state dir persists across launches, but the proxy's
/// substitution entry does not: it is rebuilt per launch from
/// [`CredsState`]. So a stale placeholder plus a failed capture means the
/// guest sends `Bearer msb-anthropic-placeholder-a-v2` verbatim — the
/// in-VM agent looks signed in until every request 401s, and the obvious
/// next move (`/login` in the guest) is itself refused by the OAuth hook.
/// Removing it makes the guest *visibly* signed out and lets
/// `run::launch` fail with an actionable message instead.
///
/// Best-effort: a removal failure is logged, not fatal — the launch is
/// about to bail for a Claude launch anyway, and a codex/opencode launch
/// should not be blocked by a stray Claude file.
fn clear_stale_anthropic_placeholder(guest: &GuestStateDir, captured: bool) {
    if captured {
        return;
    }
    if let Err(error) = guest.remove_file(Path::new("claude/.credentials.json")) {
        tracing::warn!(error = %error, "leaving stale Anthropic guest placeholder");
    }
}

fn refresh_anthropic(state_dir: &Path, guest: &GuestStateDir) -> Result<Option<PathBuf>> {
    let Some(host_path) = host_claude_creds_path() else {
        return Ok(None);
    };
    let raw = String::from_utf8(read_bounded_regular_file(
        &host_path,
        MAX_HOST_CREDENTIAL_FILE_BYTES,
    )?)
    .with_context(|| format!("reading {}", host_path.display()))?;
    let json: Value =
        serde_json::from_str(&raw).with_context(|| format!("parsing {}", host_path.display()))?;

    let oauth = json
        .get("claudeAiOauth")
        .context("host .credentials.json missing claudeAiOauth")?;
    let access_token = oauth
        .get("accessToken")
        .and_then(|v| v.as_str())
        .context("host claudeAiOauth missing accessToken")?;

    let token_file = anthropic_token_path(state_dir);
    atomic_write(&token_file, access_token.as_bytes(), 0o600)?;

    let placeholder = serde_json::json!({
        "claudeAiOauth": {
            "accessToken": ANTHROPIC_ACCESS_PLACEHOLDER,
            "refreshToken": ANTHROPIC_REFRESH_PLACEHOLDER,
            "expiresAt": oauth.get("expiresAt"),
            "scopes": oauth.get("scopes"),
            "subscriptionType": oauth.get("subscriptionType"),
            "rateLimitTier": oauth.get("rateLimitTier"),
        }
    });
    if let Err(error) = guest.atomic_write(
        Path::new("claude/.credentials.json"),
        &serde_json::to_vec(&placeholder)?,
        0o600,
    ) {
        let _ = std::fs::remove_file(&token_file);
        return Err(error).context("writing Anthropic guest placeholder");
    }

    Ok(Some(token_file))
}

/// Write `<state>/opencode/auth.json` shaped for OpenCode's OAuth
/// flow, but with placeholder strings everywhere. The `openai.access`
/// field carries our synthetic JWT placeholder; the proxy substitutes
/// it with the real OpenAI access token (from the file shared with
/// Codex) on outbound traffic. `accountId` is derived from the host
/// Codex JWT when available, so OpenCode picks the right account
/// without us hard-coding anything user-specific.
///
/// Requires that `refresh_openai` has already run (so a host codex
/// auth file existed and was parseable). Returns `None` if not.
fn opencode_oauth_entry() -> Result<Option<Value>> {
    let Some(host_path) = host_codex_auth_path() else {
        return Ok(None);
    };
    let raw = String::from_utf8(read_bounded_regular_file(
        &host_path,
        MAX_HOST_CREDENTIAL_FILE_BYTES,
    )?)
    .with_context(|| format!("reading {}", host_path.display()))?;
    let json: Value =
        serde_json::from_str(&raw).with_context(|| format!("parsing {}", host_path.display()))?;

    // account_id: from tokens.account_id directly when present,
    // otherwise pull from the id_token JWT's `chatgpt_account_id`.
    let account_id = json
        .pointer("/tokens/account_id")
        .and_then(|v| v.as_str())
        .map(String::from)
        .or_else(|| decode_id_token_account(&json))
        .unwrap_or_else(|| "00000000-0000-0000-0000-000000000000".into());

    // Far-future expires_in (ms); OpenCode treats this as a hint of
    // when to refresh. The proxy substitution is always live anyway,
    // so a long expiry just suppresses opencode's own refresh
    // attempts (which would fail against our synthetic JWT).
    let expires_ms: u64 = 9_999_999_999_000;

    Ok(Some(serde_json::json!({
        "type": "oauth",
        "refresh": OPENCODE_OPENAI_REFRESH_PLACEHOLDER,
        "access": OPENCODE_OPENAI_ACCESS_PLACEHOLDER,
        "expires": expires_ms,
        "accountId": account_id,
    })))
}

#[derive(Default)]
struct OpencodeRefresh {
    openai_wired: bool,
    api_providers: Vec<(OpencodeApiProvider, PathBuf)>,
}

fn opencode_api_token_path(state_dir: &Path, provider: OpencodeApiProvider) -> PathBuf {
    host_secret_dir_path(state_dir).join(format!("opencode-{}", provider.id))
}

fn read_guest_json_object(
    guest: &GuestStateDir,
    relative: &Path,
) -> serde_json::Map<String, Value> {
    match guest.read(relative) {
        Ok(Some(raw)) => match serde_json::from_slice::<Value>(&raw)
            .ok()
            .and_then(|value| value.as_object().cloned())
        {
            Some(object) => object,
            None => {
                tracing::warn!(path = %relative.display(), "guest JSON is not an object; replacing managed entries");
                serde_json::Map::new()
            }
        },
        Ok(None) => serde_json::Map::new(),
        Err(error) => {
            tracing::warn!(path = %relative.display(), error = %error, "guest JSON is unreadable; replacing managed entries");
            serde_json::Map::new()
        }
    }
}

fn refresh_opencode_with_paths(
    state_dir: &Path,
    guest: &GuestStateDir,
    want_opencode: bool,
    host_opencode_path: Option<&Path>,
    openai_entry: Option<Value>,
) -> Result<OpencodeRefresh> {
    let host_auth = if want_opencode {
        host_opencode_path
            .and_then(|path| read_bounded_regular_file(path, MAX_HOST_CREDENTIAL_FILE_BYTES).ok())
            .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok())
    } else {
        None
    };
    let mut installed = Vec::new();
    if let Some(host_auth) = host_auth.and_then(|value| value.as_object().cloned()) {
        for provider in OPENCODE_API_PROVIDERS {
            let key = host_auth
                .get(provider.id)
                .and_then(Value::as_object)
                .filter(|entry| {
                    entry.len() == 2 && entry.get("type").and_then(Value::as_str) == Some("api")
                })
                .and_then(|entry| entry.get("key").and_then(Value::as_str))
                .filter(|key| !key.is_empty());
            if let Some(key) = key {
                let path = opencode_api_token_path(state_dir, provider);
                if ensure_host_secret_dir(&path).is_ok()
                    && atomic_write(&path, key.as_bytes(), 0o600).is_ok()
                {
                    installed.push((provider, path));
                }
            }
        }
    }
    let relative = Path::new("opencode/auth.json");
    let mut auth = read_guest_json_object(guest, relative);
    // Only remove our own synthetic OpenAI entry. A user-managed `openai`
    // provider must survive exactly like a user-managed static provider.
    if auth.get("openai").is_some_and(is_agent_vm_openai_entry) {
        auth.remove("openai");
    }
    let openai_wired = openai_entry.is_some();
    if let Some(entry) = openai_entry {
        auth.insert("openai".into(), entry);
    }
    for provider in OPENCODE_API_PROVIDERS {
        let guest_managed = auth
            .get(provider.id)
            .and_then(Value::as_object)
            .and_then(|entry| entry.get("key"))
            .and_then(Value::as_str)
            .is_some_and(|key| {
                !OPENCODE_API_PROVIDERS
                    .iter()
                    .any(|managed| managed.placeholder == key)
            });
        if guest_managed {
            // A real value in guest state is deliberately not ours to replace.
            // It cannot be paired with a host file, so remove the candidate.
            let path = opencode_api_token_path(state_dir, provider);
            if let Err(error) = std::fs::remove_file(&path)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                tracing::warn!(
                    provider = provider.id,
                    "failed to remove unmanaged OpenCode host token"
                );
            }
            installed.retain(|(installed_provider, _)| installed_provider.id != provider.id);
            continue;
        }
        if auth
            .get(provider.id)
            .and_then(Value::as_object)
            .and_then(|entry| entry.get("key"))
            .and_then(Value::as_str)
            .is_some_and(|key| {
                OPENCODE_API_PROVIDERS
                    .iter()
                    .any(|managed| managed.placeholder == key)
            })
        {
            auth.remove(provider.id);
        }
        let path = opencode_api_token_path(state_dir, provider);
        if installed
            .iter()
            .any(|(installed_provider, _)| installed_provider.id == provider.id)
        {
            auth.insert(
                provider.id.to_owned(),
                serde_json::json!({"type":"api", "key": provider.placeholder}),
            );
        } else if let Err(error) = std::fs::remove_file(&path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(
                provider = provider.id,
                "failed to remove stale OpenCode host token"
            );
        }
    }
    if let Err(error) =
        guest.atomic_write(relative, &serde_json::to_vec(&Value::Object(auth))?, 0o600)
    {
        for (_, path) in &installed {
            let _ = std::fs::remove_file(path);
        }
        return Err(error).context("writing placeholder OpenCode auth");
    }
    Ok(OpencodeRefresh {
        openai_wired,
        api_providers: installed,
    })
}

fn is_agent_vm_openai_entry(entry: &Value) -> bool {
    entry
        .get("access")
        .and_then(Value::as_str)
        .is_some_and(|access| access == OPENCODE_OPENAI_ACCESS_PLACEHOLDER)
}

/// Decode an OpenAI id_token JWT (alg=RS256, but we don't verify) and
/// pull the `chatgpt_account_id` out of its payload's
/// `https://api.openai.com/auth` claim. Used as a fallback when the
/// codex auth.json doesn't carry `tokens.account_id` directly.
fn decode_id_token_account(json: &Value) -> Option<String> {
    let id_token = json.pointer("/tokens/id_token").and_then(|v| v.as_str())?;
    let payload_b64 = id_token.split('.').nth(1)?;
    use base64::Engine as _;
    // JWT spec says base64url *without* padding. Use URL_SAFE_NO_PAD
    // first (the conformant variant); fall back to STANDARD (some
    // libraries emit JWTs with '+'/'/' instead of '-'/'_') — review
    // finding #14.
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64.as_bytes())
        .or_else(|_| {
            let padded = format!(
                "{}{}",
                payload_b64.replace('-', "+").replace('_', "/"),
                "=".repeat((4 - payload_b64.len() % 4) % 4)
            );
            base64::engine::general_purpose::STANDARD.decode(padded.as_bytes())
        })
        .ok()?;
    let payload: Value = serde_json::from_slice(&payload_bytes).ok()?;
    payload
        .pointer("/https:~1~1api.openai.com~1auth/chatgpt_account_id")
        .and_then(|v| v.as_str())
        .map(String::from)
}

fn refresh_openai(state_dir: &Path, guest: &GuestStateDir) -> Result<Option<PathBuf>> {
    let Some(host_path) = host_codex_auth_path() else {
        return Ok(None);
    };
    let raw = String::from_utf8(read_bounded_regular_file(
        &host_path,
        MAX_HOST_CREDENTIAL_FILE_BYTES,
    )?)
    .with_context(|| format!("reading {}", host_path.display()))?;
    let mut json: Value =
        serde_json::from_str(&raw).with_context(|| format!("parsing {}", host_path.display()))?;

    // Either ChatGPT OAuth (`tokens.access_token`) or an API key
    // (`OPENAI_API_KEY`). Both end up as Bearer in outgoing requests.
    let access_token = json
        .pointer("/tokens/access_token")
        .and_then(|v| v.as_str())
        .or_else(|| json.get("OPENAI_API_KEY").and_then(|v| v.as_str()))
        .context("host codex auth missing tokens.access_token or OPENAI_API_KEY")?
        .to_string();
    let token_file = openai_token_path(state_dir);
    atomic_write(&token_file, access_token.as_bytes(), 0o600)?;

    // Replace the real value in-place with the placeholder, preserving
    // every other field (account_id, last_refresh, etc.) so the in-VM
    // codex sees a valid-looking auth.json shape.
    if let Some(tokens) = json.get_mut("tokens").and_then(|v| v.as_object_mut()) {
        if tokens.contains_key("access_token") {
            tokens.insert(
                "access_token".into(),
                Value::String(OPENAI_ACCESS_PLACEHOLDER.into()),
            );
        }
        if tokens.contains_key("refresh_token") {
            tokens.insert(
                "refresh_token".into(),
                Value::String(OPENAI_REFRESH_PLACEHOLDER.into()),
            );
        }
        // The ChatGPT auth flow also stores an `id_token` JWT — it
        // carries the user's email, org list, plan type, etc. and is
        // itself a credential at OIDC-protected endpoints. Leaving it
        // verbatim would leak that into the guest's auth.json; the
        // refresh hook already uses OPENAI_ID_PLACEHOLDER for the
        // synthesized response, so do the same on initial snapshot.
        if tokens.contains_key("id_token") {
            tokens.insert(
                "id_token".into(),
                Value::String(OPENAI_ID_PLACEHOLDER.into()),
            );
        }
    }
    if json.get("OPENAI_API_KEY").is_some() {
        json["OPENAI_API_KEY"] = Value::String(OPENAI_ACCESS_PLACEHOLDER.into());
    }

    if let Err(error) = guest.atomic_write(
        Path::new("codex/auth.json"),
        &serde_json::to_vec(&json)?,
        0o600,
    ) {
        let _ = std::fs::remove_file(&token_file);
        return Err(error).context("writing Codex guest placeholder");
    }

    Ok(Some(token_file))
}

/// Synchronize the launcher-owned Chrome MCP entry without changing user MCPs.
pub fn sync_chrome_mcp(state_dir: &Path, enabled: bool) -> Result<()> {
    let _lock = ProjectRefreshLock::acquire(state_dir)
        .context("acquiring per-project refresh lock for Chrome MCP")?;
    let guest = GuestStateDir::open(state_dir)?;
    let relative = Path::new("claude.json");
    let mut state = Value::Object(read_guest_json_object(&guest, relative));
    let root = state
        .as_object_mut()
        .context("guest claude root is not an object")?;
    sync_chrome_mcp_value(root, enabled);
    guest.atomic_write(relative, &serde_json::to_vec(&state)?, 0o644)
}

fn chrome_mcp_entry() -> Value {
    serde_json::json!({
        "command": "/usr/local/bin/agent-vm-chrome-mcp",
        "args": ["npx", "-y", "chrome-devtools-mcp@1.0.1", "--headless=true", "--isolated=true"],
        "env": {"CHROME_DEVTOOLS_MCP_NO_USAGE_STATISTICS": "1"},
    })
}

fn sync_chrome_mcp_value(root: &mut serde_json::Map<String, Value>, enabled: bool) {
    if enabled {
        let entry = root
            .entry("mcpServers")
            .or_insert_with(|| serde_json::json!({}));
        if !entry.is_object() {
            tracing::warn!("replacing invalid mcpServers value while enabling Chrome MCP");
            *entry = serde_json::json!({});
        }
        entry
            .as_object_mut()
            .expect("object set above")
            .insert("chrome-devtools".into(), chrome_mcp_entry());
        return;
    }
    let Some(entry) = root.get_mut("mcpServers") else {
        return;
    };
    let Some(servers) = entry.as_object_mut() else {
        tracing::warn!("leaving non-object mcpServers untouched while disabling Chrome MCP");
        return;
    };
    servers.remove("chrome-devtools");
    if servers.is_empty() {
        root.remove("mcpServers");
    }
}

/// Phase 6/9: write the guest's gitconfig and (if `has_gh_token`)
/// gh/git credential plumbing. Always called so the
/// `safe.directory = *` line is in place — without it, git inside the
/// guest fails with "fatal: detected dubious ownership in repository"
/// because the host-owned bind-mounted project is read by the guest's
/// root user (different UID).
///
/// Files land under `state_dir` so they're available inside the guest
/// via the existing bind mount + symlinks (see run.rs patch builder).
///
/// - `<state>/gitconfig` → symlinked to `/root/.gitconfig` in the
///   guest. Always contains `safe.directory = *`. When `identity` is
///   `Some`, also contains a `[user]` section so in-VM commits carry
///   the host's real author. When the host has gh auth, also contains
///   a `credential.helper` that echoes `username=x-access-token` /
///   `password=<placeholder>` so `git push` to GitHub goes out as
///   `Authorization: Basic base64(x-access-token:placeholder)`, which
///   the proxy substitutes on the wire.
/// - `<state>/gh-config/hosts.yml` → symlinked to `/root/.config/gh`
///   in the guest. Only written when `has_gh_token`; the placeholder
///   is what gh CLI sends and the proxy substitutes outbound to
///   api.github.com.
///
/// Omitting `[user]` when `identity` is `None` is deliberate: git
/// will refuse to commit with "Please tell me who you are", which is
/// strictly better than silently committing as `agent-vm`.
pub fn write_guest_gh_config(
    state_dir: &Path,
    has_gh_token: bool,
    identity: Option<&HostGitIdentity>,
) -> Result<()> {
    let _lock = ProjectRefreshLock::acquire(state_dir)?;
    let guest = GuestStateDir::open(state_dir)?;
    let mut gitconfig = String::from("[safe]\n\tdirectory = *\n");
    if let Some(id) = identity {
        gitconfig.push_str(&format!(
            "[user]\n\tname = {}\n\temail = {}\n",
            id.name, id.email
        ));
    }
    if has_gh_token {
        gitconfig.push_str(&format!(
            "[credential \"https://github.com\"]\n\thelper = \"!f() {{ test \\\"$1\\\" = get && echo username=x-access-token && echo password={}; }}; f\"\n[credential \"https://gist.github.com\"]\n\thelper = \"!f() {{ test \\\"$1\\\" = get && echo username=x-access-token && echo password={}; }}; f\"\n[url \"https://github.com/\"]\n\tinsteadOf = git@github.com:\n", GH_TOKEN_PLACEHOLDER, GH_TOKEN_PLACEHOLDER));
    }
    guest.atomic_write(Path::new("gitconfig"), gitconfig.as_bytes(), 0o600)?;
    if has_gh_token {
        let gh_user = identity
            .and_then(|id| id.gh_login.as_deref())
            .unwrap_or("agent-vm");
        let hosts = format!(
            "github.com:\n  user: {gh_user}\n  oauth_token: {GH_TOKEN_PLACEHOLDER}\n  git_protocol: https\n"
        );
        guest.atomic_write(Path::new("gh-config/hosts.yml"), hosts.as_bytes(), 0o600)?;
    }
    Ok(())
}

/// Write the GitHub Copilot CLI's `~/.copilot/config.json`. Two
/// purposes, both mirroring the original Bash agent-vm's
/// `_copilot_vm_setup_home`:
///
///  - `trusted_folders = ["/"]` so the CLI never prompts "do you
///    trust this folder?" — the microVM is the sandbox, so trusting
///    every path inside it is correct.
///  - the token field carries [`COPILOT_TOKEN_PLACEHOLDER`], which
///    the proxy substitutes for the real token on outbound traffic.
///    The CLI also honours the `COPILOT_GITHUB_TOKEN` env var (set by
///    the launcher); writing it here too covers config-first reads.
///
/// Merge-on-existing so a user's own settings survive across launches;
/// only the fields we manage are force-set.
/// Host-only project lock used for guest-state read-modify-write transactions.
/// It is a sibling of the guest mount so a guest cannot delete or replace the
/// synchronization point.
struct ProjectRefreshLock {
    file: std::fs::File,
}

impl ProjectRefreshLock {
    fn acquire(state_dir: &Path) -> Result<Self> {
        use std::os::unix::io::AsRawFd;
        let secret_dir = host_secret_dir_path(state_dir);
        std::fs::create_dir_all(&secret_dir)
            .with_context(|| format!("creating {}", secret_dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&secret_dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let lock_path = secret_dir.join(".refresh.project.lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .with_context(|| format!("opening {}", lock_path.display()))?;
        // LOCK_EX blocks until exclusive ownership is acquired. Loop
        // on EINTR (signal during the wait). No timeout — a peer that
        // truly hangs inside the locked section is a bug we want
        // surfaced as a stuck launcher, not silently bypassed.
        loop {
            // SAFETY: file owns the fd for the duration of the call;
            // LOCK_EX is a valid `flock(2)` operation; errno is read
            // immediately on failure.
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            if rc == 0 {
                break;
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(anyhow::Error::from(err)
                .context(format!("flock(LOCK_EX) on {}", lock_path.display())));
        }
        Ok(Self { file })
    }
}

impl Drop for ProjectRefreshLock {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        // SAFETY: file still owns the fd; LOCK_UN can't fail in a way
        // that warrants action here (close on Drop releases the lock
        // either way).
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    /// Security invariant: the real-token files must never live under
    /// `state_dir`, because the launcher bind-mounts `state_dir` into the
    /// guest at `/agent-vm-state`. A token file under that path would be
    /// readable by the in-VM agent (`cat /agent-vm-state/tokens/...`),
    /// defeating the whole "real tokens never enter the VM" design.
    #[test]
    fn all_placeholders_are_unique_and_non_overlapping() {
        for (index, placeholder) in ALL_PLACEHOLDERS.iter().enumerate() {
            assert!(!placeholder.is_empty());
            for other in ALL_PLACEHOLDERS.iter().skip(index + 1) {
                assert_ne!(placeholder, other);
                assert!(!placeholder.contains(other));
                assert!(!other.contains(placeholder));
            }
        }
        assert_eq!(OPENCODE_API_PROVIDERS.len(), 7);
    }

    #[test]
    fn opencode_static_capture_keeps_canaries_host_only_and_reconciles() {
        let state = tempfile::tempdir().unwrap();
        let host = tempfile::NamedTempFile::new().unwrap();
        let mut entries = serde_json::Map::new();
        for provider in OPENCODE_API_PROVIDERS {
            entries.insert(
                provider.id.into(),
                serde_json::json!({"type":"api", "key":format!("CANARY_{}", provider.id)}),
            );
        }
        entries.insert(
            "openrouter".into(),
            serde_json::json!({"type":"api", "key":"guest-managed"}),
        );
        std::fs::write(
            host.path(),
            serde_json::to_vec(&Value::Object(entries)).unwrap(),
        )
        .unwrap();
        let guest = GuestStateDir::open(state.path()).unwrap();
        guest
            .atomic_write(
                Path::new("opencode/auth.json"),
                br#"{"openrouter":{"type":"api","key":"guest-managed"}}"#,
                0o600,
            )
            .unwrap();
        let installed =
            refresh_opencode_with_paths(state.path(), &guest, true, Some(host.path()), None)
                .unwrap()
                .api_providers;
        assert_eq!(installed.len(), OPENCODE_API_PROVIDERS.len());
        let guest_auth: Value = serde_json::from_slice(
            &guest
                .read(Path::new("opencode/auth.json"))
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(guest_auth["openrouter"]["key"], "guest-managed");
        let guest_text = guest_auth.to_string();
        for provider in OPENCODE_API_PROVIDERS {
            let path = opencode_api_token_path(state.path(), provider);
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                format!("CANARY_{}", provider.id)
            );
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(guest_auth[provider.id]["key"], provider.placeholder);
            assert!(!guest_text.contains("CANARY_"));
        }
        let absent =
            refresh_opencode_with_paths(state.path(), &guest, false, Some(host.path()), None)
                .unwrap()
                .api_providers;
        assert!(absent.is_empty());
        for provider in OPENCODE_API_PROVIDERS {
            assert!(!opencode_api_token_path(state.path(), provider).exists());
        }
    }

    #[test]
    fn opencode_merge_preserves_known_guest_provider_and_unknown_entries() {
        let state = tempfile::tempdir().unwrap();
        let host = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            host.path(),
            br#"{"zai":{"type":"api","key":"HOST_CANARY"}}"#,
        )
        .unwrap();
        let guest = GuestStateDir::open(state.path()).unwrap();
        guest
            .atomic_write(
                Path::new("opencode/auth.json"),
                br#"{"zai":{"type":"api","key":"guest-managed"},"unknown":{"key":"keep"}}"#,
                0o600,
            )
            .unwrap();
        let result = refresh_opencode_with_paths(
            state.path(),
            &guest,
            true,
            Some(host.path()),
            Some(serde_json::json!({
                "type": "oauth",
                "access": OPENCODE_OPENAI_ACCESS_PLACEHOLDER,
            })),
        )
        .unwrap();
        assert!(result.api_providers.is_empty());
        assert!(result.openai_wired);
        assert!(!opencode_api_token_path(state.path(), OPENCODE_API_PROVIDERS[0]).exists());
        let auth: Value = serde_json::from_slice(
            &guest
                .read(Path::new("opencode/auth.json"))
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(auth["zai"]["key"], "guest-managed");
        assert_eq!(auth["unknown"]["key"], "keep");
        assert_eq!(auth["openai"]["access"], OPENCODE_OPENAI_ACCESS_PLACEHOLDER);
        assert!(!auth.to_string().contains("HOST_CANARY"));
    }

    #[test]
    fn token_files_live_outside_the_guest_mount() {
        let state_dir = Path::new("/home/u/.local/state/agent-vm/abc123");
        for token in [
            anthropic_token_path(state_dir),
            openai_token_path(state_dir),
            gh_token_path(state_dir),
            opencode_openai_token_path(state_dir),
        ] {
            assert!(
                !token.starts_with(state_dir),
                "{} must not be under the bind-mounted state dir {}",
                token.display(),
                state_dir.display(),
            );
            // ...but still derivable from it (same parent) so the launcher
            // and the refresh hook agree on the path.
            assert_eq!(token.parent().unwrap().parent(), state_dir.parent());
        }
    }

    /// The per-project refresh lock must serialize: a second
    /// `LOCK_EX` against the same lock file (via a *different* fd,
    /// because flock is per-fd on Linux) must fail with `EWOULDBLOCK`
    /// while the first guard is alive. This is the property that
    /// prevents concurrent launchers from interleaving RMW on
    /// `claude.json` / `settings.json` (see review finding #2).
    #[test]
    fn project_refresh_lock_blocks_second_acquire() {
        use std::os::unix::io::AsRawFd;
        let dir = tempfile::tempdir().expect("tempdir");
        let guard = ProjectRefreshLock::acquire(dir.path()).expect("first acquire");
        // Open a second fd on the lock file from a different File
        // (same process, but flock(2) on Linux is per-open-file-
        // description, so this is the right way to model a second
        // launcher). LOCK_NB returns EWOULDBLOCK if the lock can't be
        // taken immediately — that's what we want to observe.
        let other = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(host_secret_dir_path(dir.path()).join(".refresh.project.lock"))
            .expect("open second handle");
        let rc = unsafe { libc::flock(other.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        let err = std::io::Error::last_os_error();
        assert_eq!(rc, -1, "second flock should fail while guard is alive");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::EWOULDBLOCK),
            "expected EWOULDBLOCK, got {err:?}"
        );
        // Releasing the first guard makes the second acquire succeed.
        drop(guard);
        let rc = unsafe { libc::flock(other.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(rc, 0, "second flock should succeed after guard drop");
        let _ = unsafe { libc::flock(other.as_raw_fd(), libc::LOCK_UN) };
    }

    /// Trailing-slash state_dir was flagged in code review as a
    /// possible edge case where the secrets dir might land inside the
    /// mount. Verify it doesn't.
    #[test]
    fn host_secret_dir_safe_for_trailing_slash_state_dir() {
        // Path::file_name() strips trailing slashes — verify the
        // sibling-secrets pattern still works.
        for sd in [
            "/home/u/.local/state/agent-vm/abc123",
            "/home/u/.local/state/agent-vm/abc123/",
            "/tmp/agent-vm-state",
        ] {
            let sdp = Path::new(sd);
            let secret = host_secret_dir_path(sdp);
            assert!(
                !secret.starts_with(sdp.canonicalize().unwrap_or(sdp.to_path_buf())),
                "{} must not be inside {}",
                secret.display(),
                sdp.display(),
            );
        }
    }

    /// D1 regression guard for the per-agent Copilot gating (review
    /// finding #5). With neither GitHub egress (`use_github=false`) nor
    /// the Copilot agent selected (`want_copilot=false`), `refresh` must
    /// not capture a Copilot token — both capture conditions are off, so
    /// `copilot_token_file` is `None` by construction, independent of any
    /// host/`$HOME`/gh state (this combination skips both `refresh_gh`
    /// and `refresh_copilot`). Also re-asserts the security-critical
    /// property that the copilot token *path* lives *outside* the
    /// guest-bind-mounted state dir, same as the other token files.
    #[test]
    fn copilot_token_not_captured_without_use_github_or_want_copilot() {
        let dir = tempfile::tempdir().unwrap();
        let sd = dir.path();
        let creds = super::refresh(sd, "/workspace/p", false, false, false).unwrap();
        assert!(
            creds.copilot_token_file.is_none(),
            "copilot token captured despite use_github=false and want_copilot=false"
        );
        // Independent of capture: the path the proxy would re-read must
        // never be under the guest mount (threat-model invariant).
        let cp = copilot_token_path(sd);
        assert!(
            !cp.starts_with(sd),
            "copilot token path {} must not be inside the bind-mounted state dir {}",
            cp.display(),
            sd.display(),
        );
        assert_eq!(cp.parent().unwrap().parent(), sd.parent());
    }

    /// **Placeholder distinctness**. If one placeholder were a
    /// substring of another, the secret-substitution proxy would
    /// swap the wrong token on outbound bytes — silently corrupting
    /// requests. Verify no placeholder is a substring of any other.
    #[test]
    fn placeholders_are_pairwise_distinct() {
        let all: &[(&str, &str)] = &[
            ("ANTHROPIC_ACCESS", ANTHROPIC_ACCESS_PLACEHOLDER),
            ("ANTHROPIC_REFRESH", ANTHROPIC_REFRESH_PLACEHOLDER),
            ("OPENAI_ACCESS", OPENAI_ACCESS_PLACEHOLDER),
            ("OPENAI_REFRESH", OPENAI_REFRESH_PLACEHOLDER),
            ("OPENAI_ID", OPENAI_ID_PLACEHOLDER),
            ("OPENCODE_ACCESS", OPENCODE_OPENAI_ACCESS_PLACEHOLDER),
            ("OPENCODE_REFRESH", OPENCODE_OPENAI_REFRESH_PLACEHOLDER),
            ("GH_TOKEN", GH_TOKEN_PLACEHOLDER),
        ];
        for (a_name, a) in all {
            for (b_name, b) in all {
                if a_name == b_name {
                    continue;
                }
                assert!(
                    !a.contains(b) && !b.contains(a),
                    "placeholder {a_name:?} ({a:?}) and {b_name:?} ({b:?}) overlap as substrings — substitution would swap the wrong token"
                );
            }
        }
    }

    // ── hash_file ─────────────────────────────────────────────────

    #[test]
    fn hash_file_returns_none_for_missing_path() {
        let missing = Path::new("/this/path/very/definitely/does/not/exist/anywhere");
        assert_eq!(hash_file(missing), None);
    }

    #[test]
    fn hash_file_is_deterministic_for_known_input() {
        use std::io::Write as _;
        let tmpdir = std::env::temp_dir().join(format!(
            "agent-vm-hash-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&tmpdir).unwrap();
        let path = tmpdir.join("known");
        let mut f = std::fs::File::create(&path).unwrap();
        // Capital T is the famous one (`d7a8fbb...`).
        f.write_all(b"The quick brown fox jumps over the lazy dog")
            .unwrap();
        drop(f);
        let h = hash_file(&path).unwrap();
        assert_eq!(
            h,
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        );
        std::fs::remove_dir_all(&tmpdir).ok();
    }

    // ── decode_id_token_account ───────────────────────────────────

    fn make_jwt(
        payload_json: &str,
        alphabet: base64::engine::general_purpose::GeneralPurpose,
    ) -> String {
        use base64::Engine as _;
        // Header doesn't matter; payload is what we test.
        let header = alphabet.encode(b"{\"alg\":\"none\",\"typ\":\"JWT\"}");
        let payload = alphabet.encode(payload_json.as_bytes());
        // Trim padding when present — JWTs are unpadded.
        let h = header.trim_end_matches('=');
        let p = payload.trim_end_matches('=');
        format!("{h}.{p}.sig")
    }

    #[test]
    fn decode_id_token_account_urlsafe_jwt() {
        let payload = r#"{"https://api.openai.com/auth":{"chatgpt_account_id":"abc-123"}}"#;
        let jwt = make_jwt(payload, base64::engine::general_purpose::URL_SAFE_NO_PAD);
        let json = serde_json::json!({"tokens": {"id_token": jwt}});
        assert_eq!(decode_id_token_account(&json).as_deref(), Some("abc-123"),);
    }

    #[test]
    fn decode_id_token_account_standard_alphabet_falls_back() {
        // Some libraries emit JWTs with standard-alphabet base64
        // (`+`/`/`) instead of URL-safe (`-`/`_`). The decoder must
        // try STANDARD as a fallback. Construct a payload whose
        // base64 encoding includes a `+` or `/` — most easily by
        // embedding bytes that base64 to those chars.
        let payload = r#"{"https://api.openai.com/auth":{"chatgpt_account_id":"acct?+/"}}"#;
        let jwt = make_jwt(payload, base64::engine::general_purpose::STANDARD);
        let json = serde_json::json!({"tokens": {"id_token": jwt}});
        assert_eq!(decode_id_token_account(&json).as_deref(), Some("acct?+/"),);
    }

    #[test]
    fn decode_id_token_account_returns_none_for_missing_fields() {
        // No tokens.id_token at all.
        assert_eq!(decode_id_token_account(&serde_json::json!({})), None);
        // tokens present but id_token missing.
        assert_eq!(
            decode_id_token_account(&serde_json::json!({"tokens": {}})),
            None
        );
        // id_token present but malformed (no `.`).
        assert_eq!(
            decode_id_token_account(&serde_json::json!({"tokens": {"id_token": "garbage"}})),
            None
        );
        // id_token decodes but the OpenAI-auth claim is missing.
        let payload = r#"{"something": "else"}"#;
        let jwt = make_jwt(payload, base64::engine::general_purpose::URL_SAFE_NO_PAD);
        let json = serde_json::json!({"tokens": {"id_token": jwt}});
        assert_eq!(decode_id_token_account(&json), None);
    }

    // ── write_opencode_model_default pin/retire/preserve semantics ──
    //
    // Exercises the real production entry point (through
    // `GuestStateDir`), not a parallel plain-filesystem implementation:
    // the previous version of these tests called a `#[cfg(test)]`-only
    // `write_default_opencode_config` helper that duplicated (and had
    // drifted from) `write_opencode_model_default`'s actual pin/retire
    // rule, so passing tests proved nothing about production behavior.

    fn opencode_model_value(guest: &GuestStateDir) -> Value {
        serde_json::from_slice(
            &guest
                .read(Path::new("opencode-config/opencode.json"))
                .unwrap()
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn a_failed_capture_removes_the_stale_guest_claude_placeholder() {
        let state = tempfile::tempdir().unwrap();
        let guest = GuestStateDir::open(state.path()).unwrap();
        let relative = Path::new("claude/.credentials.json");
        guest
            .atomic_write(relative, br#"{"claudeAiOauth":{}}"#, 0o600)
            .unwrap();

        clear_stale_anthropic_placeholder(&guest, false);

        assert!(
            !state.path().join(relative).exists(),
            "a placeholder nothing will substitute must not be left behind"
        );
        // Idempotent: a launch with no placeholder to begin with is fine.
        clear_stale_anthropic_placeholder(&guest, false);
    }

    #[test]
    fn a_successful_capture_leaves_the_guest_placeholder_in_place() {
        let state = tempfile::tempdir().unwrap();
        let guest = GuestStateDir::open(state.path()).unwrap();
        let relative = Path::new("claude/.credentials.json");
        guest
            .atomic_write(
                relative,
                br#"{"claudeAiOauth":{"accessToken":"ph"}}"#,
                0o600,
            )
            .unwrap();

        clear_stale_anthropic_placeholder(&guest, true);

        assert!(state.path().join(relative).exists());
    }

    #[test]
    fn opencode_model_default_pins_when_requested_on_first_write() {
        let state = tempfile::tempdir().unwrap();
        let guest = GuestStateDir::open(state.path()).unwrap();
        write_opencode_model_default(&guest, true).unwrap();
        assert_eq!(opencode_model_value(&guest)["model"], "openai/gpt-5.5");
    }

    #[test]
    fn opencode_model_default_preserves_user_override_while_pinning() {
        let state = tempfile::tempdir().unwrap();
        let guest = GuestStateDir::open(state.path()).unwrap();
        guest
            .atomic_write(
                Path::new("opencode-config/opencode.json"),
                br#"{"model":"openai/gpt-5-turbo","extra":"user-data"}"#,
                0o644,
            )
            .unwrap();
        write_opencode_model_default(&guest, true).unwrap();
        let config = opencode_model_value(&guest);
        assert_eq!(
            config["model"], "openai/gpt-5-turbo",
            "user override survived"
        );
        assert_eq!(config["extra"], "user-data", "user-set field preserved");
    }

    #[test]
    fn opencode_model_default_retires_only_the_exact_stale_pin() {
        let state = tempfile::tempdir().unwrap();
        let guest = GuestStateDir::open(state.path()).unwrap();
        guest
            .atomic_write(
                Path::new("opencode-config/opencode.json"),
                br#"{"model":"openai/gpt-5.5"}"#,
                0o644,
            )
            .unwrap();
        // Static GLM/Kimi keys are the only OpenCode credential wired
        // this launch: pin_openai_model=false must retire the stale
        // agent-vm default so OpenCode's own default takes over.
        write_opencode_model_default(&guest, false).unwrap();
        assert!(opencode_model_value(&guest).get("model").is_none());
    }

    #[test]
    fn opencode_model_default_preserves_non_stale_value_when_not_pinning() {
        let state = tempfile::tempdir().unwrap();
        let guest = GuestStateDir::open(state.path()).unwrap();
        guest
            .atomic_write(
                Path::new("opencode-config/opencode.json"),
                br#"{"model":"anthropic/claude"}"#,
                0o644,
            )
            .unwrap();
        write_opencode_model_default(&guest, false).unwrap();
        assert_eq!(opencode_model_value(&guest)["model"], "anthropic/claude");
    }

    // ── OpenCode reconciliation edge cases (code review follow-up) ──

    #[test]
    fn opencode_malformed_host_json_does_not_disable_independent_openai_leg() {
        let state = tempfile::tempdir().unwrap();
        let host = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(host.path(), b"not valid json {{{").unwrap();
        let guest = GuestStateDir::open(state.path()).unwrap();
        let result = refresh_opencode_with_paths(
            state.path(),
            &guest,
            true,
            Some(host.path()),
            Some(serde_json::json!({
                "type": "oauth",
                "access": OPENCODE_OPENAI_ACCESS_PLACEHOLDER,
            })),
        )
        .unwrap();
        assert!(
            result.api_providers.is_empty(),
            "malformed host JSON must not yield any static provider"
        );
        assert!(
            result.openai_wired,
            "the independently-supplied OpenAI OAuth leg must survive malformed static host JSON"
        );
        let auth: Value = serde_json::from_slice(
            &guest
                .read(Path::new("opencode/auth.json"))
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(auth["openai"]["access"], OPENCODE_OPENAI_ACCESS_PLACEHOLDER);
    }

    #[test]
    fn opencode_partial_host_write_failure_yields_consistent_successful_subset() {
        let state = tempfile::tempdir().unwrap();
        let host = tempfile::NamedTempFile::new().unwrap();
        let mut entries = serde_json::Map::new();
        for provider in OPENCODE_API_PROVIDERS {
            entries.insert(
                provider.id.into(),
                serde_json::json!({"type":"api", "key":format!("CANARY_{}", provider.id)}),
            );
        }
        std::fs::write(
            host.path(),
            serde_json::to_vec(&Value::Object(entries)).unwrap(),
        )
        .unwrap();
        // Pre-occupy one provider's host token path with a directory so
        // the final `renameat` onto it fails (EISDIR/ENOTDIR) while every
        // other provider's independent write still succeeds.
        let failing = OPENCODE_API_PROVIDERS[0];
        std::fs::create_dir_all(opencode_api_token_path(state.path(), failing)).unwrap();
        let guest = GuestStateDir::open(state.path()).unwrap();
        let result =
            refresh_opencode_with_paths(state.path(), &guest, true, Some(host.path()), None)
                .unwrap();
        assert_eq!(result.api_providers.len(), OPENCODE_API_PROVIDERS.len() - 1);
        assert!(!result.api_providers.iter().any(|(p, _)| p.id == failing.id));
        let auth: Value = serde_json::from_slice(
            &guest
                .read(Path::new("opencode/auth.json"))
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert!(
            auth.get(failing.id).is_none(),
            "a provider whose host write failed must not get a guest placeholder"
        );
        for provider in OPENCODE_API_PROVIDERS
            .iter()
            .filter(|provider| provider.id != failing.id)
        {
            assert_eq!(auth[provider.id]["key"], provider.placeholder);
        }
    }

    #[test]
    fn opencode_final_guest_merge_failure_registers_no_providers_and_cleans_up_host_files() {
        let state = tempfile::tempdir().unwrap();
        let host = tempfile::NamedTempFile::new().unwrap();
        let mut entries = serde_json::Map::new();
        for provider in OPENCODE_API_PROVIDERS {
            entries.insert(
                provider.id.into(),
                serde_json::json!({"type":"api", "key":format!("CANARY_{}", provider.id)}),
            );
        }
        std::fs::write(
            host.path(),
            serde_json::to_vec(&Value::Object(entries)).unwrap(),
        )
        .unwrap();
        let guest = GuestStateDir::open(state.path()).unwrap();
        // Occupy the "opencode" parent as a regular file so the final
        // merge write to "opencode/auth.json" fails closed.
        guest
            .create(Path::new("opencode"), b"not-a-directory", 0o600)
            .unwrap();
        let result =
            refresh_opencode_with_paths(state.path(), &guest, true, Some(host.path()), None);
        assert!(result.is_err());
        for provider in OPENCODE_API_PROVIDERS {
            assert!(
                !opencode_api_token_path(state.path(), provider).exists(),
                "host token for {} must be removed best-effort after guest merge failure",
                provider.id
            );
        }
    }

    // ── sync_chrome_mcp ──────────────────────────────────────────

    #[test]
    fn sync_chrome_mcp_adds_exact_owned_entry_and_preserves_user_state() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("claude.json"),
            r#"{"other":true,"mcpServers":{"user":{"command":"mine"}}}"#,
        )
        .unwrap();
        sync_chrome_mcp(dir.path(), true).unwrap();
        let state: Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("claude.json")).unwrap())
                .unwrap();
        let chrome = &state["mcpServers"]["chrome-devtools"];
        assert_eq!(chrome["command"], "/usr/local/bin/agent-vm-chrome-mcp");
        assert_eq!(
            chrome["args"],
            serde_json::json!([
                "npx",
                "-y",
                "chrome-devtools-mcp@1.0.1",
                "--headless=true",
                "--isolated=true"
            ])
        );
        assert_eq!(
            chrome["env"]["CHROME_DEVTOOLS_MCP_NO_USAGE_STATISTICS"],
            "1"
        );
        assert_eq!(state["mcpServers"]["user"]["command"], "mine");
        assert_eq!(state["other"], true);
    }

    #[test]
    fn sync_chrome_mcp_removes_only_owned_entry() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("claude.json"),
            r#"{"other":true,"mcpServers":{"chrome-devtools":{"command":"stale"},"user":{"command":"mine"}}}"#,
        )
        .unwrap();
        sync_chrome_mcp(dir.path(), false).unwrap();
        let state: Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("claude.json")).unwrap())
                .unwrap();
        assert!(state["mcpServers"].get("chrome-devtools").is_none());
        assert_eq!(state["mcpServers"]["user"]["command"], "mine");
        assert_eq!(state["other"], true);
    }

    #[test]
    fn disabling_preserves_non_object_user_value() {
        for value in ["null", "\"text\"", "[]", "1", "true"] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(
                dir.path().join("claude.json"),
                format!(r#"{{"mcpServers":{value}}}"#),
            )
            .unwrap();
            sync_chrome_mcp(dir.path(), false).unwrap();
            let state: Value =
                serde_json::from_slice(&std::fs::read(dir.path().join("claude.json")).unwrap())
                    .unwrap();
            assert_eq!(
                state["mcpServers"],
                serde_json::from_str::<Value>(value).unwrap()
            );
        }
    }

    #[test]
    fn enabling_replaces_invalid_mcp_servers_value() {
        for value in ["null", "\"text\"", "[]", "1", "true"] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(
                dir.path().join("claude.json"),
                format!(r#"{{"mcpServers":{value}}}"#),
            )
            .unwrap();
            sync_chrome_mcp(dir.path(), true).unwrap();
            let state: Value =
                serde_json::from_slice(&std::fs::read(dir.path().join("claude.json")).unwrap())
                    .unwrap();
            assert!(state["mcpServers"]["chrome-devtools"].is_object());
        }
    }

    // ── write_guest_gh_config identity wiring ─────────────────────

    #[test]
    fn write_guest_gh_config_omits_user_section_when_identity_none() {
        let dir = tempfile::tempdir().unwrap();
        write_guest_gh_config(dir.path(), false, None).unwrap();
        let cfg = std::fs::read_to_string(dir.path().join("gitconfig")).unwrap();
        assert!(cfg.contains("[safe]"));
        assert!(
            !cfg.contains("[user]"),
            "no identity means no [user] section, so git refuses to commit \
             rather than mis-attribute (got: {cfg:?})"
        );
        // Make sure the legacy placeholder is *not* written anywhere.
        assert!(!cfg.contains("agent-vm@msb.local"));
    }

    #[test]
    fn write_guest_gh_config_writes_user_section_from_identity() {
        let dir = tempfile::tempdir().unwrap();
        let id = HostGitIdentity {
            name: "Evgeny Boger".into(),
            email: "boger@example.com".into(),
            gh_login: Some("evgeny-boger".into()),
        };
        write_guest_gh_config(dir.path(), true, Some(&id)).unwrap();
        let cfg = std::fs::read_to_string(dir.path().join("gitconfig")).unwrap();
        assert!(cfg.contains("name = Evgeny Boger"), "got: {cfg:?}");
        assert!(cfg.contains("email = boger@example.com"), "got: {cfg:?}");
        // Credential helper still wired up when has_gh_token=true.
        assert!(cfg.contains("credential \"https://github.com\""));

        let hosts = std::fs::read_to_string(dir.path().join("gh-config/hosts.yml")).unwrap();
        assert!(
            hosts.contains("user: evgeny-boger"),
            "hosts.yml user: should be the gh login, not the display name (got: {hosts:?})"
        );
    }

    // ── parse_gh_user_json ────────────────────────────────────────

    #[test]
    fn parse_gh_user_json_public_email_path() {
        // The common case: user has a public email — use it verbatim.
        let payload = br#"{"login":"evgeny-boger","id":1755320,"name":"Evgeny Boger","email":"boger@wirenboard.com"}"#;
        let id = parse_gh_user_json(payload).expect("parse");
        assert_eq!(id.name, "Evgeny Boger");
        assert_eq!(id.email, "boger@wirenboard.com");
        assert_eq!(id.gh_login.as_deref(), Some("evgeny-boger"));
    }

    #[test]
    fn parse_gh_user_json_hidden_email_falls_back_to_noreply() {
        // Email privacy on → `email: null`. We synthesize the noreply
        // form GitHub itself recommends so commits still attribute
        // correctly without leaking the user's real address.
        let payload = br#"{"login":"octocat","id":583231,"name":"The Octocat","email":null}"#;
        let id = parse_gh_user_json(payload).expect("parse");
        assert_eq!(id.name, "The Octocat");
        assert_eq!(id.email, "583231+octocat@users.noreply.github.com");
        assert_eq!(id.gh_login.as_deref(), Some("octocat"));
    }

    #[test]
    fn parse_gh_user_json_missing_name_falls_back_to_login() {
        // `name` is optional on GitHub profiles; commits should still
        // get a sensible attribution rather than `null`.
        let payload = br#"{"login":"ghost","id":10137,"name":null,"email":null}"#;
        let id = parse_gh_user_json(payload).expect("parse");
        assert_eq!(id.name, "ghost");
        assert_eq!(id.email, "10137+ghost@users.noreply.github.com");
    }

    #[test]
    fn parse_gh_user_json_rejects_empty_login() {
        // Defensive: an empty login would produce a structurally
        // valid but useless identity. Treat as no-identity.
        let payload = br#"{"login":"","id":1,"name":"X","email":"x@example.com"}"#;
        assert!(parse_gh_user_json(payload).is_none());
    }

    #[test]
    fn parse_gh_user_json_rejects_garbage() {
        assert!(parse_gh_user_json(b"not json").is_none());
        assert!(parse_gh_user_json(b"{}").is_none());
        assert!(parse_gh_user_json(b"").is_none());
    }

    #[test]
    fn parse_gh_user_json_hidden_email_without_id_yields_none() {
        // If both email and id are missing/null, we have no usable
        // address — return None so the caller can fall back further.
        let payload = br#"{"login":"weird","name":"Weird","email":null}"#;
        assert!(parse_gh_user_json(payload).is_none());
    }

    #[test]
    fn write_guest_gh_config_hosts_yml_uses_placeholder_user_without_login() {
        // Host gitconfig fallback path: identity has no gh_login.
        // hosts.yml is only written when has_gh_token=true, so this
        // pairing is rare in practice but still legitimate.
        let dir = tempfile::tempdir().unwrap();
        let id = HostGitIdentity {
            name: "Some User".into(),
            email: "u@example.com".into(),
            gh_login: None,
        };
        write_guest_gh_config(dir.path(), true, Some(&id)).unwrap();
        let hosts = std::fs::read_to_string(dir.path().join("gh-config/hosts.yml")).unwrap();
        assert!(hosts.contains("user: agent-vm"), "got: {hosts:?}");
    }

    // ── injection guards ──────────────────────────────────────────

    #[test]
    fn parse_gh_user_json_rejects_newline_in_name() {
        // The exact attack we're guarding against: a display name
        // containing `\n[core]\n\tpager = …` would inject a [core]
        // section into the guest gitconfig. is_config_safe rejects
        // any ASCII control byte, so parse_gh_user_json returns None
        // and the caller falls through to the host gitconfig.
        let payload = br#"{"login":"x","id":1,"name":"Foo\n[core]\n\tpager = bad","email":"a@b"}"#;
        assert!(parse_gh_user_json(payload).is_none());
    }

    #[test]
    fn parse_gh_user_json_rejects_newline_in_email() {
        let payload = br#"{"login":"x","id":1,"name":"OK","email":"a@b\n[user]\nname=evil"}"#;
        assert!(parse_gh_user_json(payload).is_none());
    }

    #[test]
    fn parse_gh_user_json_rejects_invalid_login() {
        // Colon, slash, leading dash, length > 39 — all rejected so
        // hosts.yml interpolation can't smuggle in extra YAML fields
        // (`user: foo\n  oauth_token: stolen`).
        for bad in [
            r#"{"login":"foo:bar","id":1,"name":"X","email":"x@y"}"#,
            r#"{"login":"-leading","id":1,"name":"X","email":"x@y"}"#,
            r#"{"login":"trailing-","id":1,"name":"X","email":"x@y"}"#,
            r#"{"login":"a/b","id":1,"name":"X","email":"x@y"}"#,
            // 40 chars (max is 39)
            r#"{"login":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","id":1,"name":"X","email":"x@y"}"#,
        ] {
            assert!(
                parse_gh_user_json(bad.as_bytes()).is_none(),
                "expected None for: {bad}"
            );
        }
    }

    #[test]
    fn parse_gh_user_json_accepts_unicode_name() {
        // Non-ASCII printable chars are fine — only control bytes
        // are rejected.
        let payload = "{\"login\":\"u\",\"id\":1,\"name\":\"Évgeny Бoger 你好\",\"email\":\"a@b\"}";
        let id = parse_gh_user_json(payload.as_bytes()).expect("parse");
        assert_eq!(id.name, "Évgeny Бoger 你好");
    }

    #[test]
    fn parse_gh_user_json_handles_large_user_id() {
        // u64 user ids above i64::MAX would have been silently
        // dropped by the old `as_i64` path; the noreply fallback
        // must still work.
        let payload = br#"{"login":"big","id":18446744073709551610,"name":null,"email":null}"#;
        let id = parse_gh_user_json(payload).expect("parse");
        assert_eq!(
            id.email,
            "18446744073709551610+big@users.noreply.github.com"
        );
    }

    #[test]
    fn is_config_safe_classifications() {
        // Accept printable ASCII, common symbols, unicode.
        assert!(is_config_safe("Evgeny Boger"));
        assert!(is_config_safe("a@b.com"));
        assert!(is_config_safe("Foo [Bar] = baz"));
        assert!(is_config_safe("Évgeny 你好"));
        // Reject ASCII controls.
        assert!(!is_config_safe(""));
        assert!(!is_config_safe("a\nb"));
        assert!(!is_config_safe("a\rb"));
        assert!(!is_config_safe("a\tb"));
        assert!(!is_config_safe("a\0b"));
        assert!(!is_config_safe("a\x7fb")); // DEL
    }

    #[test]
    fn is_valid_gh_login_classifications() {
        assert!(is_valid_gh_login("evgeny-boger"));
        assert!(is_valid_gh_login("octocat"));
        assert!(is_valid_gh_login("a"));
        assert!(is_valid_gh_login(&"a".repeat(39)));
        // Length cap.
        assert!(!is_valid_gh_login(&"a".repeat(40)));
        // Disallowed chars / positions.
        assert!(!is_valid_gh_login(""));
        assert!(!is_valid_gh_login("-leading"));
        assert!(!is_valid_gh_login("trailing-"));
        assert!(!is_valid_gh_login("has space"));
        assert!(!is_valid_gh_login("has:colon"));
        assert!(!is_valid_gh_login("has/slash"));
        assert!(!is_valid_gh_login("has\nnewline"));
    }
}
