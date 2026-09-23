//! Credential providers: the compiled-in credential subsystems a tool can
//! depend on.
//!
//! A **credential provider** is the unit of "what a tool needs in order to be
//! signed in".
//! The set of variants is a *code* fact (each needs Rust to capture / rotate /
//! inject); which tool uses which is configuration (#80/#82). Do not confuse
//! this with [`crate::secrets::OpencodeApiProvider`] — that is a *dynamic*,
//! user-populated BYO-API-key row inside OpenCode's `auth.json`, a different
//! concept that deliberately stays untouched.
//!
//! # One gating rule
//!
//! Every provider-owned facet a launch can reach — host credential capture,
//! the guest placeholder files, the proxy secret and its intercept route, the
//! first-run bypass configs, and the provider guest env — is gated on one
//! predicate: membership in the launch's **provisioning set**
//! (`config::CatalogEntry::provisioned`, the transitive closure of the tool's
//! `tools` over the catalog, unioned with each visited tool's `credentials`).
//! A `"*"` entry closes over the declaring tool's **own configuration file**
//! (origin equality — `ToolOrigin`), never the merged catalog, so one file's
//! tools cannot widen another file's tool. There is deliberately no per-facet
//! `Scope` field any more: one rule needs no table.
//!
//! **Invariant: a placeholder is never provisioned into the guest unless this
//! launch registers its substitution entry.** For Anthropic/OpenAI/
//! OpenCode-static this holds by construction — their placeholders live in
//! files written *by* capture. Copilot is the exception (its placeholder lives
//! in `copilot/config.json`, a *config* file), which is why
//! `write_copilot_guest_config` runs **after** `secrets::refresh_copilot` and
//! why `COPILOT_GITHUB_TOKEN` is gated on wiring as well as membership. See
//! ADR-0017.
//!
//! | Facet | Anthropic | OpenAI | OpenCode-static | Copilot |
//! |---|---|---|---|---|
//! | guest home symlinks | always | n/a (the codex tool's `env`) | always | always |
//! | eager state dir (`ensure_dirs`) | `claude` | `codex` | `opencode` | — |
//! | guest env | — | — | — | `COPILOT_GITHUB_TOKEN` when provisioned **and** wired |
//! | proxy secret registered | when token present | when token present | when token present | when token present **and** provisioned |
//! | missing-credential hard bail | yes | no | no | yes |
//!
//! The remaining `always` rows (guest home links, eager state dirs) are
//! **furniture, not capability** — the whole state dir is already bind-mounted
//! at `/agent-vm-state`, so they are deliberately not gated. See ADR-0017.
//!
//! # Names
//!
//! `config_name` (`anthropic` / `openai` / `opencode-static` / `copilot`) is
//! **not** the `doctor_label` (`claude` / `codex` / `opencode` / `copilot`).
//! The doctor label names the host *CLI that owns the file*, retained
//! verbatim so `agent-vm doctor` output stays byte-identical. A user who reads
//! `opencode` out of `agent-vm doctor` and writes `credentials = ["opencode"]`
//! will be rejected by #80's validator — the config name is `opencode-static`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::Value;

use crate::host_paths::GuestStateDir;
use crate::secrets;

/// A compiled-in credential subsystem a tool can depend on. The set of
/// variants is a *code* fact (each needs Rust to capture/rotate/inject);
/// which tool uses which is configuration (#80/#82).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CredentialProvider {
    Anthropic,
    OpenAi,
    OpencodeStatic,
    Copilot,
}

// `ProviderSet` is a `u8` bitset; a fifth compiled-in provider is a deliberate
// change, not an accident.
const _: () = assert!(CredentialProvider::ALL.len() <= 8);

impl CredentialProvider {
    pub const ALL: [CredentialProvider; 4] = [
        CredentialProvider::Anthropic,
        CredentialProvider::OpenAi,
        CredentialProvider::OpencodeStatic,
        CredentialProvider::Copilot,
    ];

    /// The single-row-per-provider knowledge table. Kept private: callers get
    /// accessor functions, never the struct, so an unused field cannot
    /// accumulate unnoticed.
    fn spec(self) -> &'static ProviderSpec {
        &SPECS[self as usize]
    }

    /// Stable name used in `credentials = [...]` (#80) and diagnostics.
    /// Consumed by `config::validate_credentials` on the config parse path;
    /// the inverse below is used by tests and future config printing.
    pub fn config_name(self) -> &'static str {
        self.spec().config_name
    }

    /// Inverse of [`Self::config_name`]. Unknown names are rejected.
    pub fn from_config_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.config_name() == name)
    }

    /// `$HOME`-anchored file this provider captures from. `None` only when
    /// `$HOME` is unset (preserved legacy behaviour: capture is skipped, not
    /// a hard error).
    pub fn host_credential_path(self) -> Option<PathBuf> {
        let home = std::env::var_os("HOME")?;
        Some(PathBuf::from(home).join(self.spec().host_credential_home_relative))
    }

    /// Retained verbatim so `agent-vm doctor`'s output is byte-identical; it
    /// names the *CLI that owns the host file*, not the provider.
    pub(crate) fn doctor_label(self) -> &'static str {
        self.spec().doctor_label
    }

    pub(crate) fn doctor_parses_expiry(self) -> bool {
        self.spec().doctor_parses_expiry
    }

    fn oauth_rotation(self) -> Option<&'static OAuthRotation> {
        self.spec().oauth_rotation.as_ref()
    }
}

/// The providers a single launched tool depends on. Copy + set semantics so
/// it can be threaded through launch without lifetimes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProviderSet(u8);

impl ProviderSet {
    pub fn new(providers: impl IntoIterator<Item = CredentialProvider>) -> Self {
        let mut bits = 0u8;
        for provider in providers {
            bits |= 1 << (provider as u8);
        }
        Self(bits)
    }

    pub fn contains(self, provider: CredentialProvider) -> bool {
        self.0 & (1 << (provider as u8)) != 0
    }

    pub(crate) fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Always yields in `CredentialProvider::ALL` order — determinism matters
    /// for error ordering and for the guest-env/link ordering tests.
    pub fn iter(self) -> impl Iterator<Item = CredentialProvider> {
        CredentialProvider::ALL
            .into_iter()
            .filter(move |p| self.contains(*p))
    }
}

/// Guest-HOME dotfile → state-dir-entry mapping. Replaces the bare
/// `(&str, &str)` tuple so the two same-typed halves can't be swapped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HomeLink {
    pub home_relative: &'static str,
    pub state_relative: &'static str,
}

/// Links that are not owned by any provider (`.gitconfig`, `.config/gh`,
/// `.bash_history`, `.pi`) — unconditional, and deliberately kept apart from
/// the tool-specific ones (#81 acceptance criterion).
///
/// `.pi` is here rather than on a provider because the `pi` tool declares no
/// `credentials` (Pi enrols providers in-session), so there is no
/// `ProviderSpec` to hang it off. Unconditional like the rest of this list,
/// because a bare `pi` typed into `agent-vm shell` must persist too. Issue
/// #96; see `docs/adr/0021-project-scoped-pi-home-and-wrapper-parity.md`, and
/// [`crate::session::ProjectSession::migrate_legacy_pi_home`] for the one-shot
/// upgrade from the pre-#96 real directory.
pub const GENERIC_HOME_LINKS: &[HomeLink] = &[
    // gh/git config: [`secrets::write_guest_gh_config`] writes both into the
    // state dir; these symlinks expose them at the standard paths. The
    // `gh-config` link dangles when no gh token was captured — nothing
    // references it in that case.
    HomeLink {
        home_relative: ".gitconfig",
        state_relative: "gitconfig",
    },
    HomeLink {
        home_relative: ".config/gh",
        state_relative: "gh-config",
    },
    // Persistent per-project bash history. [`secrets::refresh`] touches
    // `<state>/bash_history` so the symlink target exists on first launch
    // (see `write_bypass_configs`'s unconditional `bash_history` create).
    HomeLink {
        home_relative: ".bash_history",
        state_relative: "bash_history",
    },
    // Pi's user-scoped home (#96). Pi reads project resources from `<cwd>/.pi`
    // and user state from `~/.pi/agent` -- two different resolvers, two
    // different mounts, so this link cannot shadow the checkout's `.pi/`.
    HomeLink {
        home_relative: ".pi",
        state_relative: "pi",
    },
];

/// Every link provisioned into the guest HOME, provider links first (in
/// `ALL` order) then generic. Unconditional: see the module-level "always-on
/// is preserved" note.
///
/// Shared source-of-truth for both guest-user modes, so they cannot drift:
/// root mode bakes these as `/root/<home_relative> ->
/// /agent-vm-state/<state_relative>` rootfs symlinks via `run.rs`'s
/// `.patch()` block, and non-root mode wires the *same* mapping up host-side
/// in [`crate::session::ProjectSession::provision_guest_home`] (its HOME
/// lives under the `/agent-vm-state` runtime bind mount, which shadows
/// anything `.patch()` bakes at that path). See ADR-0002.
pub fn guest_home_links() -> Vec<HomeLink> {
    let mut links = Vec::new();
    for provider in CredentialProvider::ALL {
        links.extend_from_slice(provider.spec().home_links);
    }
    links.extend_from_slice(GENERIC_HOME_LINKS);
    links
}

/// Eager state dirs owned by no provider. `<state>/pi` is here because Pi
/// does `mkdir -p ~/.pi/agent` on startup, and `mkdir` through a DANGLING
/// symlink fails with EEXIST rather than creating the target -- `ensure_dirs`
/// otherwise creates only a link target's *parent*.
pub const GENERIC_EAGER_STATE_DIRS: &[&str] = &["pi"];

/// Directories created under the per-project state dir before boot.
pub fn eager_state_dirs() -> Vec<&'static str> {
    let mut dirs = Vec::new();
    for provider in CredentialProvider::ALL {
        dirs.extend_from_slice(provider.spec().eager_state_dirs);
    }
    dirs.extend_from_slice(GENERIC_EAGER_STATE_DIRS);
    dirs
}

/// The two per-launch provider sets the gating reads. Two separate
/// `ProviderSet` parameters would be swappable at the call site.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LaunchProviders {
    /// Everything this launch provisions (the tool's `tools` closure).
    pub(crate) provisioned: ProviderSet,
    /// Those whose host credential was captured, so the proxy holds a
    /// substitution entry. `wired ⊆ provisioned` by construction.
    pub(crate) wired: ProviderSet,
}

/// The guest env pairs owned by the providers this launch both provisions and
/// wired. A tool's own env is not here — it is config
/// ([`crate::config::Tool::guest_env`]), published earlier by `run::launch`.
///
/// Membership alone is not enough: `shell` provisions Copilot without
/// requiring it, so a failed Copilot capture would otherwise export an
/// unsubstituted placeholder bearer.
pub fn provider_guest_env(launch: LaunchProviders) -> Vec<(&'static str, &'static str)> {
    let mut env = Vec::new();
    for provider in CredentialProvider::ALL {
        if !(launch.provisioned.contains(provider) && launch.wired.contains(provider)) {
            continue;
        }
        for &(key, value) in provider.spec().guest_env {
            env.push((key, value));
        }
    }
    env
}

/// The hard-stop message when a **required** provider produced no usable
/// credential, or `None` if this provider degrades gracefully.
pub fn missing_credential_error(provider: CredentialProvider) -> Option<&'static str> {
    provider.spec().missing_credential_error
}

/// What the substituting proxy must register for `provider` — `None` when the
/// provider has no proxied secret of its own.
pub(crate) fn proxy_secret(provider: CredentialProvider) -> Option<ProxySecret> {
    provider.spec().proxy.clone()
}

/// Whether an OAuth-rotatable provider accepts a refresh placeholder, plus the
/// host-side facts the interception hook needs. Sourced from the shared table
/// so [`crate::intercept_hook::oauth_refresh`] holds no second copy.
pub(crate) fn oauth_rotation(provider: CredentialProvider) -> Option<&'static OAuthRotation> {
    provider.oauth_rotation()
}

/// Write the first-run bypass configs for the **provisioned** providers, then
/// the generic `bash_history` seed. Idempotent across launches; merges instead
/// of overwriting so user tweaks survive.
///
/// Copilot is deliberately absent: its `copilot/config.json` carries the
/// proxy placeholder, so it is written *after* capture by
/// [`write_copilot_guest_config`] — writing it here would provision a
/// placeholder the launch may never register. Do **not** "fix" that by
/// reordering this whole function: `secrets::write_opencode_model_default`
/// (post-capture) deliberately disagrees with `write_opencode_bypass`
/// (pre-capture) about `opencode-config/opencode.json`.
pub(crate) fn write_bypass_configs(
    guest: &GuestStateDir,
    ctx: &BypassContext<'_>,
    provisioned: ProviderSet,
) -> Result<()> {
    for provider in CredentialProvider::ALL {
        if !provisioned.contains(provider) {
            continue;
        }
        match provider {
            CredentialProvider::Anthropic => write_anthropic_bypass(guest, ctx)?,
            CredentialProvider::OpenAi => write_openai_bypass(guest)?,
            CredentialProvider::OpencodeStatic => write_opencode_bypass(guest)?,
            CredentialProvider::Copilot => {}
        }
    }
    // Generic: pairs with the `.bash_history` link in `GENERIC_HOME_LINKS`.
    // Run last, matching the historical relative position.
    let _ = guest.create(Path::new("bash_history"), b"", 0o600)?;
    Ok(())
}

/// Inputs the bypass writers need that are neither provider- nor selection-
/// specific.
pub(crate) struct BypassContext<'a> {
    pub(crate) project_guest_path: &'a str,
}

fn write_anthropic_bypass(guest: &GuestStateDir, ctx: &BypassContext<'_>) -> Result<()> {
    let mut settings = secrets::read_guest_json_object(guest, Path::new("claude/settings.json"));
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

    let mut root = secrets::read_guest_json_object(guest, Path::new("claude.json"));
    root.insert("hasCompletedOnboarding".into(), Value::Bool(true));
    root.insert("bypassPermissionsModeAccepted".into(), Value::Bool(true));
    let projects = root
        .entry("projects")
        .or_insert_with(|| serde_json::json!({}));
    let projects = projects
        .as_object_mut()
        .context("guest claude projects is not an object")?;
    let project = projects
        .entry(ctx.project_guest_path.to_owned())
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
    Ok(())
}

fn write_openai_bypass(guest: &GuestStateDir) -> Result<()> {
    let codex = b"sandbox_mode = \"danger-full-access\"\napproval_policy = \"never\"\n";
    let _ = guest.create(Path::new("codex/config.toml"), codex, 0o644)?;
    Ok(())
}

fn write_opencode_bypass(guest: &GuestStateDir) -> Result<()> {
    let mut opencode =
        secrets::read_guest_json_object(guest, Path::new("opencode-config/opencode.json"));
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
    Ok(())
}

/// Write the GitHub Copilot CLI's `~/.copilot/config.json`.
///
/// Called by [`crate::secrets::refresh`] **only when the Copilot token was
/// captured this launch**, because `github_token` holds the proxy placeholder.
/// Two fields are set, mirroring the original Bash agent-vm's
/// `_copilot_vm_setup_home`:
///
///  - `trusted_folders = ["/"]` so the CLI never prompts "do you trust this
///    folder?" — the microVM is the sandbox, so trusting every path inside it
///    is correct.
///  - `github_token` carries [`crate::secrets::COPILOT_TOKEN_PLACEHOLDER`],
///    which the proxy substitutes for the real token on outbound traffic. The
///    CLI also honours the `COPILOT_GITHUB_TOKEN` env var (set by the
///    launcher); writing it here too covers config-first reads.
///
/// Merge-on-existing so a user's own settings survive across launches; only
/// the fields we manage are force-set.
pub(crate) fn write_copilot_guest_config(guest: &GuestStateDir) -> Result<()> {
    let mut copilot = secrets::read_guest_json_object(guest, Path::new("copilot/config.json"));
    copilot.insert("trusted_folders".into(), serde_json::json!(["/"]));
    copilot.insert(
        "github_token".into(),
        Value::String(secrets::COPILOT_TOKEN_PLACEHOLDER.into()),
    );
    guest.atomic_write(
        Path::new("copilot/config.json"),
        &serde_json::to_vec(&Value::Object(copilot))?,
        0o600,
    )?;
    Ok(())
}

/// A proxy-substitution entry: the env var it is registered under, the
/// placeholder the guest sees, the exact hosts it may substitute on, and an
/// optional OAuth token route.
#[derive(Debug, Clone)]
pub(crate) struct ProxySecret {
    pub(crate) env_var: &'static str,
    pub(crate) placeholder: &'static str,
    pub(crate) hosts: &'static [&'static str],
    pub(crate) basic_auth: bool,
    pub(crate) oauth_token_route: Option<(&'static str, &'static str)>,
}

/// The host-side facts the OAuth-refresh interception hook needs for a
/// provider whose access token agent-vm can rotate by re-running the vendor
/// CLI.
#[derive(Debug)]
pub(crate) struct OAuthRotation {
    /// SNI/Host the guest's refresh request arrives on.
    pub(crate) sni_host: &'static str,
    pub(crate) token_path: &'static str,
    /// Refresh-token placeholders accepted on this host. OpenAI accepts two
    /// because OpenCode's synthesized entry reuses the same OAuth host with
    /// its own placeholder (see `OPENCODE_OPENAI_REFRESH_PLACEHOLDER`).
    pub(crate) accepted_refresh_placeholders: &'static [&'static str],
    /// Shown in the 503 body: what the user runs *on the host* to recover.
    pub(crate) host_login_hint: &'static str,
}

/// One row of the knowledge table: every fact about one provider in one place
/// to read. Private; the public surface is the accessor functions above.
struct ProviderSpec {
    config_name: &'static str,
    /// Retained verbatim so `agent-vm doctor`'s output is byte-identical.
    doctor_label: &'static str,
    doctor_parses_expiry: bool,
    host_credential_home_relative: &'static str,
    /// Created by `ProjectSession::ensure_dirs` before boot.
    eager_state_dirs: &'static [&'static str],
    home_links: &'static [HomeLink],
    guest_env: &'static [(&'static str, &'static str)],
    proxy: Option<ProxySecret>,
    missing_credential_error: Option<&'static str>,
    oauth_rotation: Option<OAuthRotation>,
}

const ANTHROPIC_MISSING: &str = "no usable Claude credential found on the host at \
~/.claude/.credentials.json. Sign in *on the host* with \
`claude login`, then retry — you cannot `/login` from inside \
the VM, which only ever sees placeholder tokens. Run \
`agent-vm doctor` to see what was found.";

const COPILOT_MISSING: &str = "no GitHub Copilot token found on the host. Sign in on the host \
(e.g. `gh auth login` with a Copilot seat, or run the Copilot \
device-flow login that writes ~/.cache/claude-vm/copilot-token.json) \
and retry, or pick another agent.";

const SPECS: [ProviderSpec; 4] = [
    // Anthropic
    ProviderSpec {
        config_name: "anthropic",
        doctor_label: "claude",
        doctor_parses_expiry: true,
        host_credential_home_relative: ".claude/.credentials.json",
        eager_state_dirs: &["claude"],
        home_links: &[
            HomeLink {
                home_relative: ".claude",
                state_relative: "claude",
            },
            // Onboarding-state file lives at $HOME root, not in .claude/.
            // Without persistence the in-VM Claude re-runs the theme picker
            // every launch.
            HomeLink {
                home_relative: ".claude.json",
                state_relative: "claude.json",
            },
        ],
        guest_env: &[],
        proxy: Some(ProxySecret {
            env_var: "MSB_AGENT_VM_ANTHROPIC_UNUSED",
            placeholder: secrets::ANTHROPIC_ACCESS_PLACEHOLDER,
            hosts: &[
                secrets::ANTHROPIC_API_HOST,
                secrets::ANTHROPIC_OAUTH_HOST,
                secrets::ANTHROPIC_MCP_PROXY_HOST,
            ],
            basic_auth: false,
            oauth_token_route: Some((
                secrets::ANTHROPIC_OAUTH_HOST,
                secrets::ANTHROPIC_OAUTH_TOKEN_PATH,
            )),
        }),
        missing_credential_error: Some(ANTHROPIC_MISSING),
        oauth_rotation: Some(OAuthRotation {
            sni_host: secrets::ANTHROPIC_OAUTH_HOST,
            token_path: secrets::ANTHROPIC_OAUTH_TOKEN_PATH,
            accepted_refresh_placeholders: &[secrets::ANTHROPIC_REFRESH_PLACEHOLDER],
            host_login_hint: "claude login",
        }),
    },
    // OpenAi (Codex)
    ProviderSpec {
        config_name: "openai",
        doctor_label: "codex",
        doctor_parses_expiry: false,
        host_credential_home_relative: ".codex/auth.json",
        eager_state_dirs: &["codex"],
        // Codex is deliberately absent from the dotfile links: it locates its
        // config via the `CODEX_HOME` env var, which the *codex tool* declares
        // in config (`config::Tool::guest_env`), not this provider.
        home_links: &[],
        guest_env: &[],
        proxy: Some(ProxySecret {
            env_var: "MSB_AGENT_VM_OPENAI_UNUSED",
            placeholder: secrets::OPENAI_ACCESS_PLACEHOLDER,
            hosts: &[
                secrets::OPENAI_API_HOST,
                secrets::OPENAI_CHATGPT_HOST,
                secrets::OPENAI_OAUTH_HOST,
            ],
            basic_auth: false,
            oauth_token_route: Some((secrets::OPENAI_OAUTH_HOST, secrets::OPENAI_OAUTH_TOKEN_PATH)),
        }),
        missing_credential_error: None,
        oauth_rotation: Some(OAuthRotation {
            sni_host: secrets::OPENAI_OAUTH_HOST,
            token_path: secrets::OPENAI_OAUTH_TOKEN_PATH,
            accepted_refresh_placeholders: &[
                secrets::OPENAI_REFRESH_PLACEHOLDER,
                secrets::OPENCODE_OPENAI_REFRESH_PLACEHOLDER,
            ],
            host_login_hint: "codex login",
        }),
    },
    // OpencodeStatic
    ProviderSpec {
        config_name: "opencode-static",
        doctor_label: "opencode",
        doctor_parses_expiry: false,
        host_credential_home_relative: ".local/share/opencode/auth.json",
        eager_state_dirs: &["opencode"],
        home_links: &[
            HomeLink {
                home_relative: ".local/share/opencode",
                state_relative: "opencode",
            },
            // OpenCode reads its config from $XDG_CONFIG_HOME/opencode/
            // (=~/.config/opencode/), file opencode.json. Distinct from the
            // data dir above — wired separately.
            HomeLink {
                home_relative: ".config/opencode",
                state_relative: "opencode-config",
            },
        ],
        guest_env: &[],
        proxy: Some(ProxySecret {
            env_var: "MSB_AGENT_VM_OPENCODE_OPENAI_UNUSED",
            placeholder: secrets::OPENCODE_OPENAI_ACCESS_PLACEHOLDER,
            hosts: &[secrets::OPENAI_API_HOST, secrets::OPENAI_CHATGPT_HOST],
            basic_auth: false,
            oauth_token_route: None,
        }),
        missing_credential_error: None,
        oauth_rotation: None,
    },
    // Copilot
    ProviderSpec {
        config_name: "copilot",
        doctor_label: "copilot",
        doctor_parses_expiry: false,
        host_credential_home_relative: ".cache/claude-vm/copilot-token.json",
        // Deliberately empty even though the provider owns `copilot/`:
        // `ensure_dirs` does not create it today, and an empty `<state>/copilot`
        // would turn a dangling `.copilot` symlink into a real empty directory
        // for non-copilot launches. The field name says "eagerly created before
        // boot", not "all dirs this provider owns".
        eager_state_dirs: &[],
        // D1: GitHub Copilot CLI reads/writes ~/.copilot/ (config.json with
        // trusted_folders + the placeholder token, plus its session state).
        home_links: &[HomeLink {
            home_relative: ".copilot",
            state_relative: "copilot",
        }],
        // Set via env (not just `~/.copilot/config.json`) because `attach()`'s
        // execve never sources `/etc/profile.d`, unlike the original Bash
        // agent-vm. The value is the placeholder; the proxy substitutes the
        // real GitHub OAuth token on the wire. The pair is emitted last
        // (`provider_guest_env`, published after `GUEST_ALWAYS_ENV`); see the
        // module doc for why exporting it to a non-Copilot guest would be a
        // proxy/substitution violation.
        guest_env: &[("COPILOT_GITHUB_TOKEN", secrets::COPILOT_TOKEN_PLACEHOLDER)],
        proxy: Some(ProxySecret {
            env_var: "MSB_AGENT_VM_COPILOT_UNUSED",
            placeholder: secrets::COPILOT_TOKEN_PLACEHOLDER,
            hosts: &[
                secrets::COPILOT_API_HOST,
                secrets::COPILOT_API_INDIVIDUAL_HOST,
            ],
            basic_auth: false,
            oauth_token_route: None,
        }),
        missing_credential_error: Some(COPILOT_MISSING),
        oauth_rotation: None,
    },
];

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn guest() -> (tempfile::TempDir, GuestStateDir) {
        let state = tempfile::tempdir().unwrap();
        let guest = GuestStateDir::open(state.path()).unwrap();
        (state, guest)
    }

    /// Count regular files under `root`, recursively.
    fn count_files(root: &Path) -> usize {
        let mut total = 0;
        for entry in std::fs::read_dir(root).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                total += count_files(&entry.path());
            } else {
                total += 1;
            }
        }
        total
    }

    /// V2: the exact guest-HOME link set, in order. Reordering or dropping a
    /// link silently loses a user's session state on the next launch. Golden
    /// transcribed from the pre-refactor `session::GUEST_HOME_LINKS`.
    #[test]
    fn guest_home_links_match_legacy_list() {
        let golden = [
            HomeLink {
                home_relative: ".claude",
                state_relative: "claude",
            },
            HomeLink {
                home_relative: ".claude.json",
                state_relative: "claude.json",
            },
            HomeLink {
                home_relative: ".local/share/opencode",
                state_relative: "opencode",
            },
            HomeLink {
                home_relative: ".config/opencode",
                state_relative: "opencode-config",
            },
            HomeLink {
                home_relative: ".copilot",
                state_relative: "copilot",
            },
            HomeLink {
                home_relative: ".gitconfig",
                state_relative: "gitconfig",
            },
            HomeLink {
                home_relative: ".config/gh",
                state_relative: "gh-config",
            },
            HomeLink {
                home_relative: ".bash_history",
                state_relative: "bash_history",
            },
            HomeLink {
                home_relative: ".pi",
                state_relative: "pi",
            },
        ];
        assert_eq!(guest_home_links().as_slice(), golden);
    }

    /// #96: no two compiled links may overlap component-wise, and no generic
    /// eager state dir may collide with a provider's eager dir or with a
    /// *different* link's state entry. Catches a future `.pi/agent` link that
    /// would shadow or alias `~/.pi`.
    #[test]
    fn compiled_links_and_eager_dirs_do_not_collide() {
        let links = guest_home_links();
        for (position, link) in links.iter().enumerate() {
            for other in &links[position + 1..] {
                assert!(
                    !crate::config::guest_paths_overlap(
                        Path::new(link.home_relative),
                        Path::new(other.home_relative)
                    ),
                    "{} overlaps {}",
                    link.home_relative,
                    other.home_relative
                );
            }
        }

        let provider_eager: Vec<&str> = CredentialProvider::ALL
            .iter()
            .flat_map(|provider| provider.spec().eager_state_dirs.iter().copied())
            .collect();
        for generic in GENERIC_EAGER_STATE_DIRS {
            assert!(
                !provider_eager.contains(generic),
                "generic eager dir {generic} collides with a provider's"
            );
            // The eager dir must be backed by exactly one compiled link --
            // otherwise `ensure_dirs` creates a directory nothing maps to, or
            // a second link aliases it -- and no *other* link's state entry
            // may nest under it or contain it. This is the check that fails
            // for a future `.pi/agent` link.
            let backing = links
                .iter()
                .filter(|link| link.state_relative == *generic)
                .count();
            assert_eq!(
                backing, 1,
                "generic eager dir {generic} must be backed by exactly one link, found {backing}"
            );
            for link in &links {
                if link.state_relative == *generic {
                    continue;
                }
                assert!(
                    !crate::config::guest_paths_overlap(
                        Path::new(link.state_relative),
                        Path::new(generic)
                    ),
                    "generic eager dir {generic} overlaps link {}'s state entry {}",
                    link.home_relative,
                    link.state_relative
                );
            }
        }
    }

    /// V12: the three per-tool state subdirectories plus the generic `pi` dir
    /// are eagerly created (the state root itself is created separately by
    /// `ensure_dirs`).
    #[test]
    fn eager_state_dirs_match_legacy() {
        assert_eq!(
            eager_state_dirs(),
            vec!["claude", "codex", "opencode", "pi"]
        );
    }

    /// V3: the four host credential paths, transcribed from the pre-refactor
    /// source. A typo in any literal makes the in-guest agent silently signed
    /// out.
    #[test]
    fn host_credential_paths_match_legacy() {
        let mut env = crate::test_env::guard();
        env.set_var("HOME", "/home/legacy");
        assert_eq!(
            CredentialProvider::Anthropic.host_credential_path(),
            Some(PathBuf::from("/home/legacy/.claude/.credentials.json"))
        );
        assert_eq!(
            CredentialProvider::OpenAi.host_credential_path(),
            Some(PathBuf::from("/home/legacy/.codex/auth.json"))
        );
        assert_eq!(
            CredentialProvider::OpencodeStatic.host_credential_path(),
            Some(PathBuf::from(
                "/home/legacy/.local/share/opencode/auth.json"
            ))
        );
        assert_eq!(
            CredentialProvider::Copilot.host_credential_path(),
            Some(PathBuf::from(
                "/home/legacy/.cache/claude-vm/copilot-token.json"
            ))
        );
        // `$HOME` unset ⇒ `None` (capture skipped, not a hard error).
        env.remove_var("HOME");
        assert_eq!(CredentialProvider::Anthropic.host_credential_path(), None);
    }

    /// The `CredentialProvider::ALL` order is load-bearing: `doctor.rs` maps
    /// over it to build the host-credential table, and the ticket's AC is that
    /// `agent-vm doctor`'s output stays byte-identical. `ALL` must therefore be
    /// claude, codex, opencode, copilot (transcribed from
    /// `a8fa246:crates/agent-vm/src/doctor.rs:145-161`), and only claude's row
    /// parses an expiry. `provider_table_is_internally_consistent` only checks
    /// *uniqueness*, so a reorder would slip past it; this pins the order.
    #[test]
    fn all_order_and_doctor_labels_match_historical_output() {
        assert_eq!(
            CredentialProvider::ALL.map(|p| p.doctor_label()),
            ["claude", "codex", "opencode", "copilot"],
            "doctor host-credential table order changed"
        );
        assert_eq!(
            CredentialProvider::ALL.map(|p| p.doctor_parses_expiry()),
            [true, false, false, false],
            "which doctor rows parse an expiry changed"
        );
        assert_eq!(
            CredentialProvider::ALL.map(|p| p.config_name()),
            ["anthropic", "openai", "opencode-static", "copilot"],
            "config names or their order changed"
        );
    }

    /// **U1.** `write_bypass_configs` writes exactly the bypass configs for
    /// the **provisioned** providers (plus the generic `bash_history`), and
    /// nothing else. The empty row proves the gate closes; the all-four row
    /// catches a revert of the Copilot reorder — `copilot/config.json` holds a
    /// placeholder and is written post-capture, never here.
    #[test]
    fn write_bypass_configs_follows_the_provisioning_set() {
        use CredentialProvider::*;
        let ctx = BypassContext {
            project_guest_path: "/workspace/p",
        };
        let claude_settings: (&str, Vec<u8>, u32) = (
            "claude/settings.json",
            br#"{"theme":"dark","hasCompletedOnboarding":true,"skipDangerousModePermissionPrompt":true,"effortLevel":"xhigh"}"#.to_vec(),
            0o644,
        );
        let claude_json: (&str, Vec<u8>, u32) = (
            "claude.json",
            br#"{"hasCompletedOnboarding":true,"bypassPermissionsModeAccepted":true,"projects":{"/workspace/p":{"hasTrustDialogAccepted":true,"hasCompletedProjectOnboarding":true,"history":[]}}}"#.to_vec(),
            0o644,
        );
        let codex_config: (&str, Vec<u8>, u32) = (
            "codex/config.toml",
            b"sandbox_mode = \"danger-full-access\"\napproval_policy = \"never\"\n".to_vec(),
            0o644,
        );
        let opencode_config: (&str, Vec<u8>, u32) = (
            "opencode-config/opencode.json",
            br#"{"$schema":"https://opencode.ai/config.json","model":"openai/gpt-5.5","autoupdate":false}"#.to_vec(),
            0o644,
        );
        // Type alias keeps the nested tuple out of clippy's `type_complexity`
        // lint, which the `--all-targets -D warnings` gate turns into an error.
        type GoldenFile = (&'static str, Vec<u8>, u32);
        let cases: [(Vec<CredentialProvider>, Vec<GoldenFile>); 5] = [
            (vec![], vec![]),
            (vec![OpenAi], vec![codex_config.clone()]),
            (
                vec![Anthropic],
                vec![claude_settings.clone(), claude_json.clone()],
            ),
            (vec![OpencodeStatic], vec![opencode_config.clone()]),
            (
                vec![Anthropic, OpenAi, OpencodeStatic, Copilot],
                vec![
                    claude_settings.clone(),
                    claude_json.clone(),
                    codex_config.clone(),
                    opencode_config.clone(),
                ],
            ),
        ];
        for (provisioned, files) in cases {
            let (state, guest) = guest();
            write_bypass_configs(&guest, &ctx, ProviderSet::new(provisioned.clone())).unwrap();
            let mut expected = files;
            expected.push(("bash_history", b"".to_vec(), 0o600));
            for (relative, bytes, mode) in &expected {
                let actual = guest
                    .read(Path::new(relative))
                    .unwrap()
                    .unwrap_or_else(|| panic!("{relative} must be written for {provisioned:?}"));
                assert_eq!(
                    &actual, bytes,
                    "bytes for {relative} changed ({provisioned:?})"
                );
                assert_eq!(
                    std::fs::metadata(state.path().join(relative))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    *mode,
                    "mode for {relative} changed ({provisioned:?})"
                );
            }
            assert_eq!(
                count_files(state.path()),
                expected.len(),
                "an unexpected file was written for {provisioned:?}"
            );
            assert!(
                !state.path().join("copilot").exists(),
                "copilot/config.json must never be written by the pre-capture pass ({provisioned:?})"
            );
        }
    }

    /// **U2.** Copilot's guest config is written by the post-capture writer
    /// only, carries the placeholder at 0600, and its placeholder is removed
    /// again when a later launch does not wire Copilot — without disturbing
    /// keys we do not own.
    #[test]
    fn copilot_guest_config_round_trips_and_clears_only_our_placeholder() {
        let (state, guest) = guest();
        write_copilot_guest_config(&guest).unwrap();
        let bytes = guest
            .read(Path::new("copilot/config.json"))
            .unwrap()
            .expect("copilot/config.json must be written");
        assert_eq!(
            bytes,
            br#"{"trusted_folders":["/"],"github_token":"msb-copilot-placeholder-v2"}"#
        );
        assert_eq!(
            std::fs::metadata(state.path().join("copilot/config.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        crate::secrets::clear_copilot_guest_token(&guest).unwrap();
        let config: serde_json::Value = serde_json::from_slice(
            &guest
                .read(Path::new("copilot/config.json"))
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert!(config.get("github_token").is_none(), "{config}");
        assert_eq!(config["trusted_folders"], serde_json::json!(["/"]));

        // Idempotent.
        crate::secrets::clear_copilot_guest_token(&guest).unwrap();

        // A fresh guest creates nothing.
        let (fresh_state, fresh_guest) = self::guest();
        crate::secrets::clear_copilot_guest_token(&fresh_guest).unwrap();
        assert!(!fresh_state.path().join("copilot").exists());

        // Asymmetric boundary: a real user value is left untouched.
        let (_seed_state, seeded) = self::guest();
        seeded
            .atomic_write(
                Path::new("copilot/config.json"),
                br#"{"github_token":"ghu_real_user_value"}"#,
                0o600,
            )
            .unwrap();
        crate::secrets::clear_copilot_guest_token(&seeded).unwrap();
        let config: serde_json::Value = serde_json::from_slice(
            &seeded
                .read(Path::new("copilot/config.json"))
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(config["github_token"], "ghu_real_user_value");
    }

    /// **U3.** `provider_guest_env` is membership in the **provisioning set**
    /// **times** wiring: only Copilot contributes a pair, and only when this
    /// launch both provisions it and captured its token. Exporting the Copilot
    /// placeholder into a non-Copilot guest — or after a failed capture — would
    /// make the guest send an unsubstituted bearer to the Copilot API.
    /// `CODEX_HOME` must never appear here — it moved onto the codex tool's
    /// config `env` (#119), so the tool owns that emission, not a provider.
    #[test]
    fn provider_guest_env_is_membership_times_wiring() {
        use CredentialProvider::*;
        const COPILOT: [(&str, &str); 1] = [("COPILOT_GITHUB_TOKEN", "msb-copilot-placeholder-v2")];
        // Type alias keeps the nested tuple out of clippy's `type_complexity`
        // lint, which the `--all-targets -D warnings` gate turns into an error.
        type Case = (
            &'static [CredentialProvider],
            &'static [CredentialProvider],
            &'static [(&'static str, &'static str)],
        );
        let all: &'static [CredentialProvider] = &[Anthropic, OpenAi, OpencodeStatic, Copilot];
        let cases: [Case; 6] = [
            (&[], &[], &[]),
            // The load-bearing row: provisioned but not wired.
            (&[Copilot], &[], &[]),
            // Defence in depth (unreachable by construction: `wired ⊆ provisioned`).
            (&[], &[Copilot], &[]),
            (&[Copilot], &[Copilot], &COPILOT),
            (all, all, &COPILOT),
            (
                &[Anthropic, OpenAi, OpencodeStatic],
                &[Anthropic, OpenAi, OpencodeStatic],
                &[],
            ),
        ];
        for (provisioned, wired, expected) in cases {
            let launch = LaunchProviders {
                provisioned: ProviderSet::new(provisioned.iter().copied()),
                wired: ProviderSet::new(wired.iter().copied()),
            };
            let pairs = provider_guest_env(launch);
            // Before the exact-set assertion on purpose: on an ownership
            // regression this fires first with the "ownership moved" message,
            // rather than an opaque `left == right` diff that also happens to
            // name the offender.
            assert!(
                !pairs.iter().any(|(key, _)| *key == "CODEX_HOME"),
                "the tool owns CODEX_HOME now, not a provider ({provisioned:?})"
            );
            assert_eq!(
                pairs, expected,
                "for provisioned={provisioned:?} wired={wired:?}"
            );
        }
    }

    /// **U4.** The legacy scope machinery is deleted, not merely unused:
    /// `Scope`, `CaptureScope` and `proxy_requires_selection` no longer exist.
    /// This scans the **definitions** only — historical mentions in doc
    /// comments are legitimate (they are how ADR-0017 records why the enums
    /// went away). The compiler plus the deleted behaviour are the real guard;
    /// this is a cheap tripwire.
    #[test]
    fn the_legacy_scope_machinery_is_absent_from_the_source() {
        let src = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/credential_provider.rs"
        ));
        // The needles are assembled so this very test's source does not contain
        // them contiguously (an `include_str!` self-reference would always hit).
        for banned in [
            ["enum", " Scope"].concat(),
            ["enum", " CaptureScope"].concat(),
            ["fn ", "proxy_requires_selection"].concat(),
        ] {
            assert!(!src.contains(&banned), "{banned} came back");
        }
    }

    /// V11: config-name round trip; unknown names rejected.
    #[test]
    fn config_name_round_trips() {
        for provider in CredentialProvider::ALL {
            assert_eq!(
                CredentialProvider::from_config_name(provider.config_name()),
                Some(provider)
            );
        }
        assert_eq!(CredentialProvider::from_config_name("opencode"), None);
        assert_eq!(CredentialProvider::from_config_name(""), None);
    }

    /// V10: property-style internal consistency of the table. Catches a
    /// copy-paste error when a fifth provider is added later.
    #[test]
    fn provider_table_is_internally_consistent() {
        let mut config_names = Vec::new();
        let mut doctor_labels = Vec::new();
        let mut proxy_env_vars = Vec::new();
        let mut state_dirs = Vec::new();
        let mut home_relatives = Vec::new();
        let mut placeholders: Vec<(&str, &str)> = Vec::new();
        for provider in CredentialProvider::ALL {
            let spec = provider.spec();
            config_names.push(spec.config_name);
            doctor_labels.push(spec.doctor_label);
            for dir in spec.eager_state_dirs {
                state_dirs.push(*dir);
            }
            for link in spec.home_links {
                home_relatives.push(link.home_relative);
                assert!(
                    !Path::new(link.home_relative).is_absolute()
                        && !link
                            .home_relative
                            .split('/')
                            .any(|component| component == ".."),
                    "{:?} is not a safe relative home path",
                    link.home_relative
                );
            }
            if let Some(secret) = &spec.proxy {
                proxy_env_vars.push(secret.env_var);
                placeholders.push((secret.env_var, secret.placeholder));
            }
        }
        assert_eq!(
            config_names.len(),
            config_names
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            "config names must be unique"
        );
        assert_eq!(
            doctor_labels.len(),
            doctor_labels
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            "doctor labels must be unique"
        );
        assert_eq!(
            proxy_env_vars.len(),
            proxy_env_vars
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            "proxy env vars must be unique"
        );
        // Placeholders must be pairwise non-substring (see
        // `secrets::placeholders_are_pairwise_distinct` for the full set).
        for (a_name, a) in &placeholders {
            for (b_name, b) in &placeholders {
                if a_name == b_name {
                    continue;
                }
                assert!(
                    !a.contains(b) && !b.contains(a),
                    "{a_name} and {b_name} placeholders overlap"
                );
            }
        }
        // No two providers claim the same eager state dir or home link.
        for values in [&state_dirs, &home_relatives] {
            assert_eq!(
                values.len(),
                values
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len(),
                "duplicate claim in {values:?}"
            );
        }
        for name in config_names {
            assert!(
                name.chars()
                    .all(|c| c.is_ascii_lowercase() || c == '-' || c.is_ascii_digit()),
                "{name} is not lowercase-kebab"
            );
        }
    }

    /// Every `ProxySecret`/`OAuthRotation` field is read by an accessor so an
    /// unused field can't accumulate (see the module doc's "guardrails").
    #[test]
    fn table_fields_are_all_reachable() {
        for provider in CredentialProvider::ALL {
            assert!(!provider.config_name().is_empty());
            assert!(!provider.doctor_label().is_empty());
            let _ = provider.doctor_parses_expiry();
            let _ = provider.host_credential_path();
            let _ = oauth_rotation(provider);
            if let Some(secret) = proxy_secret(provider) {
                assert!(!secret.env_var.is_empty());
                assert!(!secret.placeholder.is_empty());
                assert!(!secret.hosts.is_empty());
                let _ = secret.basic_auth;
                let _ = secret.oauth_token_route;
            }
            if let Some(rotation) = oauth_rotation(provider) {
                assert!(!rotation.sni_host.is_empty());
                assert!(rotation.token_path.starts_with('/'));
                assert!(!rotation.accepted_refresh_placeholders.is_empty());
                assert!(!rotation.host_login_hint.is_empty());
            }
        }
    }

    /// The `missing_credential_error` loop only ever fires for Anthropic and
    /// Copilot, and their texts are the two pre-refactor
    /// `anyhow::bail!` literals **verbatim**. The legacy literals are inlined
    /// here (copied from `a8fa246:crates/agent-vm/src/run.rs`, the two bail
    /// blocks around lines 1245-1271) rather than compared against the table's
    /// own consts, so a future edit to `ANTHROPIC_MISSING`/`COPILOT_MISSING`
    /// actually fails this test.
    #[test]
    fn missing_credential_errors_are_exactly_the_two_legacy_bails() {
        // `\`-newline continuation strips the newline and the next line's
        // leading indentation, so this is byte-identical to the legacy `bail!`.
        let legacy_copilot = "no GitHub Copilot token found on the host. Sign in on the host \
             (e.g. `gh auth login` with a Copilot seat, or run the Copilot \
             device-flow login that writes ~/.cache/claude-vm/copilot-token.json) \
             and retry, or pick another agent.";
        let legacy_anthropic = "no usable Claude credential found on the host at \
             ~/.claude/.credentials.json. Sign in *on the host* with \
             `claude login`, then retry — you cannot `/login` from inside \
             the VM, which only ever sees placeholder tokens. Run \
             `agent-vm doctor` to see what was found.";
        assert_eq!(
            missing_credential_error(CredentialProvider::Anthropic),
            Some(legacy_anthropic)
        );
        assert_eq!(
            missing_credential_error(CredentialProvider::Copilot),
            Some(legacy_copilot)
        );
        assert_eq!(missing_credential_error(CredentialProvider::OpenAi), None);
        assert_eq!(
            missing_credential_error(CredentialProvider::OpencodeStatic),
            None
        );
    }
}
