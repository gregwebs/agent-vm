//! Credential providers: the compiled-in credential subsystems a tool can
//! depend on.
//!
//! A **credential provider** is the unit of "what a tool needs in order to be
//! signed in". Before this module existed that unit was implicit — a set of
//! `bool`s derived from the launched subcommand and spread over six files.
//! The set of variants is a *code* fact (each needs Rust to capture / rotate /
//! inject); which tool uses which is configuration (#80/#82). Do not confuse
//! this with [`crate::secrets::OpencodeApiProvider`] — that is a *dynamic*,
//! user-populated BYO-API-key row inside OpenCode's `auth.json`, a different
//! concept that deliberately stays untouched.
//!
//! # The legacy asymmetry this table encodes
//!
//! The hardest acceptance criterion for #81 is **zero behaviour change**, and
//! today's gating is asymmetric: most credential work runs on every launch
//! regardless of which tool was picked. A naive "each provider owns its
//! stuff, iterate the selected set" refactor would silently delete every
//! `Always` in the table below. Each cell is therefore an explicit, tested
//! field rather than an inference.
//!
//! | Facet | Anthropic | OpenAI | OpenCode-static | Copilot |
//! |---|---|---|---|---|
//! | host credential capture | always | always | when selected | when selected \|\| github-egress |
//! | bypass config written | always | always | always | when selected |
//! | guest home symlinks | always | n/a (`CODEX_HOME`) | always | always |
//! | eager state dir (`ensure_dirs`) | `claude` | `codex` | `opencode` | — |
//! | guest env | — | — | — | `COPILOT_GITHUB_TOKEN` when selected |
//! | proxy secret registered | when token present | when token present | when token present | when token present **and** selected |
//! | missing-credential hard bail | yes | no | no | yes |
//!
//! `Always` is a *preserved legacy behaviour*, not a design goal. Narrowing it
//! is a behaviour change tracked in
//! [agent-vm #118](https://github.com/gregwebs/agent-vm/issues/118) (#82 kept
//! it intact to meet its identical-behaviour criterion), which is why it is
//! spelled out in [`Scope`] rather than hard-coded.
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
/// `.bash_history`) — unconditional, and deliberately kept apart from the
/// tool-specific ones (#81 acceptance criterion).
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
];

/// Guest env that is not owned by any provider. `CODEX_HOME` lives here
/// because it names codex-the-tool's config dir, not a credential
/// subsystem; moving it onto the resolved tool where it belongs is
/// [agent-vm #119](https://github.com/gregwebs/agent-vm/issues/119).
// TODO(#119): move `CODEX_HOME` onto the resolved tool (a config field), not a
// generic const.
pub const GENERIC_GUEST_ENV: &[(&str, &str)] = &[("CODEX_HOME", "/agent-vm-state/codex")];

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

/// Directories created under the per-project state dir before boot.
pub fn eager_state_dirs() -> Vec<&'static str> {
    let mut dirs = Vec::new();
    for provider in CredentialProvider::ALL {
        dirs.extend_from_slice(provider.spec().eager_state_dirs);
    }
    dirs
}

/// The two guest-env emission *slots*, in publication order.
///
/// `SandboxBuilder::env` **appends** to a `Vec<EnvVar>` (serialized as a JSON
/// *array*, not a key→value map — see
/// `vendor/microsandbox/sdk/rust/lib/sandbox/builder.rs`), so the pre-#81
/// config JSON emitted the generic `CODEX_HOME` early (right after the
/// root-mode `.patch()` block) and the provider-owned `COPILOT_GITHUB_TOKEN`
/// last (after `GUEST_ALWAYS_ENV`). This prefactor's headline AC is
/// byte-identical config JSON, so the two historical positions are named
/// explicitly rather than collapsed into one loop — the same explicit-splice
/// treatment as `credential_injection`'s `WIRE_ORDER`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestEnvSlot {
    /// `GENERIC_GUEST_ENV`: pairs owned by no provider.
    Generic,
    /// The selected providers' own pairs (`ProviderSpec::guest_env`).
    ProviderOwned,
}

/// Both emission slots, in publication order.
pub const GUEST_ENV_SLOTS: [GuestEnvSlot; 2] = [GuestEnvSlot::Generic, GuestEnvSlot::ProviderOwned];

/// The `(key, value)` pairs published in one emission slot for `selection`.
pub fn guest_env_slot(
    slot: GuestEnvSlot,
    selection: ProviderSet,
) -> Vec<(&'static str, &'static str)> {
    match slot {
        GuestEnvSlot::Generic => GENERIC_GUEST_ENV.to_vec(),
        GuestEnvSlot::ProviderOwned => {
            let mut env = Vec::new();
            for provider in CredentialProvider::ALL {
                for &(key, value, scope) in provider.spec().guest_env {
                    if scope.applies(provider, selection) {
                        env.push((key, value));
                    }
                }
            }
            env
        }
    }
}

/// The full guest-env set in canonical order (generic, then provider-owned).
/// Callers that must reproduce the historical serialization positions walk
/// [`GUEST_ENV_SLOTS`] / call [`guest_env_slot`] instead.
///
/// Used by tests only today; [`crate::run`] publishes the two slots at their
/// historical positions rather than this concatenation.
#[cfg_attr(not(test), allow(dead_code))]
pub fn guest_env(selection: ProviderSet) -> Vec<(&'static str, &'static str)> {
    let mut env = Vec::new();
    for slot in GUEST_ENV_SLOTS {
        env.extend(guest_env_slot(slot, selection));
    }
    env
}

/// The hard-stop message when a selected provider produced no usable
/// credential, or `None` if this provider degrades gracefully.
pub fn missing_credential_error(provider: CredentialProvider) -> Option<&'static str> {
    provider.spec().missing_credential_error
}

/// Whether the substituting proxy must only register `provider`'s secret when
/// the provider was selected. This is the one security-critical asymmetry: a
/// Copilot placeholder exported into a non-Copilot guest would be sent to the
/// Copilot API with no registered substitution entry.
pub(crate) fn proxy_requires_selection(provider: CredentialProvider) -> bool {
    provider.spec().proxy_requires_selection
}

/// What the substituting proxy must register for `provider` — `None` when the
/// provider has no proxied secret of its own.
pub(crate) fn proxy_secret(provider: CredentialProvider) -> Option<ProxySecret> {
    provider.spec().proxy.clone()
}

/// The capture gate for `provider`, read by [`crate::secrets::refresh`] as the
/// single source of truth for the legacy asymmetry.
pub(crate) fn capture_scope(provider: CredentialProvider) -> CaptureScope {
    provider.spec().capture
}

/// Whether an OAuth-rotatable provider accepts a refresh placeholder, plus the
/// host-side facts the interception hook needs. Sourced from the shared table
/// so [`crate::intercept_hook::oauth_refresh`] holds no second copy.
pub(crate) fn oauth_rotation(provider: CredentialProvider) -> Option<&'static OAuthRotation> {
    provider.oauth_rotation()
}

/// Write the first-run bypass configs for the selected providers, then the
/// generic `bash_history` seed. Idempotent across launches; merges instead of
/// overwrites so user tweaks survive.
///
/// **Not the same writer as [`crate::secrets::write_opencode_model_default`].**
/// Both touch `opencode-config/opencode.json`; they are ordered and disagree
/// on purpose. This function seeds `model = "openai/gpt-5.5"` *before*
/// capture; `write_opencode_model_default` runs *after* capture and removes
/// that key when the launch ended up wired to a non-OpenAI OpenCode provider.
/// Do not merge them.
pub(crate) fn write_bypass_configs(
    guest: &GuestStateDir,
    ctx: &BypassContext<'_>,
    selection: ProviderSet,
) -> Result<()> {
    for provider in CredentialProvider::ALL {
        if !provider.spec().bypass.applies(provider, selection) {
            continue;
        }
        match provider {
            CredentialProvider::Anthropic => write_anthropic_bypass(guest, ctx)?,
            CredentialProvider::OpenAi => write_openai_bypass(guest)?,
            CredentialProvider::OpencodeStatic => write_opencode_bypass(guest)?,
            CredentialProvider::Copilot => write_copilot_bypass(guest)?,
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

fn write_copilot_bypass(guest: &GuestStateDir) -> Result<()> {
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

/// Whether a facet applies on every launch or only when the launched tool
/// declared the provider. Today most facets are `Always` — that is a
/// *preserved legacy behaviour*, not a design goal;
/// [agent-vm #118](https://github.com/gregwebs/agent-vm/issues/118) narrows
/// them deliberately, which is exactly why it is spelled out here.
// TODO(#118): narrow the `Always` scopes deliberately — each is a *preserved*
// legacy behaviour, not a design goal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    Always,
    WhenSelected,
}

impl Scope {
    /// Whether this facet applies for the given selection. `github_egress` is
    /// deliberately absent: only [`CaptureScope`] has the three-way case.
    fn applies(self, provider: CredentialProvider, selection: ProviderSet) -> bool {
        match self {
            Scope::Always => true,
            Scope::WhenSelected => selection.contains(provider),
        }
    }
}

/// Capture gate for a provider. A distinct type from [`Scope`] because Copilot
/// has the one three-way case: captured when selected *or* when GitHub egress
/// is already on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CaptureScope {
    Always,
    WhenSelected,
    /// Copilot only: the Copilot API takes a GitHub OAuth token, which is also
    /// captured whenever GitHub egress is on. See `secrets.rs`'s D1 note.
    WhenSelectedOrGithubEgress,
}

impl CaptureScope {
    pub(crate) fn applies(
        self,
        provider: CredentialProvider,
        selection: ProviderSet,
        github_egress: bool,
    ) -> bool {
        match self {
            CaptureScope::Always => true,
            CaptureScope::WhenSelected => selection.contains(provider),
            CaptureScope::WhenSelectedOrGithubEgress => {
                selection.contains(provider) || github_egress
            }
        }
    }
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
    guest_env: &'static [(&'static str, &'static str, Scope)],
    proxy: Option<ProxySecret>,
    proxy_requires_selection: bool,
    capture: CaptureScope,
    bypass: Scope,
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
        proxy_requires_selection: false,
        capture: CaptureScope::Always,
        bypass: Scope::Always,
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
        // config via the `CODEX_HOME` env var (`GENERIC_GUEST_ENV`), not a
        // dotfile symlink.
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
        proxy_requires_selection: false,
        capture: CaptureScope::Always,
        bypass: Scope::Always,
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
        proxy_requires_selection: false,
        capture: CaptureScope::WhenSelected,
        bypass: Scope::Always,
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
        // (`GuestEnvSlot::ProviderOwned`); see the module doc for why exporting
        // it to a non-Copilot guest would be a proxy/substitution violation.
        guest_env: &[(
            "COPILOT_GITHUB_TOKEN",
            secrets::COPILOT_TOKEN_PLACEHOLDER,
            Scope::WhenSelected,
        )],
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
        proxy_requires_selection: true,
        capture: CaptureScope::WhenSelectedOrGithubEgress,
        bypass: Scope::WhenSelected,
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
        ];
        assert_eq!(guest_home_links().as_slice(), golden);
    }

    /// V12: exactly the three per-tool state subdirectories are eagerly
    /// created (the state root itself is created separately by `ensure_dirs`).
    #[test]
    fn eager_state_dirs_match_legacy() {
        assert_eq!(eager_state_dirs(), vec!["claude", "codex", "opencode"]);
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

    /// V4: characterization golden for the bypass configs written on a
    /// *codex* (non-copilot) launch, captured on the pre-refactor tree. The
    /// claude/codex/opencode files are written **unconditionally** — a
    /// `Scope::Always` transcribed as `WhenSelected` is the single biggest
    /// regression class this ticket guards against.
    #[test]
    fn bypass_configs_written_for_codex_launch_match_legacy() {
        let (state, guest) = guest();
        let ctx = BypassContext {
            project_guest_path: "/workspace/p",
        };
        write_bypass_configs(&guest, &ctx, ProviderSet::new([CredentialProvider::OpenAi])).unwrap();

        let golden: &[(&str, &[u8], u32)] = &[
            (
                "claude/settings.json",
                br#"{"theme":"dark","hasCompletedOnboarding":true,"skipDangerousModePermissionPrompt":true,"effortLevel":"xhigh"}"#,
                0o644,
            ),
            (
                "claude.json",
                br#"{"hasCompletedOnboarding":true,"bypassPermissionsModeAccepted":true,"projects":{"/workspace/p":{"hasTrustDialogAccepted":true,"hasCompletedProjectOnboarding":true,"history":[]}}}"#,
                0o644,
            ),
            (
                "codex/config.toml",
                b"sandbox_mode = \"danger-full-access\"\napproval_policy = \"never\"\n",
                0o644,
            ),
            (
                "opencode-config/opencode.json",
                br#"{"$schema":"https://opencode.ai/config.json","model":"openai/gpt-5.5","autoupdate":false}"#,
                0o644,
            ),
            ("bash_history", b"", 0o600),
        ];
        for (relative, bytes, mode) in golden {
            let actual = guest
                .read(Path::new(relative))
                .unwrap()
                .unwrap_or_else(|| panic!("{relative} must be written by the bypass writer"));
            assert_eq!(&actual, bytes, "bytes for {relative} changed");
            assert_eq!(
                std::fs::metadata(state.path().join(relative))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                *mode,
                "mode for {relative} changed"
            );
        }
        assert!(!state.path().join("copilot").exists());
        assert_eq!(count_files(state.path()), golden.len());
    }

    /// V5: the copilot bypass config is written **only** when Copilot is
    /// selected, at 0600, carrying the placeholder (never a real token).
    #[test]
    fn copilot_bypass_config_only_when_selected() {
        let (state, guest) = guest();
        let ctx = BypassContext {
            project_guest_path: "/workspace/p",
        };
        write_bypass_configs(
            &guest,
            &ctx,
            ProviderSet::new([CredentialProvider::Copilot]),
        )
        .unwrap();
        let bytes = guest
            .read(Path::new("copilot/config.json"))
            .unwrap()
            .expect("copilot/config.json must be written for a copilot launch");
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
    }

    /// V13: the guest-env set per tool. `CODEX_HOME` is always exported;
    /// `COPILOT_GITHUB_TOKEN` only for a Copilot launch. Exporting the
    /// Copilot placeholder into every guest would make the guest send an
    /// unsubstituted bearer to the Copilot API.
    #[test]
    fn guest_env_matches_legacy_per_agent() {
        // Type alias keeps the nested tuple out of clippy's `type_complexity`
        // lint (`--all-targets`), which CI does not gate on.
        type LegacyGuestEnv = [(
            &'static [&'static str],
            &'static [(&'static str, &'static str)],
        ); 5];
        let legacy: LegacyGuestEnv = [
            (&["anthropic"], &[("CODEX_HOME", "/agent-vm-state/codex")]),
            (&["openai"], &[("CODEX_HOME", "/agent-vm-state/codex")]),
            (
                &["openai", "opencode-static"],
                &[("CODEX_HOME", "/agent-vm-state/codex")],
            ),
            (
                &["openai", "opencode-static"],
                &[("CODEX_HOME", "/agent-vm-state/codex")],
            ),
            (
                &["copilot"],
                &[
                    ("CODEX_HOME", "/agent-vm-state/codex"),
                    ("COPILOT_GITHUB_TOKEN", "msb-copilot-placeholder-v2"),
                ],
            ),
        ];
        for (names, expected) in legacy {
            let selection = ProviderSet::new(
                names
                    .iter()
                    .map(|name| CredentialProvider::from_config_name(name).unwrap()),
            );
            assert_eq!(guest_env(selection), expected, "for {names:?}");
        }
        // Empty selection still exports the generic env.
        assert_eq!(
            guest_env(ProviderSet::default()),
            vec![("CODEX_HOME", "/agent-vm-state/codex")]
        );
    }

    /// The two emission *slots* (`GUEST_ENV_SLOTS`) are pinned, not merely the
    /// combined set: `SandboxBuilder::env` appends to a `Vec<EnvVar>`
    /// (serialized as a JSON array), so the *position* of each pair is
    /// observable in the emitted config JSON and the pre-#81 positions differ
    /// from each other. `Generic` must hold exactly the generic pairs for any
    /// selection; `ProviderOwned` must hold exactly the selected providers'
    /// pairs and never the generic ones.
    #[test]
    fn guest_env_slots_pin_generic_and_provider_owned() {
        use GuestEnvSlot::{Generic, ProviderOwned};
        let copilot = ProviderSet::new([CredentialProvider::Copilot]);

        // Slot 1 is exactly the generic pairs, for every selection —
        // transcribed from the pre-#81 `.env("CODEX_HOME", …)` call, not from
        // `GENERIC_GUEST_ENV`, so moving a provider pair into the generic slot
        // fails here.
        for selection in [ProviderSet::default(), copilot] {
            assert_eq!(
                guest_env_slot(Generic, selection),
                vec![("CODEX_HOME", "/agent-vm-state/codex")],
                "the generic slot must never carry a provider-owned pair"
            );
        }
        // Slot 2 is exactly the provider-owned pairs, and is empty without one.
        assert_eq!(
            guest_env_slot(ProviderOwned, copilot),
            vec![("COPILOT_GITHUB_TOKEN", "msb-copilot-placeholder-v2")]
        );
        assert!(guest_env_slot(ProviderOwned, ProviderSet::default()).is_empty());
        assert!(
            guest_env_slot(
                ProviderOwned,
                ProviderSet::new([CredentialProvider::Anthropic])
            )
            .is_empty()
        );
        // The two slots, in order, are the whole set.
        let mut walked = Vec::new();
        for slot in GUEST_ENV_SLOTS {
            walked.extend(guest_env_slot(slot, copilot));
        }
        assert_eq!(walked, guest_env(copilot));
        assert_eq!(GUEST_ENV_SLOTS, [Generic, ProviderOwned]);
    }

    /// Every `Scope`/`CaptureScope`/`proxy_requires_selection` value pinned to
    /// the legacy gating. The Anthropic/OpenAI capture scopes are read by no
    /// behaviour today (capture is unconditional), so only this direct value
    /// test would fail if one were transcribed wrong.
    #[test]
    fn scopes_match_legacy_gating() {
        use CaptureScope::*;
        assert_eq!(capture_scope(CredentialProvider::Anthropic), Always);
        assert_eq!(capture_scope(CredentialProvider::OpenAi), Always);
        assert_eq!(
            capture_scope(CredentialProvider::OpencodeStatic),
            WhenSelected
        );
        assert_eq!(
            capture_scope(CredentialProvider::Copilot),
            WhenSelectedOrGithubEgress
        );

        for provider in [
            CredentialProvider::Anthropic,
            CredentialProvider::OpenAi,
            CredentialProvider::OpencodeStatic,
        ] {
            assert_eq!(
                provider.spec().bypass,
                Scope::Always,
                "bypass configs must be written unconditionally for {provider:?}"
            );
        }
        assert_eq!(
            CredentialProvider::Copilot.spec().bypass,
            Scope::WhenSelected
        );

        assert!(!proxy_requires_selection(CredentialProvider::Anthropic));
        assert!(!proxy_requires_selection(CredentialProvider::OpenAi));
        assert!(!proxy_requires_selection(
            CredentialProvider::OpencodeStatic
        ));
        assert!(proxy_requires_selection(CredentialProvider::Copilot));
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
            let _ = proxy_requires_selection(provider);
            let _ = capture_scope(provider);
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
