use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use microsandbox::sandbox::SandboxBuilder;
use microsandbox_network::builder::NetworkBuilder;

use crate::credential_provider::{self, CredentialProvider, ProviderSet};
use crate::credential_resolver::{LaunchCredentials, ReadyCredential};
use crate::secrets::{self, CredsState};

const MAX_BUFFERED_REQUEST_BYTES: usize = 2 * 1024 * 1024;
const API_METHODS: [&str; 5] = ["GET", "POST", "PATCH", "PUT", "DELETE"];
const SMART_HTTP_METHODS: [&str; 2] = ["GET", "POST"];

pub(crate) struct Inputs<'a> {
    pub creds: &'a CredsState,
    pub state_dir: &'a Path,
    pub allowed_repos: &'a [String],
    /// The launch's provisioning set; a provider outside it is never
    /// registered.
    pub provisioned: ProviderSet,
    /// The credentials this launch resolved (#161). Registered *after* every
    /// legacy wire slot so the existing order stays byte-identical.
    pub launch: &'a LaunchCredentials,
}

/// Registration order for the substituting proxy's secrets. Explicit because
/// GitHub is *not* a [`CredentialProvider`] (it is gated by `--no-git`, not by
/// the launched tool) yet has always been registered between the OpenCode and
/// Copilot entries. Reordering is believed harmless —
/// `secrets::placeholders_are_pairwise_distinct` proves no placeholder is a
/// substring of another, so substitution cannot pick the wrong secret — but
/// this is a prefactor, so the wire order stays byte-identical and is asserted
/// by `proxy_plan_registers_only_the_provisioned_providers`.
enum WireSlot {
    Provider(CredentialProvider),
    GithubEgress,
}

const WIRE_ORDER: [WireSlot; 5] = [
    WireSlot::Provider(CredentialProvider::Anthropic),
    WireSlot::Provider(CredentialProvider::OpenAi),
    WireSlot::Provider(CredentialProvider::OpencodeStatic),
    WireSlot::GithubEgress,
    WireSlot::Provider(CredentialProvider::Copilot),
];

pub(crate) struct Plan {
    secrets: Vec<FileSecret>,
    /// Origin-scoped named-header credentials (#161): a reference the runtime
    /// resolves at spawn, never a value.
    header_credentials: Vec<crate::credential_resolver::ReadyCredential>,
    hook_argv: Vec<String>,
    routes: Vec<Route>,
}

struct FileSecret {
    env_var: String,
    placeholder: String,
    path: PathBuf,
    hosts: Vec<&'static str>,
    basic_auth: bool,
}

#[derive(Clone, Copy)]
struct Route {
    host: &'static str,
    method: &'static str,
    path: &'static str,
    dispatch_on_headers: bool,
}

impl Plan {
    pub(crate) fn new(executable: PathBuf, inputs: Inputs<'_>) -> Result<Self> {
        let executable = utf8_path(&executable, "agent-vm executable")?;
        let state_dir = utf8_path(inputs.state_dir, "credential hook state directory")?;
        let mut hook_argv = vec![
            executable,
            "_intercept-hook".into(),
            "--state-dir".into(),
            state_dir,
        ];
        for repo in inputs.allowed_repos {
            hook_argv.extend(["--allowed-repo".into(), repo.clone()]);
        }

        let mut secrets = Vec::new();
        let mut routes = Vec::new();
        for slot in WIRE_ORDER {
            match slot {
                WireSlot::Provider(provider) => {
                    // One rule for every provider: a secret outside the
                    // provisioning set is never registered, so a placeholder
                    // can never reach a guest without its substitution entry.
                    if !inputs.provisioned.contains(provider) {
                        continue;
                    }
                    let (Some(spec), Some(path)) = (
                        credential_provider::proxy_secret(provider),
                        inputs.creds.token_file(provider),
                    ) else {
                        continue;
                    };
                    secrets.push(FileSecret {
                        env_var: spec.env_var.into(),
                        placeholder: spec.placeholder.into(),
                        path: path.to_path_buf(),
                        hosts: spec.hosts.to_vec(),
                        basic_auth: spec.basic_auth,
                    });
                    if let Some((host, path)) = spec.oauth_token_route {
                        routes.push(Route {
                            host,
                            method: "POST",
                            path,
                            dispatch_on_headers: false,
                        });
                    }
                }
                WireSlot::GithubEgress => {
                    // GitHub is not a `CredentialProvider`: its capture is
                    // gated by `--no-git`, not by the launched tool. Keep its
                    // own block (with its route allow-list) as before.
                    if let Some(path) = &inputs.creds.gh_token_file {
                        secrets.push(FileSecret {
                            env_var: "MSB_AGENT_VM_GH_UNUSED".into(),
                            placeholder: secrets::GH_TOKEN_PLACEHOLDER.into(),
                            path: path.clone(),
                            hosts: vec![
                                secrets::GITHUB_API_HOST,
                                secrets::GITHUB_HOST,
                                secrets::GITHUB_CODELOAD_HOST,
                                secrets::GITHUB_RAW_HOST,
                                secrets::GITHUB_OBJECTS_HOST,
                            ],
                            basic_auth: true,
                        });
                        for method in API_METHODS {
                            routes.push(Route {
                                host: secrets::GITHUB_API_HOST,
                                method,
                                path: "/",
                                dispatch_on_headers: false,
                            });
                        }
                        for host in [
                            secrets::GITHUB_HOST,
                            secrets::GITHUB_CODELOAD_HOST,
                            secrets::GITHUB_RAW_HOST,
                            secrets::GITHUB_OBJECTS_HOST,
                        ] {
                            for method in SMART_HTTP_METHODS {
                                routes.push(Route {
                                    host,
                                    method,
                                    path: "/",
                                    dispatch_on_headers: true,
                                });
                            }
                        }
                    }
                }
            }
        }

        for (provider, path) in &inputs.creds.opencode_api_token_files {
            secrets.push(FileSecret {
                env_var: provider.env_var(),
                placeholder: provider.placeholder.into(),
                path: path.clone(),
                hosts: vec![provider.host],
                basic_auth: false,
            });
        }

        Ok(Self {
            secrets,
            header_credentials: inputs.launch.ready().to_vec(),
            hook_argv,
            routes,
        })
    }

    /// Whether this plan registers *anything* in the network overlay. A
    /// YAML-only launch has an empty `secrets` list, so both guards below must
    /// consider the header credentials too: otherwise
    /// `builder.network(..)` is never called at all and a YAML-only launch
    /// registers nothing (#161).
    fn is_empty(&self) -> bool {
        self.secrets.is_empty() && self.header_credentials.is_empty()
    }

    pub(crate) fn apply_to(self, builder: SandboxBuilder) -> Result<SandboxBuilder> {
        // An empty plan must leave the builder untouched: installing a default
        // network overlay changes the durable config's shape for a launch that
        // registers nothing, which the goldens pin.
        if self.is_empty() {
            return Ok(builder);
        }
        // The closure signature is `FnOnce(NetworkBuilder) -> NetworkBuilder`,
        // so a failure cannot be returned through it. Stash it and surface it
        // after: the alternative would be a default that could silently drop a
        // caller's intercepted port (agent-vm #161 review, m1).
        let failure: std::cell::Cell<Option<anyhow::Error>> = std::cell::Cell::new(None);
        let builder = builder.network(|network| match self.apply_to_network(network) {
            Ok(network) => network,
            Err(error) => {
                failure.set(Some(error));
                NetworkBuilder::new()
            }
        });
        match failure.into_inner() {
            Some(error) => Err(error),
            None => Ok(builder),
        }
    }

    /// The guard plus configuration `apply_to` actually runs. Split out so a
    /// test can exercise the emptiness guard - the "YAML-only launch registers
    /// nothing" regression - without an async `SandboxBuilder`.
    pub(crate) fn apply_to_network(self, network: NetworkBuilder) -> Result<NetworkBuilder> {
        if self.is_empty() {
            return Ok(network);
        }
        self.configure_network(network)
    }

    fn configure_network(self, mut network: NetworkBuilder) -> Result<NetworkBuilder> {
        // Interception is decided **per port** (#175's fail-closed rule): the
        // runtime refuses a credential whose origin port is not in
        // `tls.intercepted_ports`. The base config's own list (default `[443]`)
        // is read here, before anything is added, and every credential origin's
        // port is unioned in below — never replacing it, so 443 and any port a
        // caller already intercepted survive.
        let base_ports = intercepted_ports_of(&network)?;
        network = network.tls_overlay(|tls| tls.enabled(true));
        // Every wire slot's `env_var` is `MSB_`-prefixed, and `GuestEnvName::parse`
        // reserves that whole namespace, so a YAML credential can never *own*
        // one and `assemble_guest_env` (which does not consult these slots) needs
        // no filter for them. `every_wire_slot_env_var_is_in_the_reserved_msb_namespace`
        // asserts the invariant so a future non-`MSB_` slot fails a test instead
        // of silently bypassing ownership (agent-vm #161 review, N5).
        for secret in self.secrets {
            network = network.secret(|mut builder| {
                builder = builder
                    .env(secret.env_var)
                    .file(secret.path)
                    .placeholder(secret.placeholder)
                    .inject_headers(true)
                    .inject_basic_auth(secret.basic_auth)
                    .inject_query(false)
                    .inject_body(false)
                    .require_tls_identity(true);
                for host in secret.hosts {
                    builder = builder.allow_host(host);
                }
                builder
            });
        }
        // #161's origin-scoped named-header credentials, registered *after*
        // every legacy wire slot so the existing order is untouched. No
        // explicit TLS enable is needed: `header_credential` turns TLS
        // interception on itself. Declaring the ports *is* needed now: the
        // union keeps 443 and every credential origin's port intercepted, so a
        // bare `domain` (which means 443) and an explicit `:port` both inject.
        if !self.header_credentials.is_empty() {
            let ports = intercepted_ports_with(base_ports, &self.header_credentials);
            network = network.tls_overlay(|tls| tls.intercepted_ports(ports.clone()));
        }
        for credential in &self.header_credentials {
            for rule in credential.inject() {
                network = network.header_credential(|builder| {
                    builder
                        // `id` and `reference` are both the folded service name
                        // today; kept explicit so a future divergence is a
                        // deliberate edit here and not an accident.
                        .id(credential.service().as_str())
                        .reference(credential.service().as_str())
                        .origin(rule.host(), rule.port())
                        .header(rule.header())
                        .format(rule.format())
                });
            }
        }
        if !self.routes.is_empty() {
            network = network.intercept(|mut intercept| {
                intercept = intercept
                    .hook(self.hook_argv)
                    .max_request_bytes(MAX_BUFFERED_REQUEST_BYTES);
                for route in self.routes {
                    intercept = if route.dispatch_on_headers {
                        intercept.streaming_rule(route.host, route.method, route.path)
                    } else {
                        intercept.rule(route.host, route.method, route.path)
                    };
                }
                intercept
            });
        }
        Ok(network)
    }
}

fn utf8_path(path: &Path, label: &str) -> Result<String> {
    path.to_str()
        .map(ToOwned::to_owned)
        .with_context(|| format!("{label} must be valid UTF-8: {}", path.display()))
}

/// The TLS-intercepted ports `network` already carries, read through the one
/// lossless read available: `NetworkBuilder` exposes no getter, but it is
/// `Clone`, and `build()` on a clone yields the assembled `NetworkConfig`.
///
/// A failed build is **propagated**, not papered over: the base is always a
/// config the SDK itself already built successfully (`SandboxBuilder::network`
/// installs only the config whose build passed), so a failure here is an
/// invariant violation - and substituting the default `[443]` would silently
/// drop any port a caller configured, which is exactly the data loss this
/// function exists to avoid (agent-vm #161 review, m1).
fn intercepted_ports_of(network: &NetworkBuilder) -> Result<Vec<u16>> {
    let config = network.clone().build().map_err(|error| {
        anyhow::anyhow!(
            "the base network configuration could not be read ({error}); refusing to register \
             credentialed interception because reading it could drop an already-configured \
             intercepted port"
        )
    })?;
    Ok(config.tls.intercepted_ports)
}

/// The intercepted-port set for a launch that registers `credentials`: `base`
/// unioned with every credential origin's port, sorted and deduplicated.
///
/// Union, never replacement. A bare `domain` means 443 and must stay
/// intercepted, and any port an existing network config already intercepts is
/// preserved. Declaring a port intercepts TLS for **every** host on it, not only
/// the credential's host — that is the honest cost of the runtime's per-port
/// fail-closed decision, and why the widening is explicit here rather than
/// derived upstream.
fn intercepted_ports_with(
    base: impl IntoIterator<Item = u16>,
    credentials: &[ReadyCredential],
) -> Vec<u16> {
    let mut ports: BTreeSet<u16> = base.into_iter().collect();
    for credential in credentials {
        for rule in credential.inject() {
            ports.insert(rule.port());
        }
    }
    ports.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use microsandbox_network::{
        builder::NetworkBuilder,
        policy::{NetworkPolicy, NetworkProfile},
        secrets::config::{HostPattern, SecretSource, ViolationAction},
    };

    use super::*;
    use crate::credential_resolver::EnvDisposition;

    fn path(name: &str) -> PathBuf {
        PathBuf::from(format!("/host/{name}"))
    }
    fn inputs(creds: &CredsState, provisioned: ProviderSet) -> Inputs<'_> {
        // No YAML-authorized credentials: every legacy ordering assertion must
        // be byte-identical whether or not #161's list is empty.
        static NONE: std::sync::LazyLock<LaunchCredentials> =
            std::sync::LazyLock::new(LaunchCredentials::default);
        Inputs {
            creds,
            state_dir: Path::new("/state/project"),
            allowed_repos: &[],
            provisioned,
            launch: &NONE,
        }
    }

    /// Select every compiled-in provider (the "all secrets present" case).
    fn all() -> ProviderSet {
        ProviderSet::new(CredentialProvider::ALL)
    }
    /// Exercise the guard `apply_to` actually runs (`apply_to_network`), not
    /// `configure_network` directly, so a YAML-only launch that fails the
    /// "nothing to register" guard is caught here (agent-vm #161 review, M4).
    fn network(plan: Plan) -> microsandbox_network::config::NetworkConfig {
        plan.apply_to_network(NetworkBuilder::new())
            .expect("a valid base network")
            .build()
            .unwrap()
    }

    /// #161 ownership: `assemble_guest_env` does not consult the legacy
    /// wire-slot variables, so the only thing keeping a wire slot from
    /// colliding with a YAML credential's owned guest variable is that every
    /// one of them is `MSB_`-prefixed — and `GuestEnvName::parse` rejects the
    /// whole `MSB_` namespace. This asserts that invariant over every slot the
    /// module can register, so a future non-`MSB_` slot fails here instead of
    /// silently bypassing ownership (agent-vm #161 review, N5).
    #[test]
    fn every_wire_slot_env_var_is_in_the_reserved_msb_namespace() {
        use crate::credential_yaml::GuestEnvName;
        let creds = CredsState {
            anthropic_token_file: Some(path("anthropic")),
            openai_token_file: Some(path("openai")),
            opencode_openai_access_token_file: Some(path("openai")),
            opencode_api_token_files: secrets::OPENCODE_API_PROVIDERS
                .iter()
                .map(|provider| (*provider, path(provider.id)))
                .collect(),
            gh_token_file: Some(path("gh")),
            copilot_token_file: Some(path("copilot")),
            ..CredsState::default()
        };
        let config = network(Plan::new(path("agent-vm"), inputs(&creds, all())).unwrap());
        assert!(!config.secrets.secrets.is_empty());
        for entry in &config.secrets.secrets {
            assert!(
                entry.env_var.starts_with("MSB_"),
                "wire slot {:?} is not in the reserved `MSB_` namespace",
                entry.env_var
            );
            assert!(
                GuestEnvName::parse(&entry.env_var).is_err(),
                "wire slot {:?} is a legal guest-env name, so a credential could own it",
                entry.env_var
            );
        }
    }

    /// V6: the emitted secret registration order, captured on the
    /// pre-refactor tree. Today it is `anthropic, openai, opencode-openai,
    /// gh, copilot` then the static OpenCode rows. A prefactor must keep
    /// this byte-identical (the `WIRE_ORDER` splice exists for exactly
    /// this reason).
    #[test]
    fn proxy_plan_matches_legacy_order() {
        let creds = CredsState {
            anthropic_token_file: Some(path("anthropic")),
            openai_token_file: Some(path("openai")),
            opencode_openai_access_token_file: Some(path("openai")),
            gh_token_file: Some(path("gh")),
            copilot_token_file: Some(path("copilot")),
            ..CredsState::default()
        };
        let config = network(Plan::new(path("agent-vm"), inputs(&creds, all())).unwrap());
        let order: Vec<String> = config
            .secrets
            .secrets
            .iter()
            .map(|entry| entry.env_var.clone())
            .collect();
        assert_eq!(
            order,
            vec![
                "MSB_AGENT_VM_ANTHROPIC_UNUSED",
                "MSB_AGENT_VM_OPENAI_UNUSED",
                "MSB_AGENT_VM_OPENCODE_OPENAI_UNUSED",
                "MSB_AGENT_VM_GH_UNUSED",
                "MSB_AGENT_VM_COPILOT_UNUSED",
            ]
        );
    }

    /// V6: per-tool secret order. The registered secret order is fixed by
    /// `WIRE_ORDER`, with `gh` spliced between the OpenCode and Copilot
    /// entries, and each provider is registered only when it is in the
    /// launch's **provisioning set** (GitHub egress is orthogonal and stays
    /// its own slot).
    #[test]
    fn proxy_plan_registers_only_the_provisioned_providers() {
        let creds = CredsState {
            anthropic_token_file: Some(path("anthropic")),
            openai_token_file: Some(path("openai")),
            opencode_openai_access_token_file: Some(path("openai")),
            gh_token_file: Some(path("gh")),
            copilot_token_file: Some(path("copilot")),
            ..CredsState::default()
        };
        let opencode = ProviderSet::new([
            CredentialProvider::OpenAi,
            CredentialProvider::OpencodeStatic,
        ]);
        let cases: [(&str, ProviderSet, &[&str]); 5] = [
            (
                "claude",
                ProviderSet::new([CredentialProvider::Anthropic]),
                &["MSB_AGENT_VM_ANTHROPIC_UNUSED", "MSB_AGENT_VM_GH_UNUSED"],
            ),
            (
                "codex",
                ProviderSet::new([CredentialProvider::OpenAi]),
                &["MSB_AGENT_VM_OPENAI_UNUSED", "MSB_AGENT_VM_GH_UNUSED"],
            ),
            (
                "opencode",
                opencode,
                &[
                    "MSB_AGENT_VM_OPENAI_UNUSED",
                    "MSB_AGENT_VM_OPENCODE_OPENAI_UNUSED",
                    "MSB_AGENT_VM_GH_UNUSED",
                ],
            ),
            (
                "shell",
                opencode,
                &[
                    "MSB_AGENT_VM_OPENAI_UNUSED",
                    "MSB_AGENT_VM_OPENCODE_OPENAI_UNUSED",
                    "MSB_AGENT_VM_GH_UNUSED",
                ],
            ),
            (
                "copilot",
                ProviderSet::new([CredentialProvider::Copilot]),
                &["MSB_AGENT_VM_GH_UNUSED", "MSB_AGENT_VM_COPILOT_UNUSED"],
            ),
        ];
        for (name, providers, expected) in cases {
            let config = network(Plan::new(path("agent-vm"), inputs(&creds, providers)).unwrap());
            let order: Vec<String> = config
                .secrets
                .secrets
                .iter()
                .map(|entry| entry.env_var.clone())
                .collect();
            assert_eq!(order, expected, "secret order changed for {name}");
        }
        // A non-copilot tool must never register the copilot placeholder.
        for (name, providers, _) in &cases[..4] {
            let config = network(Plan::new(path("agent-vm"), inputs(&creds, *providers)).unwrap());
            assert!(
                config
                    .secrets
                    .secrets
                    .iter()
                    .all(|entry| entry.placeholder != secrets::COPILOT_TOKEN_PLACEHOLDER),
                "copilot leaked into a {name} launch"
            );
        }
    }

    /// D2 (#162): a provider is *provisioned* but was **replaced** by a
    /// same-named YAML authorization, so this launch captured no token for it
    /// (`replaced` suppresses capture; see `secrets.rs`). `credential_injection`
    /// deliberately holds **no second `replaced` gate**: the
    /// `(proxy_secret, creds.token_file(p))` tuple already registers nothing,
    /// and a redundant gate reading the same `replaced` set would only mask a
    /// capture-gate regression.
    ///
    /// So this test pins the *composition*: no `FileSecret` and no OAuth route
    /// for the replaced provider, while the authorization's own header
    /// credential is registered. It is what makes the end-to-end precedence
    /// assertion in `config_launch_driven.rs` meaningful rather than incidental.
    #[test]
    fn a_replaced_provider_registers_no_secret_but_keeps_the_yaml_credential() {
        // Provisioned Anthropic with no token file: exactly the state a
        // same-named authorization leaves behind.
        let creds = CredsState::default();
        let launch = LaunchCredentials::for_test(
            vec![(
                "anthropic",
                vec![crate::credential_yaml::rule_for_test(
                    "api.anthropic.com",
                    443,
                    "x-api-key",
                    "%s",
                )],
            )],
            vec![("ANTHROPIC_API_KEY", EnvDisposition::Sentinel)],
        );
        let config = network(
            Plan::new(
                path("agent-vm"),
                Inputs {
                    creds: &creds,
                    state_dir: Path::new("/state/project"),
                    allowed_repos: &[],
                    provisioned: ProviderSet::new([CredentialProvider::Anthropic]),
                    launch: &launch,
                },
            )
            .unwrap(),
        );
        let env_vars: Vec<&str> = config
            .secrets
            .secrets
            .iter()
            .map(|entry| entry.env_var.as_str())
            .collect();
        assert!(
            !env_vars.contains(&"MSB_AGENT_VM_ANTHROPIC_UNUSED"),
            "a replaced provider must register no substitution entry: {env_vars:?}"
        );
        let route_hosts: Vec<&str> = config
            .intercept
            .rules
            .iter()
            .map(|route| route.host.as_str())
            .collect();
        assert!(
            !route_hosts.contains(&"platform.claude.com"),
            "a replaced provider must register no OAuth route: {route_hosts:?}"
        );
        // The authorization's own credential is registered independently.
        assert_eq!(config.secrets.header_credentials.len(), 1);
        assert_eq!(config.secrets.header_credentials[0].reference, "anthropic");
        assert_eq!(
            config.secrets.header_credentials[0].origin.host,
            "api.anthropic.com"
        );
    }

    /// V14: the hand-written `WIRE_ORDER` array covers every provider exactly
    /// once plus one GitHub slot. A fifth provider that is added to the enum
    /// but forgotten here then fails a test instead of silently vanishing
    /// from the proxy.
    #[test]
    fn wire_order_covers_every_provider_exactly_once() {
        let mut providers = Vec::new();
        let mut github = 0;
        for slot in WIRE_ORDER {
            match slot {
                WireSlot::Provider(provider) => providers.push(provider),
                WireSlot::GithubEgress => github += 1,
            }
        }
        assert_eq!(github, 1, "GithubEgress must appear exactly once");
        for provider in CredentialProvider::ALL {
            assert_eq!(
                providers.iter().filter(|p| **p == provider).count(),
                1,
                "{provider:?} must appear exactly once in WIRE_ORDER"
            );
        }
        assert_eq!(providers.len(), CredentialProvider::ALL.len());
    }

    #[test]
    fn no_credentials_leave_network_unmodified() {
        let plan = Plan::new(
            path("agent-vm"),
            inputs(&CredsState::default(), ProviderSet::default()),
        )
        .unwrap();
        let config = network(plan);
        assert!(config.secrets.secrets.is_empty());
        assert!(!config.intercept.is_active());
        assert_eq!(
            config.tls.enabled,
            NetworkBuilder::new().build().unwrap().tls.enabled
        );
    }

    #[test]
    fn full_mapping_uses_file_sources_exact_hosts_and_expected_routes() {
        let creds = CredsState {
            anthropic_token_file: Some(path("anthropic")),
            openai_token_file: Some(path("openai")),
            opencode_openai_access_token_file: Some(path("openai")),
            gh_token_file: Some(path("gh")),
            copilot_token_file: Some(path("copilot")),
            ..CredsState::default()
        };
        let allowed_repos = vec!["owner/one".to_string(), "owner/two".to_string()];
        let config = network(
            Plan::new(
                path("agent-vm"),
                Inputs {
                    creds: &creds,
                    state_dir: Path::new("/state/project"),
                    allowed_repos: &allowed_repos,
                    provisioned: all(),
                    launch: &LaunchCredentials::default(),
                },
            )
            .unwrap(),
        );
        assert_eq!(config.secrets.secrets.len(), 5);
        for entry in &config.secrets.secrets {
            assert!(entry.value.is_empty());
            assert!(matches!(entry.source, Some(SecretSource::File { .. })));
            assert!(entry.require_tls_identity);
            assert!(entry.on_violation.is_none());
            assert!(
                entry
                    .allowed_hosts
                    .iter()
                    .all(|host| matches!(host, HostPattern::Exact(_)))
            );
            assert!(
                entry.injection.headers && !entry.injection.query_params && !entry.injection.body
            );
        }
        let gh = config
            .secrets
            .secrets
            .iter()
            .find(|entry| entry.placeholder == secrets::GH_TOKEN_PLACEHOLDER)
            .unwrap();
        assert!(gh.injection.basic_auth);
        assert_eq!(config.secrets.on_violation, ViolationAction::BlockAndLog);
        assert!(config.tls.enabled);
        assert_eq!(
            config.intercept.max_request_bytes,
            MAX_BUFFERED_REQUEST_BYTES
        );
        assert_eq!(
            config.intercept.hook.unwrap(),
            vec![
                "/host/agent-vm",
                "_intercept-hook",
                "--state-dir",
                "/state/project",
                "--allowed-repo",
                "owner/one",
                "--allowed-repo",
                "owner/two"
            ]
        );
        assert!(
            config
                .intercept
                .rules
                .iter()
                .any(|route| route.host == secrets::ANTHROPIC_OAUTH_HOST
                    && route.path_prefix == secrets::ANTHROPIC_OAUTH_TOKEN_PATH)
        );
        assert!(
            config
                .intercept
                .rules
                .iter()
                .any(|route| route.host == secrets::GITHUB_HOST
                    && route.method == "POST"
                    && route.dispatch_on_headers)
        );
        assert!(
            config
                .intercept
                .rules
                .iter()
                .filter(|route| route.host == secrets::GITHUB_API_HOST)
                .all(|route| !route.dispatch_on_headers)
        );
    }

    #[test]
    fn opencode_static_rows_have_one_exact_host_and_no_hook_route() {
        let creds = CredsState {
            opencode_api_token_files: secrets::OPENCODE_API_PROVIDERS
                .iter()
                .map(|provider| (*provider, path(&format!("opencode-{}", provider.id))))
                .collect(),
            ..CredsState::default()
        };
        let config =
            network(Plan::new(path("agent-vm"), inputs(&creds, ProviderSet::default())).unwrap());
        assert_eq!(
            config.secrets.secrets.len(),
            secrets::OPENCODE_API_PROVIDERS.len()
        );
        for provider in secrets::OPENCODE_API_PROVIDERS {
            let entry = config
                .secrets
                .secrets
                .iter()
                .find(|entry| entry.placeholder == provider.placeholder)
                .unwrap();
            assert_eq!(entry.env_var, provider.env_var());
            assert!(matches!(
                &entry.source,
                Some(SecretSource::File { path: source_path }) if source_path == &path(&format!("opencode-{}", provider.id))
            ));
            assert_eq!(entry.allowed_hosts.len(), 1);
            assert!(
                matches!(&entry.allowed_hosts[0], HostPattern::Exact(host) if host == provider.host)
            );
            assert!(entry.require_tls_identity);
            assert!(entry.injection.headers);
            assert!(!entry.injection.basic_auth);
            assert!(!entry.injection.query_params && !entry.injection.body);
            assert!(
                config
                    .intercept
                    .rules
                    .iter()
                    .all(|route| route.host != provider.host)
            );
        }
    }

    #[test]
    fn captured_providers_register_only_when_provisioned() {
        let creds = CredsState {
            anthropic_token_file: Some(path("anthropic")),
            copilot_token_file: Some(path("copilot")),
            ..CredsState::default()
        };
        // Nothing provisioned: not even the captured Anthropic token is
        // registered — the capability leak this ticket closes.
        let without =
            network(Plan::new(path("agent-vm"), inputs(&creds, ProviderSet::default())).unwrap());
        assert!(without.secrets.secrets.is_empty());
        assert!(
            without
                .intercept
                .rules
                .iter()
                .all(|route| route.host != secrets::GITHUB_API_HOST)
        );
        let with = network(Plan::new(path("agent-vm"), inputs(&creds, all())).unwrap());
        assert!(
            with.secrets
                .secrets
                .iter()
                .any(|entry| entry.placeholder == secrets::COPILOT_TOKEN_PLACEHOLDER)
        );
        assert!(
            with.secrets
                .secrets
                .iter()
                .any(|entry| entry.placeholder == secrets::ANTHROPIC_ACCESS_PLACEHOLDER)
        );
    }

    #[test]
    fn provisioned_openai_and_opencode_register_their_secrets() {
        let creds = CredsState {
            openai_token_file: Some(path("openai")),
            opencode_openai_access_token_file: Some(path("openai")),
            ..CredsState::default()
        };
        let provisioned = ProviderSet::new([
            CredentialProvider::OpenAi,
            CredentialProvider::OpencodeStatic,
        ]);
        let config = network(Plan::new(path("agent-vm"), inputs(&creds, provisioned)).unwrap());
        assert_eq!(config.secrets.secrets.len(), 2);
        assert!(
            config
                .secrets
                .secrets
                .iter()
                .all(|entry| entry.placeholder != secrets::GH_TOKEN_PLACEHOLDER
                    && entry.placeholder != secrets::COPILOT_TOKEN_PLACEHOLDER)
        );
    }

    #[test]
    fn full_mapping_has_no_cross_provider_hosts_or_routes() {
        let creds = CredsState {
            anthropic_token_file: Some(path("anthropic")),
            openai_token_file: Some(path("openai")),
            opencode_openai_access_token_file: Some(path("openai")),
            gh_token_file: Some(path("gh")),
            copilot_token_file: Some(path("copilot")),
            ..CredsState::default()
        };
        let config = network(Plan::new(path("agent-vm"), inputs(&creds, all())).unwrap());
        let expected = [
            (
                "MSB_AGENT_VM_ANTHROPIC_UNUSED",
                secrets::ANTHROPIC_ACCESS_PLACEHOLDER,
                "/host/anthropic",
                vec![
                    "api.anthropic.com",
                    "platform.claude.com",
                    "mcp-proxy.anthropic.com",
                ],
                false,
            ),
            (
                "MSB_AGENT_VM_OPENAI_UNUSED",
                secrets::OPENAI_ACCESS_PLACEHOLDER,
                "/host/openai",
                vec!["api.openai.com", "chatgpt.com", "auth.openai.com"],
                false,
            ),
            (
                "MSB_AGENT_VM_OPENCODE_OPENAI_UNUSED",
                secrets::OPENCODE_OPENAI_ACCESS_PLACEHOLDER,
                "/host/openai",
                vec!["api.openai.com", "chatgpt.com"],
                false,
            ),
            (
                "MSB_AGENT_VM_GH_UNUSED",
                secrets::GH_TOKEN_PLACEHOLDER,
                "/host/gh",
                vec![
                    "api.github.com",
                    "github.com",
                    "codeload.github.com",
                    "raw.githubusercontent.com",
                    "objects.githubusercontent.com",
                ],
                true,
            ),
            (
                "MSB_AGENT_VM_COPILOT_UNUSED",
                secrets::COPILOT_TOKEN_PLACEHOLDER,
                "/host/copilot",
                vec!["api.githubcopilot.com", "api.individual.githubcopilot.com"],
                false,
            ),
        ];
        for (env_var, placeholder, source_path, hosts, basic_auth) in expected {
            let entry = config
                .secrets
                .secrets
                .iter()
                .find(|entry| entry.env_var == env_var)
                .unwrap();
            assert_eq!(entry.placeholder, placeholder);
            assert_eq!(
                entry.source,
                Some(SecretSource::File {
                    path: PathBuf::from(source_path)
                })
            );
            assert_eq!(entry.injection.basic_auth, basic_auth);
            assert_eq!(
                entry
                    .allowed_hosts
                    .iter()
                    .map(|host| match host {
                        HostPattern::Exact(host) => host.as_str(),
                        _ => panic!("wildcard host"),
                    })
                    .collect::<Vec<_>>(),
                hosts,
            );
        }
        let routes = config
            .intercept
            .rules
            .iter()
            .map(|route| {
                (
                    route.host.as_str(),
                    route.method.as_str(),
                    route.path_prefix.as_str(),
                    route.dispatch_on_headers,
                )
            })
            .collect::<Vec<_>>();
        let mut expected_routes = vec![
            ("platform.claude.com", "POST", "/v1/oauth/token", false),
            ("auth.openai.com", "POST", "/oauth/token", false),
        ];
        expected_routes.extend(
            API_METHODS
                .into_iter()
                .map(|method| ("api.github.com", method, "/", false)),
        );
        for host in [
            "github.com",
            "codeload.github.com",
            "raw.githubusercontent.com",
            "objects.githubusercontent.com",
        ] {
            expected_routes.extend(
                SMART_HTTP_METHODS
                    .into_iter()
                    .map(|method| (host, method, "/", true)),
            );
        }
        assert_eq!(routes, expected_routes);
    }

    #[test]
    fn partial_provider_plans_omit_other_secrets_and_routes() {
        for (creds, provisioned, expected_placeholder, expected_route_host) in [
            (
                CredsState {
                    anthropic_token_file: Some(path("anthropic")),
                    ..CredsState::default()
                },
                ProviderSet::new([CredentialProvider::Anthropic]),
                secrets::ANTHROPIC_ACCESS_PLACEHOLDER,
                Some(secrets::ANTHROPIC_OAUTH_HOST),
            ),
            (
                CredsState {
                    openai_token_file: Some(path("openai")),
                    ..CredsState::default()
                },
                ProviderSet::new([CredentialProvider::OpenAi]),
                secrets::OPENAI_ACCESS_PLACEHOLDER,
                Some(secrets::OPENAI_OAUTH_HOST),
            ),
            (
                CredsState {
                    gh_token_file: Some(path("gh")),
                    ..CredsState::default()
                },
                ProviderSet::default(),
                secrets::GH_TOKEN_PLACEHOLDER,
                Some(secrets::GITHUB_API_HOST),
            ),
        ] {
            let config = network(Plan::new(path("agent-vm"), inputs(&creds, provisioned)).unwrap());
            assert_eq!(config.secrets.secrets.len(), 1);
            assert_eq!(config.secrets.secrets[0].placeholder, expected_placeholder);
            if let Some(host) = expected_route_host {
                assert!(
                    config
                        .intercept
                        .rules
                        .iter()
                        .any(|route| route.host == host)
                );
            }
            for entry in &config.secrets.secrets {
                assert_ne!(entry.placeholder, secrets::COPILOT_TOKEN_PLACEHOLDER);
            }
        }
    }

    #[test]
    fn credential_overlay_preserves_base_network_plan() {
        let creds = CredsState {
            anthropic_token_file: Some(path("anthropic")),
            ..CredsState::default()
        };
        let base_policy = NetworkPolicy::from_profiles([NetworkProfile::Private]);
        let base = NetworkBuilder::new()
            .policy(base_policy.clone())
            .port(8080, 3000)
            .auto_publish();
        let config = Plan::new(
            path("agent-vm"),
            inputs(&creds, ProviderSet::new([CredentialProvider::Anthropic])),
        )
        .unwrap()
        .configure_network(base)
        .expect("a valid base network")
        .build()
        .unwrap();
        assert_eq!(config.ports.len(), 1);
        assert_eq!(config.ports[0].host_port, 8080);
        assert!(config.auto_publish.is_some());
        assert_eq!(config.policy.default_egress, base_policy.default_egress);
        assert_eq!(config.policy.default_ingress, base_policy.default_ingress);
        assert_eq!(config.policy.rules.len(), base_policy.rules.len());
        assert!(config.tls.enabled);
    }

    // -- #161: origin-scoped named-header credentials ---------------------

    /// A YAML-only launch has **no** legacy secrets, so the old `apply_to`
    /// guard (`self.secrets.is_empty()`) returned early and registered nothing.
    /// This exercises `apply_to_network` - the guard `apply_to` actually runs -
    /// so reverting either half of the `secrets && header_credentials` fix
    /// fails here (agent-vm #161 review, M4).
    #[test]
    fn yaml_only_launch_registers_the_credential_and_enables_tls() {
        let launch = LaunchCredentials::for_test(
            vec![(
                "my-service",
                vec![crate::credential_yaml::rule_for_test(
                    "api.my-service.com",
                    8443,
                    "x-api-key",
                    "%s",
                )],
            )],
            vec![("MY_SERVICE_KEY", EnvDisposition::Sentinel)],
        );
        let creds = CredsState::default();
        let config = network(
            Plan::new(
                path("agent-vm"),
                Inputs {
                    creds: &creds,
                    state_dir: Path::new("/state/project"),
                    allowed_repos: &[],
                    provisioned: ProviderSet::default(),
                    launch: &launch,
                },
            )
            .unwrap(),
        );
        // No legacy secret was invented, and injection is independent of
        // `sentinelEnv` (AC2): the header credential registers either way.
        assert!(config.secrets.secrets.is_empty());
        assert_eq!(config.secrets.header_credentials.len(), 1);
        let entry = &config.secrets.header_credentials[0];
        assert_eq!(entry.id, "my-service");
        assert_eq!(entry.reference, "my-service");
        assert_eq!(entry.origin.host, "api.my-service.com");
        assert_eq!(entry.origin.port, 8443);
        assert_eq!(entry.header, "x-api-key");
        assert_eq!(entry.format, "%s");
        // `header_credential` turns TLS interception on itself.
        assert!(config.tls.enabled);
        // Interception is per-port and the runtime now fails closed on an
        // undeclared port, so the credential's port is unioned with the default
        // 443 (which a bare `domain` means and must keep).
        assert_eq!(config.tls.intercepted_ports, vec![443, 8443]);
    }

    /// A 443-only credential must not narrow the default interception set: the
    /// port is already there, so the union is exactly `[443]`.
    #[test]
    fn a_443_only_credential_does_not_narrow_the_default() {
        let launch = LaunchCredentials::for_test(
            vec![(
                "my-service",
                vec![crate::credential_yaml::rule_for_test(
                    "api.my-service.com",
                    443,
                    "authorization",
                    "Bearer %s",
                )],
            )],
            vec![],
        );
        let creds = CredsState::default();
        let config = network(
            Plan::new(
                path("agent-vm"),
                Inputs {
                    creds: &creds,
                    state_dir: Path::new("/state/project"),
                    allowed_repos: &[],
                    provisioned: ProviderSet::default(),
                    launch: &launch,
                },
            )
            .unwrap(),
        );
        assert_eq!(config.tls.intercepted_ports, vec![443]);
    }

    /// The port composition itself: union with the base, never replacement, so
    /// 443 and any caller-configured port survive a credential's own port.
    #[test]
    fn declaring_a_credential_port_unions_with_the_base_ports() {
        let launch = |port: u16| {
            LaunchCredentials::for_test(
                vec![(
                    "my-service",
                    vec![crate::credential_yaml::rule_for_test(
                        "api.my-service.com",
                        port,
                        "x-api-key",
                        "%s",
                    )],
                )],
                vec![],
            )
        };
        // Non-443: the port is added, 443 stays.
        assert_eq!(
            intercepted_ports_with([443], launch(8443).ready()),
            vec![443, 8443]
        );
        // 443-only: no change.
        assert_eq!(
            intercepted_ports_with([443], launch(443).ready()),
            vec![443]
        );
        // A caller's own interception is preserved (union, not replacement).
        assert_eq!(
            intercepted_ports_with([443, 9000], launch(8443).ready()),
            vec![443, 8443, 9000]
        );
        // A credential-free plan adds nothing.
        assert_eq!(intercepted_ports_with([443], &[]), vec![443]);
    }

    /// The composition that actually runs (`apply_to_network`, the path
    /// `apply_to` delegates to): a caller's own intercepted port survives a
    /// credential whose origin is on another port. This is the read the
    /// old `[443]` fallback could erase (agent-vm #161 review, m1).
    #[test]
    fn a_custom_base_intercepted_port_survives_the_credential_overlay() {
        let base = NetworkBuilder::new().tls_overlay(|tls| tls.intercepted_ports(vec![443, 9000]));
        let launch = LaunchCredentials::for_test(
            vec![(
                "my-service",
                vec![crate::credential_yaml::rule_for_test(
                    "api.my-service.com",
                    8443,
                    "x-api-key",
                    "%s",
                )],
            )],
            vec![],
        );
        let creds = CredsState::default();
        let plan = Plan::new(
            path("agent-vm"),
            Inputs {
                creds: &creds,
                state_dir: Path::new("/state/project"),
                allowed_repos: &[],
                provisioned: ProviderSet::default(),
                launch: &launch,
            },
        )
        .unwrap();
        let config = plan
            .apply_to_network(base)
            .expect("a valid base composes")
            .build()
            .unwrap();
        assert_eq!(config.tls.intercepted_ports, vec![443, 8443, 9000]);
    }

    /// The review's latent defect: a base whose `build()` fails (here a header
    /// credential whose TLS was then disabled) must be **refused**, not
    /// repaired by substituting `[443]` - which would have silently dropped the
    /// caller's 9000 (agent-vm #161 review, m1).
    #[test]
    fn an_unbuildable_base_is_refused_rather_than_losing_a_port() {
        let base = NetworkBuilder::new()
            .tls_overlay(|tls| tls.intercepted_ports(vec![443, 9000]))
            .header_credential(|c| {
                c.id("prior")
                    .reference("prior")
                    .origin("prior.example", 443)
                    .header("x-prior")
                    .format("%s")
            })
            .tls_overlay(|tls| tls.enabled(false));
        assert!(
            base.clone().build().is_err(),
            "the fixture base must be unbuildable"
        );
        let launch = LaunchCredentials::for_test(
            vec![(
                "my-service",
                vec![crate::credential_yaml::rule_for_test(
                    "api.my-service.com",
                    8443,
                    "x-api-key",
                    "%s",
                )],
            )],
            vec![],
        );
        let creds = CredsState::default();
        let plan = Plan::new(
            path("agent-vm"),
            Inputs {
                creds: &creds,
                state_dir: Path::new("/state/project"),
                allowed_repos: &[],
                provisioned: ProviderSet::default(),
                launch: &launch,
            },
        )
        .unwrap();
        let error = match plan.apply_to_network(base) {
            Ok(_) => panic!("an unreadable base must be refused"),
            Err(error) => error,
        };
        assert!(
            format!("{error:#}").contains("could not be read"),
            "{error:#}"
        );
    }

    /// Negative control at agent-vm's own boundary: the registration alone,
    /// with no port declaration, is refused by the runtime's fail-closed check.
    /// This is why `configure_network` must declare the ports; without that,
    /// `network()`'s `.build().unwrap()` would panic exactly as this asserts.
    #[test]
    fn an_undeclared_port_is_refused_without_the_declaration() {
        let err = NetworkBuilder::new()
            .header_credential(|c| {
                c.id("my-service")
                    .reference("my-service")
                    .origin("api.my-service.com", 8443)
                    .header("x-api-key")
                    .format("%s")
            })
            .build()
            .unwrap_err();
        assert!(
            matches!(
                err,
                microsandbox_network::policy::BuildError::HeaderCredentialPortNotIntercepted {
                    port: 8443,
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    /// Negative control at the engine's config-level re-validation: a stored or
    /// hand-built config that bypasses `NetworkBuilder::build` is refused for
    /// the same reason, proving the upstream guard agent-vm's ports satisfy is
    /// real rather than assumed.
    #[test]
    fn an_undeclared_port_is_refused_by_the_engine_config_validation() {
        use microsandbox_network::network::{NetworkInitError, SmoltcpNetwork};
        use microsandbox_network::secrets::credential::ResolvedHeaderCredential;
        use microsandbox_types::{DeploymentProfile, DurableHeaderCredential, HttpsOrigin};

        let definition = DurableHeaderCredential {
            id: "my-service".into(),
            reference: "my-service".into(),
            origin: HttpsOrigin {
                host: "api.my-service.example".into(),
                port: 8443,
            },
            header: "x-api-key".into(),
            format: "%s".into(),
        };
        let resolved =
            ResolvedHeaderCredential::from_definition(&definition, "not-a-real-value".to_owned());

        let mut config = microsandbox_network::config::NetworkConfig::default();
        config.tls.enabled = true;
        // 8443 deliberately omitted: this is what an agent-vm launch would look
        // like if it registered the credential without declaring the port.
        config.tls.intercepted_ports = vec![443];
        config.secrets.header_credentials.push(definition);

        let err = match SmoltcpNetwork::new_with_profile_and_credentials(
            config,
            0,
            DeploymentProfile::SingleTenant,
            vec![resolved],
        ) {
            Ok(_) => panic!("an undeclared port must be refused by the engine"),
            Err(err) => err,
        };
        assert!(
            matches!(
                err,
                NetworkInitError::HeaderCredentialPortNotIntercepted { port: 8443, .. }
            ),
            "got {err:?}"
        );
    }

    /// AC2: header injection does not depend on `sentinelEnv`. A credential
    /// whose guest variable must be left unset (`EnvDisposition::Unset`) still
    /// registers its header credential.
    #[test]
    fn header_injection_is_independent_of_sentinel_env() {
        let launch = LaunchCredentials::for_test(
            vec![(
                "my-service",
                vec![crate::credential_yaml::rule_for_test(
                    "api.my-service.com",
                    443,
                    "x-api-key",
                    "%s",
                )],
            )],
            vec![("MY_SERVICE_KEY", EnvDisposition::Unset)],
        );
        let creds = CredsState::default();
        let config = network(
            Plan::new(
                path("agent-vm"),
                Inputs {
                    creds: &creds,
                    state_dir: Path::new("/state/project"),
                    allowed_repos: &[],
                    provisioned: ProviderSet::default(),
                    launch: &launch,
                },
            )
            .unwrap(),
        );
        assert_eq!(config.secrets.header_credentials.len(), 1);
    }

    /// The registration is reference-only: the durable entry has exactly the
    /// five non-secret fields, so no value can be carried by it (Decision 2),
    /// and the serialized config has nowhere to put one. The value-carrying
    /// half - a canary seeded through resolution and rendered out of the
    /// *actual* durable config - is
    /// `credential_resolver::tests::durable_config_carries_the_reference_and_never_a_value`,
    /// where a `CredentialSource` exists to seed it.
    #[test]
    fn header_credential_registration_is_reference_only() {
        let launch = LaunchCredentials::for_test(
            vec![(
                "my-service",
                vec![crate::credential_yaml::rule_for_test(
                    "api.my-service.com",
                    443,
                    "authorization",
                    "Bearer %s",
                )],
            )],
            vec![],
        );
        let creds = CredsState::default();
        let config = network(
            Plan::new(
                path("agent-vm"),
                Inputs {
                    creds: &creds,
                    state_dir: Path::new("/state/project"),
                    allowed_repos: &[],
                    provisioned: ProviderSet::default(),
                    launch: &launch,
                },
            )
            .unwrap(),
        );
        let entry = serde_json::to_value(&config.secrets.header_credentials[0]).unwrap();
        let keys: Vec<&str> = entry
            .as_object()
            .expect("the durable entry is an object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            ["id", "reference", "origin", "header", "format"],
            "the durable entry must have no value-shaped field"
        );
        let rendered = serde_json::to_string(&config).unwrap();
        assert!(rendered.contains("my-service"), "{rendered}");
    }

    /// A credential the file authorizes but this launch does not request
    /// registers nothing (AC8): resolution never puts it in `ready`.
    #[test]
    fn authorized_but_unrequested_credential_registers_nothing() {
        let launch =
            LaunchCredentials::for_test(vec![], vec![("MY_SERVICE_KEY", EnvDisposition::Unset)]);
        let creds = CredsState::default();
        let config = network(
            Plan::new(
                path("agent-vm"),
                Inputs {
                    creds: &creds,
                    state_dir: Path::new("/state/project"),
                    allowed_repos: &[],
                    provisioned: ProviderSet::default(),
                    launch: &launch,
                },
            )
            .unwrap(),
        );
        assert!(config.secrets.header_credentials.is_empty());
        assert!(config.secrets.secrets.is_empty());
    }
}
