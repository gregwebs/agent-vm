use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use microsandbox::sandbox::SandboxBuilder;
use microsandbox_network::builder::NetworkBuilder;

use crate::credential_provider::{self, CredentialProvider, ProviderSet};
use crate::secrets::{self, CredsState};

const MAX_BUFFERED_REQUEST_BYTES: usize = 2 * 1024 * 1024;
const API_METHODS: [&str; 5] = ["GET", "POST", "PATCH", "PUT", "DELETE"];
const SMART_HTTP_METHODS: [&str; 2] = ["GET", "POST"];

pub(crate) struct Inputs<'a> {
    pub creds: &'a CredsState,
    pub state_dir: &'a Path,
    pub allowed_repos: &'a [String],
    pub providers: ProviderSet,
}

/// Registration order for the substituting proxy's secrets. Explicit because
/// GitHub is *not* a [`CredentialProvider`] (it is gated by `--no-git`, not by
/// the launched tool) yet has always been registered between the OpenCode and
/// Copilot entries. Reordering is believed harmless —
/// `secrets::placeholders_are_pairwise_distinct` proves no placeholder is a
/// substring of another, so substitution cannot pick the wrong secret — but
/// this is a prefactor, so the wire order stays byte-identical and is asserted
/// by `proxy_plan_matches_legacy_for_each_agent`.
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
                    if credential_provider::proxy_requires_selection(provider)
                        && !inputs.providers.contains(provider)
                    {
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
            hook_argv,
            routes,
        })
    }

    pub(crate) fn apply_to(self, builder: SandboxBuilder) -> SandboxBuilder {
        if self.secrets.is_empty() {
            return builder;
        }
        builder.network(move |network| self.configure_network(network))
    }

    fn configure_network(self, mut network: NetworkBuilder) -> NetworkBuilder {
        if self.secrets.is_empty() {
            return network;
        }
        network = network.tls_overlay(|tls| tls.enabled(true));
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
        network
    }
}

fn utf8_path(path: &Path, label: &str) -> Result<String> {
    path.to_str()
        .map(ToOwned::to_owned)
        .with_context(|| format!("{label} must be valid UTF-8: {}", path.display()))
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

    fn path(name: &str) -> PathBuf {
        PathBuf::from(format!("/host/{name}"))
    }
    fn inputs(creds: &CredsState, providers: ProviderSet) -> Inputs<'_> {
        Inputs {
            creds,
            state_dir: Path::new("/state/project"),
            allowed_repos: &[],
            providers,
        }
    }

    /// Select every compiled-in provider (the "all secrets present" case).
    fn all() -> ProviderSet {
        ProviderSet::new(CredentialProvider::ALL)
    }
    fn network(plan: Plan) -> microsandbox_network::config::NetworkConfig {
        plan.configure_network(NetworkBuilder::new())
            .build()
            .unwrap()
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

    /// V6: per-tool secret order. With every token file present, the
    /// *legacy asymmetry* shows: anthropic/openai/opencode-openai/gh are
    /// registered for **every** tool (only Copilot requires selection). The
    /// order is fixed by `WIRE_ORDER`, with `gh` spliced between the OpenCode
    /// and Copilot entries.
    #[test]
    fn proxy_plan_matches_legacy_for_each_agent() {
        let creds = CredsState {
            anthropic_token_file: Some(path("anthropic")),
            openai_token_file: Some(path("openai")),
            opencode_openai_access_token_file: Some(path("openai")),
            gh_token_file: Some(path("gh")),
            copilot_token_file: Some(path("copilot")),
            ..CredsState::default()
        };
        let base = [
            "MSB_AGENT_VM_ANTHROPIC_UNUSED",
            "MSB_AGENT_VM_OPENAI_UNUSED",
            "MSB_AGENT_VM_OPENCODE_OPENAI_UNUSED",
            "MSB_AGENT_VM_GH_UNUSED",
        ];
        let opencode = ProviderSet::new([
            CredentialProvider::OpenAi,
            CredentialProvider::OpencodeStatic,
        ]);
        let cases: [(&str, ProviderSet, &[&str]); 5] = [
            (
                "claude",
                ProviderSet::new([CredentialProvider::Anthropic]),
                &base,
            ),
            (
                "codex",
                ProviderSet::new([CredentialProvider::OpenAi]),
                &base,
            ),
            ("opencode", opencode, &base),
            ("shell", opencode, &base),
            (
                "copilot",
                ProviderSet::new([CredentialProvider::Copilot]),
                &[
                    "MSB_AGENT_VM_ANTHROPIC_UNUSED",
                    "MSB_AGENT_VM_OPENAI_UNUSED",
                    "MSB_AGENT_VM_OPENCODE_OPENAI_UNUSED",
                    "MSB_AGENT_VM_GH_UNUSED",
                    "MSB_AGENT_VM_COPILOT_UNUSED",
                ],
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
                    providers: all(),
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
    fn copilot_requires_selected_agent_and_partial_credentials_do_not_cross_configure() {
        let creds = CredsState {
            anthropic_token_file: Some(path("anthropic")),
            copilot_token_file: Some(path("copilot")),
            ..CredsState::default()
        };
        let without =
            network(Plan::new(path("agent-vm"), inputs(&creds, ProviderSet::default())).unwrap());
        assert_eq!(without.secrets.secrets.len(), 1);
        assert_eq!(
            without.secrets.secrets[0].placeholder,
            secrets::ANTHROPIC_ACCESS_PLACEHOLDER
        );
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
    }

    #[test]
    fn shell_no_git_still_injects_available_provider_credentials() {
        let creds = CredsState {
            openai_token_file: Some(path("openai")),
            opencode_openai_access_token_file: Some(path("openai")),
            ..CredsState::default()
        };
        let config =
            network(Plan::new(path("agent-vm"), inputs(&creds, ProviderSet::default())).unwrap());
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
        for (creds, expected_placeholder, expected_route_host) in [
            (
                CredsState {
                    anthropic_token_file: Some(path("anthropic")),
                    ..CredsState::default()
                },
                secrets::ANTHROPIC_ACCESS_PLACEHOLDER,
                Some(secrets::ANTHROPIC_OAUTH_HOST),
            ),
            (
                CredsState {
                    openai_token_file: Some(path("openai")),
                    ..CredsState::default()
                },
                secrets::OPENAI_ACCESS_PLACEHOLDER,
                Some(secrets::OPENAI_OAUTH_HOST),
            ),
            (
                CredsState {
                    gh_token_file: Some(path("gh")),
                    ..CredsState::default()
                },
                secrets::GH_TOKEN_PLACEHOLDER,
                Some(secrets::GITHUB_API_HOST),
            ),
        ] {
            let config = network(
                Plan::new(path("agent-vm"), inputs(&creds, ProviderSet::default())).unwrap(),
            );
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
        let config = Plan::new(path("agent-vm"), inputs(&creds, ProviderSet::default()))
            .unwrap()
            .configure_network(base)
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
}
