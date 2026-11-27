//! One-time lowering from a selected target to shared launch inputs.
//!
//! The grant is a private snapshot adapter, not credential authorization: the
//! credential resolver and network policy retain those decisions.
use std::collections::{BTreeMap, BTreeSet};

use crate::config::{CatalogEntry, PersistPath};
use crate::config_mounts::ResolvedMountList;
use crate::credential_provider::ProviderSet;
use crate::credential_resolver::{RequestProvenance, RequestedServices};
use crate::network_requests::{NetworkRequests, RequestTier};
use crate::secret_store::ServiceName;

pub(crate) enum LaunchTarget {
    /// A direct command with the I/O mode dispatch already resolved for it, and
    /// the grant a *direct* command carries: the authored `default_tools` closure
    /// and nothing else (#749 E5). Empty unless a file wrote the key.
    ///
    /// The mode is a facet of *this* target, never of the grant: a direct launch
    /// has no catalog authority, and a tool launch has no terminal policy.
    Direct {
        command: DirectCommand,
        terminal: crate::direct_terminal::DirectIo,
        grant: CatalogGrant,
    },
    Tool {
        entry: Box<CatalogEntry>,
        tool_args: Vec<String>,
    },
}

impl LaunchTarget {
    /// Every named YAML service this launch requests, with its provenance, on
    /// either route.
    ///
    /// A direct command has no catalog entry to read them from, so it carries
    /// the **authored** defaults' requests (#749 E5): `provisioned` speaks only
    /// for the built-in providers, and a `default_tools` contributor's named
    /// service reaches `credentials.yaml` through this set or not at all.
    pub(crate) fn requested_services(&self) -> RequestedServices {
        match self {
            Self::Tool { entry, .. } => {
                // Only the launched tool's own `credentials` are *selected*: its
                // own local `tools` closure and the effective `default_tools`
                // add provisioning, never a hard bail (#749 E6).
                let own = entry.tool().credential_names();
                entry
                    .requested_names()
                    .iter()
                    .cloned()
                    .map(|service| {
                        let provenance = if own.contains(&service) {
                            RequestProvenance::Selected
                        } else {
                            RequestProvenance::Inherited
                        };
                        (service, provenance)
                    })
                    .collect()
            }
            Self::Direct { grant, .. } => grant.requested_services(),
        }
    }

    pub(crate) fn is_direct(&self) -> bool {
        matches!(self, Self::Direct { .. })
    }

    pub(crate) fn into_parts(self) -> (CatalogGrant, GuestInvocation) {
        match self {
            Self::Direct {
                command,
                terminal,
                grant,
            } => {
                let invocation = GuestInvocation {
                    display: crate::config::escape_str(command.program()),
                    program: command.program,
                    argv: command.args,
                    guard: ProgramGuard::Direct,
                    direct_io: Some(terminal),
                };
                (grant, invocation)
            }
            Self::Tool { entry, tool_args } => {
                let tool = entry.tool();
                let grant = CatalogGrant {
                    provisioned: entry.provisioned(),
                    // Only a *directly selected* tool's own requirement may stop
                    // a launch: a grant inherited from `default_tools` adds
                    // provisioning, never a hard bail (#749 E6).
                    required: tool.credential_providers(),
                    // A tool launch reads its requests from the entry, which
                    // folded them over its own closure and the defaults.
                    requested_names: BTreeSet::new(),
                    persist: entry.persist().to_vec(),
                    // The entry's own folded facet, borrowed as a shared handle:
                    // lowering must not re-resolve, re-parse or copy declarations.
                    mounts: entry.mounts().clone(),
                    // The entry's folded env: the tool's own, plus whatever the
                    // effective `default_tools` closure brings (#749).
                    guest_env: entry.guest_env().clone(),
                    // #735: authorization is what makes a tool's own
                    // `network_requests` authoritative egress. The compiled-in
                    // defaults keep ADR-0039's non-authoritative report.
                    // The folded requests, for the same reason as `guest_env`:
                    // a built-in contributor's stay report-only, so the shipped
                    // list grants no egress request on its own (#749 E5).
                    tool_egress: Some(if entry.is_authorized_egress() {
                        ToolEgress::Authorized {
                            tool_name: tool.name().to_owned(),
                            requests: entry.network_requests().clone(),
                        }
                    } else {
                        ToolEgress::UnmetOnly {
                            tier: RequestTier::from(tool.origin()),
                            requests: entry.network_requests().clone(),
                        }
                    }),
                };
                let invocation = GuestInvocation {
                    program: tool.command().to_owned(),
                    display: tool.command().to_owned(),
                    argv: crate::run::inner_argv(tool, tool_args),
                    guard: ProgramGuard::ImageContract,
                    // A tool launch keeps the legacy stdin-only predicate; only a
                    // direct command carries a resolved terminal mode.
                    direct_io: None,
                };
                (grant, invocation)
            }
        }
    }
}

/// What a launched tool's own `network_requests` are, per #735's two cases.
///
/// The distinction is authority, not shape: an **authorized** tool's requests are
/// granted as exact `tcp://HOST:PORT` allowances on this launch, while a
/// compiled-in default's stay metadata under ADR-0036 default-deny and the
/// ADR-0039 unmet report. A named enum rather than a boolean beside the requests,
/// so a call site cannot grant without knowing which case it is in.
pub(crate) enum ToolEgress {
    /// A configuration file declared it, so its own
    /// `network_requests` become hostname allowances for this launch.
    Authorized {
        tool_name: String,
        requests: NetworkRequests,
    },
    /// Compiled-in defaults: non-authoritative, reported as unmet.
    UnmetOnly {
        tier: RequestTier,
        requests: NetworkRequests,
    },
}

impl ToolEgress {
    /// The authorized form, as the egress authority's borrowed view.
    pub(crate) fn authorized(&self) -> Option<crate::egress_policy::AuthorizedToolEgress<'_>> {
        match self {
            Self::Authorized {
                tool_name,
                requests,
            } => Some(crate::egress_policy::AuthorizedToolEgress {
                tool_name,
                requests,
            }),
            Self::UnmetOnly { .. } => None,
        }
    }

    /// The ADR-0039 report's inputs, for the non-authoritative case only.
    pub(crate) fn unmet(&self) -> Option<(&NetworkRequests, RequestTier)> {
        match self {
            Self::Authorized { .. } => None,
            Self::UnmetOnly { tier, requests } => Some((requests, *tier)),
        }
    }
}

/// Only the catalog facts already consumed by the shared launch pipeline.
pub(crate) struct CatalogGrant {
    provisioned: ProviderSet,
    required: ProviderSet,
    /// The named YAML services this grant's closure requests. Empty for a tool
    /// launch, whose entry carries them (see [`LaunchTarget::requested_names`]).
    requested_names: BTreeSet<ServiceName>,
    persist: Vec<PersistPath>,
    /// The selected entry's config mount declarations, own plus inherited. Empty
    /// for a direct launch, which still receives user-wide defaults and explicit
    /// `--mount` selections from the shared pipeline.
    mounts: ResolvedMountList,
    guest_env: BTreeMap<String, String>,
    tool_egress: Option<ToolEgress>,
}

impl CatalogGrant {
    fn none() -> Self {
        Self {
            provisioned: ProviderSet::default(),
            required: ProviderSet::default(),
            requested_names: BTreeSet::new(),
            persist: Vec::new(),
            mounts: ResolvedMountList::empty(),
            guest_env: BTreeMap::new(),
            tool_egress: None,
        }
    }

    /// A direct command's grant: the **authored** `default_tools` closure and
    /// nothing else (#749 E5).
    ///
    /// `required` stays empty on purpose: an inherited default's missing login
    /// leaves that helper unavailable, never the command fatal (E6). The egress
    /// request set is the closure's *declared* contributors', so a built-in one
    /// still grants nothing.
    ///
    /// The contributors must pass the same verified-read verdict the shell route
    /// requires before it launches (#749 E8/E10): a grant built from a read that
    /// refused cannot be built here either, so both routes share one rule.
    pub(crate) fn from_defaults(defaults: &crate::config::DefaultFacets) -> anyhow::Result<Self> {
        if let Some(trust) = defaults.refusal() {
            trust.require_for_trusted_tool().map_err(|refusal| {
                anyhow::anyhow!(
                    "config: {}: {refusal}",
                    crate::one_line::quoted_path(trust.file())
                )
            })?;
        }
        if defaults.is_empty() {
            // No file wrote `default_tools`: a direct command provisions nothing,
            // exactly as it did before the field existed (ADR-0017, E5).
            return Ok(Self::none());
        }
        let tool_egress =
            (!defaults.network_requests().is_empty()).then(|| ToolEgress::Authorized {
                tool_name: crate::launch_target::DIRECT_RUN_VERB.to_owned(),
                requests: defaults.network_requests().clone(),
            });
        Ok(Self {
            provisioned: defaults.provisioned(),
            required: ProviderSet::default(),
            requested_names: defaults.requested_names().clone(),
            persist: defaults.persist().to_vec(),
            mounts: defaults.mounts().clone(),
            guest_env: defaults.guest_env().clone(),
            tool_egress,
        })
    }
    pub(crate) fn provisioned(&self) -> ProviderSet {
        self.provisioned
    }
    pub(crate) fn required(&self) -> ProviderSet {
        self.required
    }
    /// A direct command has no directly selected tool, so every authored
    /// default's request is inherited: none of them may stop the command (#749
    /// E6).
    pub(crate) fn requested_services(&self) -> RequestedServices {
        self.requested_names
            .iter()
            .cloned()
            .map(|service| (service, RequestProvenance::Inherited))
            .collect()
    }
    pub(crate) fn persist(&self) -> &[PersistPath] {
        &self.persist
    }
    pub(crate) fn mounts(&self) -> &ResolvedMountList {
        &self.mounts
    }
    pub(crate) fn guest_env(&self) -> &BTreeMap<String, String> {
        &self.guest_env
    }
    pub(crate) fn tool_egress(&self) -> Option<&ToolEgress> {
        self.tool_egress.as_ref()
    }

    /// The authorized-tool view the egress plan takes: `None` for a direct launch
    /// and for the compiled-in defaults.
    pub(crate) fn authorized_tool_egress(
        &self,
    ) -> Option<crate::egress_policy::AuthorizedToolEgress<'_>> {
        self.tool_egress.as_ref().and_then(ToolEgress::authorized)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProgramGuard {
    Direct,
    ImageContract,
}

pub(crate) struct GuestInvocation {
    program: String,
    display: String,
    argv: Vec<String>,
    guard: ProgramGuard,
    /// `Some` only for a direct launch, whose I/O mode was resolved before any
    /// runtime setup. `None` means "keep the legacy selection".
    direct_io: Option<crate::direct_terminal::DirectIo>,
}

impl GuestInvocation {
    pub(crate) fn program(&self) -> &str {
        &self.program
    }
    pub(crate) fn display(&self) -> &str {
        &self.display
    }
    pub(crate) fn argv(&self) -> &[String] {
        &self.argv
    }
    pub(crate) fn guard(&self) -> ProgramGuard {
        self.guard
    }
    pub(crate) fn direct_io(&self) -> Option<crate::direct_terminal::DirectIo> {
        self.direct_io
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_command_validates_without_replacing_bytes() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        assert_eq!(
            DirectCommand::from_os_args(vec![]),
            Err(DirectCommandError::MissingProgram)
        );
        assert_eq!(
            DirectCommand::from_os_args(vec!["".into(), OsString::from_vec(vec![255])]),
            Err(DirectCommandError::EmptyProgram)
        );
        for position in 0..3 {
            let mut vector = vec!["p".into(), "".into(), "日本語".into()];
            vector[position] = OsString::from_vec(vec![255]);
            let error = DirectCommand::from_os_args(vector).unwrap_err();
            assert_eq!(error, DirectCommandError::NonUnicode { position });
            assert!(!error.to_string().contains('\u{fffd}'));
            assert!(!error.to_string().contains("255"));
        }
        let command = DirectCommand::from_os_args(vec![
            "日本語".into(),
            "".into(),
            "x".into(),
            "x".into(),
            "--".into(),
        ])
        .unwrap();
        assert_eq!(command.program(), "日本語");
        assert_eq!(command.args, ["", "x", "x", "--"]);
    }

    #[test]
    fn direct_lowering_has_no_catalog_inputs_or_defaults() {
        let command =
            DirectCommand::from_os_args(vec!["claude".into(), "x".into(), "x".into(), "".into()])
                .unwrap();
        let target = LaunchTarget::Direct {
            command,
            terminal: crate::direct_terminal::DirectIo::Pty,
            grant: CatalogGrant::none(),
        };
        assert!(target.requested_services().is_empty());
        assert!(target.is_direct());
        let (grant, invocation) = target.into_parts();
        assert_eq!(grant.provisioned().iter().count(), 0);
        assert_eq!(grant.required().iter().count(), 0);
        assert!(grant.persist().is_empty());
        assert!(grant.mounts().is_empty());
        assert!(grant.guest_env().is_empty());
        assert!(grant.tool_egress().is_none());
        assert_eq!(invocation.program(), "claude");
        assert_eq!(invocation.argv(), ["x", "x", ""]);
        assert_eq!(invocation.guard(), ProgramGuard::Direct);
        let catalog = crate::config::default_launch_catalog().unwrap();
        let tool = catalog
            .as_slice()
            .iter()
            .find(|entry| entry.tool().name() == "claude")
            .unwrap()
            .tool();
        assert_eq!(
            crate::run::inner_argv(tool, vec!["x".into()]),
            ["--dangerously-skip-permissions", "x"]
        );
    }
    /// A mount-bearing loaded config, built through the real verified read (the
    /// directory and file modes are what the authority check measures) so lowering
    /// is exercised on a facet the shipped catalog cannot supply.
    fn loaded_catalog(body: &str) -> crate::config::LaunchCatalog {
        use std::os::unix::fs::PermissionsExt;
        let user_dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(user_dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let user = user_dir.path().join("config.toml");
        std::fs::write(&user, body).unwrap();
        std::fs::set_permissions(&user, std::fs::Permissions::from_mode(0o600)).unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        let report = crate::config::load(&crate::config::ConfigPaths::for_test(
            Some(user),
            project_dir.path().join("config.toml"),
        ))
        .unwrap();
        report.into_launch_catalog().unwrap()
    }

    /// The mount facet survives lowering as a shared handle, and a direct launch's
    /// grant stays empty while still receiving the user-wide defaults and explicit
    /// `--mount` selections from the shared pipeline.
    #[test]
    fn tool_lowering_carries_mount_facet_and_direct_is_empty() {
        let mut catalog = loaded_catalog(
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\ntools = [\"u\"]\n\
             mounts = [\"/a:/a:ro\"]\n\
             [[tools]]\nname = \"u\"\ncommand = \"u\"\nmounts = [\"/b:/b:fork\"]\n",
        );
        let entry = catalog.take_entry("t").unwrap();
        let expected = entry.mounts().clone();
        assert!(!expected.is_empty());
        let (grant, _) = LaunchTarget::Tool {
            entry: Box::new(entry),
            tool_args: Vec::new(),
        }
        .into_parts();
        assert_eq!(grant.mounts(), &expected);
        // Both the own and the inherited declaration are present, in arena order.
        let guests: Vec<String> = grant
            .mounts()
            .requests()
            .map(|request| request.mount.guest.display().to_string())
            .collect();
        assert_eq!(guests, ["/a", "/b"]);

        // A direct launch has no catalog inputs of any kind; its defaults and
        // `--mount`s arrive from selection, not from the grant.
        let command = DirectCommand::from_os_args(vec!["t".into(), "x".into()]).expect("a program");
        let (grant, invocation) = LaunchTarget::Direct {
            command,
            terminal: crate::direct_terminal::DirectIo::Stream,
            grant: CatalogGrant::none(),
        }
        .into_parts();
        assert!(grant.mounts().is_empty());
        assert_eq!(
            invocation.direct_io(),
            Some(crate::direct_terminal::DirectIo::Stream),
            "lowering must carry the resolved mode, not default it"
        );
    }

    /// Both resolved direct modes survive lowering exactly, with no catalog
    /// authority attached, and neither is reconstructed from the program guard.
    #[test]
    fn both_direct_modes_survive_lowering() {
        use crate::direct_terminal::DirectIo;
        for (mode, argv) in [
            (DirectIo::Pty, vec!["x", ""]),
            (DirectIo::Stream, vec!["--tty", "-T"]),
        ] {
            let command = DirectCommand::from_os_args(
                std::iter::once("日本語".to_string())
                    .chain(argv.iter().map(|value| value.to_string()))
                    .map(Into::into)
                    .collect(),
            )
            .unwrap();
            let (grant, invocation) = LaunchTarget::Direct {
                command,
                terminal: mode,
                grant: CatalogGrant::none(),
            }
            .into_parts();
            assert_eq!(invocation.direct_io(), Some(mode));
            assert_eq!(invocation.guard(), ProgramGuard::Direct);
            assert_eq!(invocation.program(), "日本語");
            assert_eq!(
                invocation.argv(),
                argv.iter().map(|v| v.to_string()).collect::<Vec<_>>(),
                "argv stays literal: a suffix terminal flag is the guest's argument"
            );
            assert_eq!(grant.provisioned().iter().count(), 0);
            assert!(grant.tool_egress().is_none());
            assert!(grant.guest_env().is_empty());
        }
    }

    #[test]
    fn tool_lowering_preserves_catalog_inputs() {
        let mut catalog = crate::config::default_launch_catalog().unwrap();
        let names: Vec<_> = catalog
            .as_slice()
            .iter()
            .map(|entry| entry.tool().name().to_owned())
            .collect();
        for name in names {
            let entry = catalog.take_entry(&name).unwrap();
            let tool = entry.tool();
            let provisioned = entry.provisioned();
            let required = tool.credential_providers();
            let persist = entry.persist().to_vec();
            let mounts = entry.mounts().clone();
            let env = entry.guest_env().clone();
            let requests = entry.network_requests().clone();
            let tier = RequestTier::from(tool.origin());
            let command = tool.command().to_owned();
            let argv = crate::run::inner_argv(tool, vec!["x".into(), "x".into()]);
            let names = entry.requested_names().clone();
            let target = LaunchTarget::Tool {
                entry: Box::new(entry),
                tool_args: vec!["x".into(), "x".into()],
            };
            assert_eq!(
                target
                    .requested_services()
                    .names()
                    .cloned()
                    .collect::<BTreeSet<_>>(),
                names
            );
            let (grant, invocation) = target.into_parts();
            assert_eq!(grant.provisioned(), provisioned);
            assert_eq!(grant.required(), required);
            assert_eq!(grant.persist(), persist);
            assert_eq!(grant.mounts(), &mounts);
            assert_eq!(grant.guest_env(), &env);
            // The shipped catalog is the compiled-in defaults, so its requests
            // stay non-authoritative metadata (ADR-0036/ADR-0039).
            let ToolEgress::UnmetOnly {
                requests: granted,
                tier: granted_tier,
            } = grant.tool_egress().expect("shipped tools declare requests")
            else {
                panic!("a compiled-in default must never be authorized egress")
            };
            assert_eq!(*granted, requests);
            assert_eq!(*granted_tier, tier);
            assert_eq!(invocation.program(), command);
            assert_eq!(invocation.argv(), argv);
            assert_eq!(invocation.guard(), ProgramGuard::ImageContract);
            assert_eq!(
                invocation.direct_io(),
                None,
                "a catalog launch carries no terminal mode; its selection stays legacy"
            );
        }
    }

    /// V25(e), R5: lowering an authorized **source** entry carries every one of
    /// its own and closure facets, and its requests arrive as `Authorized` egress
    /// rather than the ADR-0039 metadata a compiled-in default keeps.
    #[test]
    fn authorized_source_entry_lowers_every_own_and_closure_facet() {
        use crate::credential_provider::CredentialProvider;
        use std::os::unix::fs::PermissionsExt;
        // The project store and a checkout, the shape ADR-0073/ADR-0074 require.
        let root = tempfile::tempdir().unwrap();
        let base = root.path().canonicalize().unwrap();
        let home = base.join("home");
        let checkout = base.join("checkout");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&checkout).unwrap();
        std::fs::create_dir_all(checkout.join(".agent-vm")).unwrap();
        let project =
            crate::project::ProjectDir::from_path_for_tests(&checkout).expect("a project root");
        let config = crate::project_config::path(&home, &project);
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        std::fs::set_permissions(
            config.parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::write(
            checkout.join(".agent-vm/config.toml"),
            "[[tools]]\nname = \"app\"\ncommand = \"/bin/echo\"\nargs = [\"--own-arg\"]\n\
             env = { APP_OWN = \"own-sentinel\" }\ncredentials = [\"openai\"]\n\
             persist = [\".app-own\"]\nmounts = [\"/app:/app:ro\"]\n\
             network_requests = [\"app.example\", \"app.example:8443\"]\ntools = [\"helper\"]\n\
             [[tools]]\nname = \"helper\"\ncommand = \"/bin/echo\"\n\
             env = { HELPER_ENV = \"helper-sentinel\" }\ncredentials = [\"anthropic\"]\n\
             persist = [\".helper\"]\nmounts = [\"/helper:/helper:ro\"]\n\
             network_requests = [\"helper.example\"]\ntools = []\n",
        )
        .unwrap();
        std::fs::write(
            &config,
            "\
             [[sources]]\nname = \"repo\"\npath = \"./.agent-vm/config.toml\"\n",
        )
        .unwrap();
        let paths = crate::config::ConfigPaths::for_test_captured(home.clone(), &project);
        crate::config::approve_all_pinned(&paths);
        let report = crate::config::load(&paths).expect("the project config loads");
        let mut catalog = report.into_launch_catalog().expect("catalog");
        let entry = catalog.take_entry("app").expect("app is a verb");
        let tool_args = vec!["x".to_owned(), "y".to_owned()];
        let expected_argv = crate::run::inner_argv(entry.tool(), tool_args.clone());
        let target = LaunchTarget::Tool {
            entry: Box::new(entry),
            tool_args: tool_args.clone(),
        };
        let (grant, invocation) = target.into_parts();
        assert_eq!(
            grant.provisioned().iter().collect::<Vec<_>>(),
            [CredentialProvider::Anthropic, CredentialProvider::OpenAi],
            "the closure's providers, in fold order"
        );
        assert_eq!(
            grant.required().iter().collect::<Vec<_>>(),
            [CredentialProvider::OpenAi]
        );
        assert_eq!(
            grant
                .persist()
                .iter()
                .map(|path| path.as_path().display().to_string())
                .collect::<Vec<_>>(),
            [".app-own", ".helper"]
        );
        assert_eq!(
            grant
                .mounts()
                .requests()
                .map(|request| request.mount.guest.display().to_string())
                .collect::<Vec<_>>(),
            ["/app", "/helper"]
        );
        assert_eq!(
            grant
                .guest_env()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["APP_OWN", "HELPER_ENV"],
            "the launch's own env first, then its referenced helper's (#749 AC2)"
        );
        let ToolEgress::Authorized {
            tool_name,
            requests,
        } = grant.tool_egress().expect("an authorized tool has egress")
        else {
            panic!("a source authorization must lower as Authorized")
        };
        assert_eq!(tool_name, "app");
        assert_eq!(
            requests.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["app.example", "tcp://app.example:8443", "helper.example"],
            "the closed fold, not the launched definition's own list"
        );
        assert_eq!(invocation.program(), "/bin/echo");
        assert_eq!(invocation.argv(), expected_argv);
        assert_eq!(invocation.argv(), ["--own-arg", "x", "y"]);
        assert_eq!(invocation.guard(), ProgramGuard::ImageContract);
        // A direct launch of the same program carries no tool egress at all.
        let command =
            DirectCommand::from_os_args(vec!["/bin/echo".into(), "x".into()]).expect("a program");
        let (grant, _) = LaunchTarget::Direct {
            command,
            terminal: crate::direct_terminal::DirectIo::Stream,
            grant: CatalogGrant::none(),
        }
        .into_parts();
        assert!(grant.tool_egress().is_none());
    }
}

/// The direct runner's verb. Reserved in every config tier, registered as a
/// subcommand on both catalog paths, and never a catalog entry.
pub(crate) const DIRECT_RUN_VERB: &str = "run";

/// The status of a direct launch's ordinary returned failure. It does not cover
/// aborts, signals or panics, and it never overrides a guest's own status.
pub(crate) const DIRECT_LAUNCHER_FAILURE_EXIT: i32 = 125;
pub(crate) const DIRECT_NOT_EXECUTABLE_EXIT: u8 = 126;
pub(crate) const DIRECT_NOT_FOUND_EXIT: u8 = 127;

/// A deferred direct-launch configuration failure. Ordinary direct errors are
/// 125 (issue #398); this marker carries a *broken catalog* through the parse
/// without clap's "unrecognized subcommand" noise, and main maps it to 125.
#[derive(Debug)]
pub(crate) struct DirectLaunchFailure(pub(crate) anyhow::Error);
impl std::fmt::Display for DirectLaunchFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#}", self.0)
    }
}
impl std::error::Error for DirectLaunchFailure {}

/// Unicode argv only; error text never includes rejected bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirectCommand {
    program: String,
    args: Vec<String>,
}
impl DirectCommand {
    pub(crate) fn from_os_args(
        vector: Vec<std::ffi::OsString>,
    ) -> Result<Self, DirectCommandError> {
        let Some(first) = vector.first() else {
            return Err(DirectCommandError::MissingProgram);
        };
        if first.is_empty() {
            return Err(DirectCommandError::EmptyProgram);
        }
        let mut vector = vector.into_iter().enumerate().map(|(position, value)| {
            value
                .into_string()
                .map_err(|_| DirectCommandError::NonUnicode { position })
        });
        let program = vector.next().ok_or(DirectCommandError::MissingProgram)??;
        let args = vector.collect::<Result<_, _>>()?;
        Ok(Self { program, args })
    }
    pub(crate) fn program(&self) -> &str {
        &self.program
    }
    #[cfg(test)]
    pub(crate) fn args(&self) -> &[String] {
        &self.args
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DirectCommandError {
    MissingProgram,
    EmptyProgram,
    NonUnicode { position: usize },
}
impl std::fmt::Display for DirectCommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingProgram => {
                f.write_str("a program is required: agent-vm [launch options] run PROGRAM [ARG]...")
            }
            Self::EmptyProgram => f.write_str("the program name (PROGRAM) must not be empty"),
            Self::NonUnicode { position } => {
                if *position == 0 {
                    f.write_str("the program name is not valid UTF-8")?;
                } else {
                    write!(f, "argument {position} is not valid UTF-8")?;
                }
                f.write_str(
                    "; direct commands accept Unicode only, without replacement of invalid bytes",
                )
            }
        }
    }
}
impl std::error::Error for DirectCommandError {}
