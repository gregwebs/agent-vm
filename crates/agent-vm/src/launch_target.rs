//! One-time lowering from a selected target to shared launch inputs.
//!
//! The grant is a private snapshot adapter, not credential authorization: the
//! credential resolver and network policy retain those decisions.
use std::collections::{BTreeMap, BTreeSet};

use crate::config::{CatalogEntry, PersistPath};
use crate::credential_provider::ProviderSet;
use crate::network_requests::{NetworkRequests, RequestTier};
use crate::secret_store::ServiceName;

pub(crate) enum LaunchTarget {
    Direct(DirectCommand),
    Tool {
        entry: Box<CatalogEntry>,
        tool_args: Vec<String>,
    },
}

impl LaunchTarget {
    pub(crate) fn requested_names(&self) -> &BTreeSet<ServiceName> {
        match self {
            Self::Tool { entry, .. } => entry.requested_names(),
            Self::Direct(_) => {
                static EMPTY: std::sync::LazyLock<BTreeSet<ServiceName>> =
                    std::sync::LazyLock::new(BTreeSet::new);
                &EMPTY
            }
        }
    }

    pub(crate) fn is_direct(&self) -> bool {
        matches!(self, Self::Direct(_))
    }

    pub(crate) fn into_parts(self) -> (CatalogGrant, GuestInvocation) {
        match self {
            Self::Direct(command) => {
                let invocation = GuestInvocation {
                    display: crate::config::escape_str(command.program()),
                    program: command.program,
                    argv: command.args,
                    guard: ProgramGuard::Direct,
                };
                (CatalogGrant::none(), invocation)
            }
            Self::Tool { entry, tool_args } => {
                let tool = entry.tool();
                let grant = CatalogGrant {
                    provisioned: entry.provisioned(),
                    required: tool.credential_providers(),
                    persist: entry.persist().to_vec(),
                    guest_env: tool.guest_env().clone(),
                    requests: Some(DeclaredRequests {
                        requests: tool.network_requests().clone(),
                        tier: RequestTier::from(tool.origin()),
                    }),
                };
                let invocation = GuestInvocation {
                    program: tool.command().to_owned(),
                    display: tool.command().to_owned(),
                    argv: crate::run::inner_argv(tool, tool_args),
                    guard: ProgramGuard::ImageContract,
                };
                (grant, invocation)
            }
        }
    }
}

pub(crate) struct DeclaredRequests {
    pub(crate) requests: NetworkRequests,
    pub(crate) tier: RequestTier,
}

/// Only the catalog facts already consumed by the shared launch pipeline.
pub(crate) struct CatalogGrant {
    provisioned: ProviderSet,
    required: ProviderSet,
    persist: Vec<PersistPath>,
    guest_env: BTreeMap<String, String>,
    requests: Option<DeclaredRequests>,
}

impl CatalogGrant {
    fn none() -> Self {
        Self {
            provisioned: ProviderSet::default(),
            required: ProviderSet::default(),
            persist: Vec::new(),
            guest_env: BTreeMap::new(),
            requests: None,
        }
    }
    pub(crate) fn provisioned(&self) -> ProviderSet {
        self.provisioned
    }
    pub(crate) fn required(&self) -> ProviderSet {
        self.required
    }
    pub(crate) fn persist(&self) -> &[PersistPath] {
        &self.persist
    }
    pub(crate) fn guest_env(&self) -> &BTreeMap<String, String> {
        &self.guest_env
    }
    pub(crate) fn requests(&self) -> Option<&DeclaredRequests> {
        self.requests.as_ref()
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
        let target = LaunchTarget::Direct(command);
        assert!(target.requested_names().is_empty());
        assert!(target.is_direct());
        let (grant, invocation) = target.into_parts();
        assert_eq!(grant.provisioned().iter().count(), 0);
        assert_eq!(grant.required().iter().count(), 0);
        assert!(grant.persist().is_empty());
        assert!(grant.guest_env().is_empty());
        assert!(grant.requests().is_none());
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
            let env = tool.guest_env().clone();
            let requests = tool.network_requests().clone();
            let tier = RequestTier::from(tool.origin());
            let command = tool.command().to_owned();
            let argv = crate::run::inner_argv(tool, vec!["x".into(), "x".into()]);
            let names = entry.requested_names().clone();
            let target = LaunchTarget::Tool {
                entry: Box::new(entry),
                tool_args: vec!["x".into(), "x".into()],
            };
            assert_eq!(target.requested_names(), &names);
            let (grant, invocation) = target.into_parts();
            assert_eq!(grant.provisioned(), provisioned);
            assert_eq!(grant.required(), required);
            assert_eq!(grant.persist(), persist);
            assert_eq!(grant.guest_env(), &env);
            assert_eq!(grant.requests().unwrap().requests, requests);
            assert_eq!(grant.requests().unwrap().tier, tier);
            assert_eq!(invocation.program(), command);
            assert_eq!(invocation.argv(), argv);
            assert_eq!(invocation.guard(), ProgramGuard::ImageContract);
        }
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
