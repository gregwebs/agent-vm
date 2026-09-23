//! CLI construction and dispatch.
//!
//! Everything clap-shaped lives behind this module. The set of **launch
//! verbs** is a *runtime* fact — read from the resolved tool catalog — while
//! the fixed built-ins (`setup`, `pull`, `msb`, `clipboard`, `doctor`,
//! `_intercept-hook`) are static. [`parse_from`] is the seam: argv plus the
//! *result* of `config::load` yields a [`Dispatch`] decision.
//!
//! `parse_from` takes `argv` explicitly and returns `Result`; it never calls
//! `get_matches()` and never exits on the success path, so the whole dispatch
//! table is unit-testable without spawning a process. The one place it exits
//! is clap's own `error.exit()`, which handles `--help`/`--version` (stdout,
//! status 0) and usage errors, so a launch verb cannot report a config error
//! where clap's help was asked for.
//!
//! # A broken config is deferred, not fatal
//!
//! `config::load` runs before parsing, because the catalog decides which
//! subcommands exist. But its *failure* is carried as data: `doctor`,
//! `clipboard` and `_intercept-hook` must keep working (the latter two run
//! inside the guest, where a project config is present), and any unknown verb
//! must be able to surface the config error rather than clap's "unrecognized
//! subcommand", which would send the user hunting for a typo in the verb
//! instead of in their TOML. On the broken path we therefore register no tool
//! subcommands and enable `allow_external_subcommands`.
//!
//! # Security
//!
//! A tool name is a validated [`crate::config::ToolName`] (no whitespace, no
//! control characters, no leading `-`, no `/`, not reserved), so interpolating
//! it into help output cannot inject terminal control sequences. A tool's
//! `command` is **not** equally validated (`config::validate_command` rejects
//! only empty and NUL), so the guest command must **not** appear in help text:
//! the `about` line names only the verb.

use std::ffi::OsString;

use anyhow::{Result, anyhow};
use clap::{Args as _, CommandFactory as _, FromArgMatches as _, Parser, Subcommand};

use crate::config::{self, Catalog, CatalogEntry, ConfigReport, Tool};
use crate::run;
use crate::{clipboard, doctor, intercept_hook, msb_cmd, pull, setup};

// Shown under the top-level `agent-vm --help`, after the command list. Names
// no specific tool: the verbs come from configuration, so a hard-coded name
// would be wrong for a user who does not have it.
pub(crate) const TOP_AFTER_HELP: &str = "\
Getting started:
  agent-vm setup       fetch and verify the base image (run once first)
  cd ~/your-project
  agent-vm <tool>      launch one of the tools listed above

Launch verbs come from your tool configuration and all share the same options;
see `agent-vm <tool> --help` for mounts, ports, networking and credentials.
`agent-vm doctor` shows which config files were found and what they resolved to.";

/// Shown under `agent-vm --help` when the config could not be read, so the
/// absent verb list is explained rather than silently empty.
const CONFIG_BROKEN_NOTE: &str = "\
Your tool configuration could not be read, so no launch verbs are listed.
Run `agent-vm doctor` to see the error.";

#[derive(Parser)]
#[command(
    name = "agent-vm",
    version,
    about = "Sandboxed microVMs for AI coding agents.",
    after_help = TOP_AFTER_HELP
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

/// The fixed, compiled-in subcommands. Launch verbs are **not** variants here:
/// they are generated per catalog entry (see [`launch_subcommand`]).
#[derive(Subcommand)]
pub(crate) enum Cmd {
    /// Pull and verify the base image (run once first).
    Setup(setup::Args),

    /// Refresh the cached base image.
    Pull(pull::Args),

    /// Forward arguments to the bundled `msb` with agent-vm's MSB_HOME/MSB_PATH
    /// pinned (e.g. `agent-vm msb ls`, `agent-vm msb status`). Relies on
    /// `needs_msb_setup` staying true for this variant — see main().
    Msb(msb_cmd::Args),

    /// Exchange a string between the host and the sandbox.
    Clipboard(clipboard::Args),

    /// Diagnostic / maintenance operations for agent-vm's private
    /// microsandbox state (e.g. --reset-msb-db).
    Doctor(doctor::Args),

    /// Internal: invoked by msb's interceptor hook for matched OAuth
    /// and scoped GitHub requests. Reads stdin and writes the protocol
    /// response on stdout. Not meant for direct use.
    #[command(name = "_intercept-hook", hide = true)]
    InterceptHook(intercept_hook::Args),
}

/// What [`parse_from`] decided to do. Built-in verbs keep their derived clap
/// types **and** the loaded catalog: only `Cmd::Setup` reads it (it verifies
/// every configured tool's command), but every built-in carries it so the
/// catalog a launch *would* have used is the same value `setup` reads.
pub(crate) enum Dispatch {
    Builtin {
        cmd: Cmd,
        catalog: Catalog,
    },
    // `args` is boxed so `Dispatch` does not carry the shared launch `Args`'s
    // full size inline (clippy `large_enum_variant`).
    Launch {
        entry: CatalogEntry,
        /// The catalog's declared tool layers, read **before** `take_entry`
        /// removed the launched verb (issue #84). The booted image is a
        /// property of the whole catalog, not of the invoked verb, so reading
        /// this after `take_entry` would silently drop the launched tool's own
        /// layer.
        layers: Vec<config::DeclaredLayer>,
        args: Box<run::Args>,
    },
}

/// Every subcommand name `build_command` registers that is not a tool,
/// including clap's synthesized `help`. Used for the misspelling check below
/// and asserted against `config::RESERVED_TOOL_NAMES` by a test, so a future
/// built-in cannot silently shadow — or be shadowed by — a config tool.
pub(crate) const BUILTIN_SUBCOMMANDS: &[&str] = &[
    "setup",
    "pull",
    "msb",
    "clipboard",
    "doctor",
    "_intercept-hook",
    "help",
];

/// Build the full command (built-ins + one subcommand per catalog entry) and
/// parse `argv`.
///
/// `config` is the *result* of `config::load`, not a `ConfigReport`: a broken
/// config must not stop `doctor`/`clipboard`/`_intercept-hook`, but must be
/// the error any launch verb reports (never clap's "unrecognized subcommand").
///
/// Never panics on user input: help/version/usage errors are handed to clap's
/// `error.exit()`.
pub(crate) fn parse_from<I, T>(argv: I, config: Result<ConfigReport>) -> Result<Dispatch>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let catalog = match config {
        // A dangling `tools` reference is *user* input, so it must degrade to
        // the deferred-error path (ADR-0015) rather than `?`-propagate and take
        // `doctor`/`--help`/`clipboard` down with it.
        Ok(report) => match report.into_launch_catalog() {
            Ok(catalog) => Catalog::Ready(catalog),
            Err(error) => Catalog::Broken(error),
        },
        Err(error) => Catalog::Broken(error),
    };

    let matches = match build_command(&catalog).try_get_matches_from(argv) {
        Ok(matches) => matches,
        Err(error) => {
            // On the broken path `allow_external_subcommands` absorbs every
            // unknown verb, so the only `InvalidSubcommand` clap can raise is
            // its synthesized `help <x>` validating `x` against the tool-less
            // command. Report the config error there — never clap's
            // "unrecognized subcommand" — with a did-you-mean hint when
            // useful.
            if error.kind() == clap::error::ErrorKind::InvalidSubcommand
                && let Catalog::Broken(config_error) = &catalog
            {
                return Err(config_error_with_hint(
                    config_error,
                    invalid_subcommand(&error).as_deref().unwrap_or_default(),
                ));
            }
            // Help and version are not failures: clap's own `exit()` writes
            // them to stdout with status 0. Propagating them as
            // `anyhow::Error` through main's `?` would print help to *stderr*
            // with status 2.
            error.exit()
        }
    };

    match (matches.subcommand(), catalog) {
        // Unreachable in practice: clap returns
        // `DisplayHelpOnMissingArgumentOrSubcommand` for a bare `agent-vm`
        // even with external subcommands enabled, so `error.exit()` above has
        // already handled it. Kept as an explicit error rather than a panic.
        (None, _) => Err(anyhow!("no subcommand")),
        // The catalog is authoritative (checked first) so a future built-in
        // added without updating `RESERVED_TOOL_NAMES` fails a test rather
        // than silently shadowing a user's tool.
        (Some((name, sub)), Catalog::Ready(mut catalog)) => {
            // Read the declared layers BEFORE `take_entry`: the image a launch
            // boots is a property of the whole catalog, so removing the
            // launched verb first would drop its own layer (issue #84).
            let layers = catalog.declared_layers();
            match catalog.take_entry(name) {
                Some(entry) => Ok(Dispatch::Launch {
                    entry,
                    layers,
                    args: Box::new(run::Args::from_arg_matches(sub)?),
                }),
                // Not a tool, so a fixed built-in: the two name sets are disjoint
                // (`RESERVED_TOOL_NAMES`, asserted by a test) and external
                // subcommands are off on this path, so clap could not have accepted
                // anything else. The catalog (minus the taken launch entry, which
                // only a launch verb would have matched) is carried to the built-in
                // so `setup` can read it.
                None => Ok(Dispatch::Builtin {
                    cmd: Cli::from_arg_matches(&matches)?.cmd,
                    catalog: Catalog::Ready(catalog),
                }),
            }
        }
        (Some((name, _)), Catalog::Broken(config_error)) => {
            // A registered built-in still works; anything else is an unknown
            // verb clap accepted as an external subcommand, and carries the
            // config error.
            match Cli::from_arg_matches(&matches) {
                Ok(cli) => Ok(Dispatch::Builtin {
                    cmd: cli.cmd,
                    catalog: Catalog::Broken(config_error),
                }),
                Err(_) => Err(config_error_with_hint(&config_error, name)),
            }
        }
    }
}

/// The clap command for a given catalog: `Ready` registers one subcommand per
/// tool, `Broken` registers none and lets unknown verbs reach the deferred
/// config error. Pure over its inputs so the help fixtures are pinned without
/// touching `$HOME` or the cwd.
pub(crate) fn build_command(catalog: &Catalog) -> clap::Command {
    let mut command = Cli::command();
    match catalog {
        Catalog::Ready(catalog) => {
            for entry in catalog.as_slice() {
                command = command.subcommand(launch_subcommand(entry.tool()));
            }
        }
        // D1: with no catalog, any unknown verb must be able to surface the
        // config error rather than clap's "unrecognized subcommand", which
        // would send the user hunting for a typo in the verb instead of in
        // their TOML.
        Catalog::Broken(_) => {
            command = command
                .allow_external_subcommands(true)
                .after_help(format!("{TOP_AFTER_HELP}\n\n{CONFIG_BROKEN_NOTE}"));
        }
    }
    command
}

/// Format the deferred config error as the primary message, appending clap's
/// did-you-mean as a hint when `verb` is a near-miss on a built-in. A broken
/// config must never be replaced by "unrecognized subcommand" (issue #82's
/// acceptance criterion), but a verb typo still deserves the pointer clap
/// would give — *after* the real error, not instead of it.
fn config_error_with_hint(config_error: &anyhow::Error, verb: &str) -> anyhow::Error {
    match nearest_builtin(verb) {
        Some(builtin) => {
            anyhow!("{config_error:#}\n\ntip: a similar subcommand exists: '{builtin}'")
        }
        None => anyhow!("{config_error:#}"),
    }
}

/// The verb clap rejected in an `InvalidSubcommand` error. clap always sets
/// this context alongside that kind; `None` is a defensive fallback.
fn invalid_subcommand(error: &clap::Error) -> Option<String> {
    match error.get(clap::error::ContextKind::InvalidSubcommand) {
        Some(clap::error::ContextValue::String(name)) => Some(name.clone()),
        _ => None,
    }
}

/// The built-in `verb` is a near-miss on — within edit distance 2, closest
/// first — or `None` when it is not near any. `help` is excluded: it is
/// clap-synthesized, and including it makes real launch verbs false-positive
/// ("shell" is edit distance 2 from "help"), which would append a misleading
/// hint to an otherwise valid tool name.
fn nearest_builtin(verb: &str) -> Option<&'static str> {
    BUILTIN_SUBCOMMANDS
        .iter()
        .filter(|builtin| **builtin != "help")
        .map(|builtin| (*builtin, edit_distance(verb, builtin)))
        .filter(|(_, distance)| *distance <= 2)
        .min_by_key(|(_, distance)| *distance)
        .map(|(builtin, _)| builtin)
}

/// One launch subcommand, backed by the shared [`run::Args`]. `tool.name()` is
/// a validated name, so it carries no whitespace or control characters into
/// rendered help; `tool.command()` is deliberately not rendered (see module
/// docs).
fn launch_subcommand(tool: &Tool) -> clap::Command {
    run::Args::augment_args(clap::Command::new(tool.name().to_owned()))
        .about(format!("Launch {} in a per-project sandbox", tool.name()))
        .after_help(run::launch_after_help(tool.name()))
        .after_long_help(run::launch_after_long_help(tool.name()))
}

/// Levenshtein distance. Small inputs (subcommand names) so the simple
/// two-row DP is plenty.
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    let mut current = vec![0usize; b.len() + 1];
    for (i, &ca) in a.iter().enumerate() {
        current[0] = i + 1;
        for (j, &cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            current[j + 1] = (previous[j + 1] + 1)
                .min(current[j] + 1)
                .min(previous[j] + cost);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ConfigPaths, LaunchCatalog, RESERVED_TOOL_NAMES};
    use std::path::Path;

    /// A `ConfigReport` loaded from `body` in a throwaway project file. `load`
    /// reads the file eagerly, so the temp dir is gone by the time this
    /// returns.
    fn report_from(body: &str) -> ConfigReport {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("config.toml");
        std::fs::write(&project, body).unwrap();
        crate::config::load(&ConfigPaths {
            user: Some(dir.path().join("no-user-config.toml")),
            project,
        })
        .expect("the fixture config parses")
    }

    /// The embedded default catalog, loaded via explicit non-existent paths so
    /// the test never depends on the developer's `$HOME` or cwd.
    fn default_catalog() -> LaunchCatalog {
        let dir = tempfile::tempdir().unwrap();
        crate::config::load(&ConfigPaths {
            user: Some(dir.path().join("no-user-config.toml")),
            project: dir.path().join("no-project-config.toml"),
        })
        .expect("the embedded default catalog parses")
        .into_launch_catalog()
        .expect("the default catalog resolves")
    }

    fn subcommand_names(command: &clap::Command) -> Vec<String> {
        command
            .get_subcommands()
            .map(|sub| sub.get_name().to_string())
            .collect()
    }

    // -- T6: registration is exactly the built-ins plus the tools ----------

    #[test]
    fn default_catalog_registers_builtins_then_tools_in_order() {
        let catalog = default_catalog();
        let mut command = build_command(&Catalog::Ready(catalog));
        // `build()` runs clap's `_check_help_and_version`, which is what
        // registers the synthesized `help` subcommand — so the names below are
        // the full `BUILTIN_SUBCOMMANDS` set, in registration order: fixed
        // built-ins, then tools in catalog order, then clap's `help` last.
        command.build();
        let names = subcommand_names(&command);

        let mut expected: Vec<String> = BUILTIN_SUBCOMMANDS
            .iter()
            .filter(|name| **name != "help")
            .map(|s| s.to_string())
            .collect();
        expected.extend(
            [
                "dsh", "pi", "codex", "opencode", "claude", "copilot", "shell",
            ]
            .iter()
            .map(|s| s.to_string()),
        );
        expected.push("help".to_string());
        assert_eq!(names, expected);
    }

    // -- T7: the two lists cannot drift -----------------------------------

    #[test]
    fn every_builtin_subcommand_is_reserved_from_tool_names() {
        for builtin in BUILTIN_SUBCOMMANDS {
            assert!(
                RESERVED_TOOL_NAMES.contains(builtin),
                "{builtin} is a built-in subcommand but not a reserved tool name; \
                 a config could shadow it"
            );
        }
    }

    // -- T8: a one-tool catalog registers only it plus the shell fallback --

    #[test]
    fn a_claude_only_catalog_registers_only_claude_and_shell() {
        let report = report_from(
            "[[tools]]\nname = \"claude\"\ncommand = \"claude\"\ncredentials = [\"anthropic\"]\n",
        );
        let catalog = report.into_launch_catalog().unwrap();
        let command = build_command(&Catalog::Ready(catalog));
        assert!(command.find_subcommand("claude").is_some());
        assert!(command.find_subcommand("shell").is_some());
        for absent in ["codex", "opencode", "copilot"] {
            assert!(
                command.find_subcommand(absent).is_none(),
                "{absent} should not be registered"
            );
        }
    }

    /// Issue #84's `take_entry` ordering trap: a launch verb's `Dispatch` must
    /// carry the layers read from the catalog *before* the launched verb is
    /// removed, so `claude` under the default config carries all six shipped
    /// layers in order (its own included).
    #[test]
    fn a_launch_carries_every_declared_layer_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let config = crate::config::load(&ConfigPaths {
            user: Some(dir.path().join("no-user-config.toml")),
            project: dir.path().join("no-project-config.toml"),
        });
        let dispatch = parse_from(["agent-vm", "claude"], config).expect("claude parses");
        match dispatch {
            Dispatch::Launch { entry, layers, .. } => {
                assert_eq!(entry.tool().name(), "claude");
                let seq: Vec<_> = layers.iter().map(|l| l.layer().clone()).collect();
                assert_eq!(seq, crate::config::shipped_tool_layers().unwrap());
            }
            Dispatch::Builtin { .. } => panic!("claude is a launch verb"),
        }
    }

    // -- T9: dispatch to a launch verb and to a built-in ------------------

    /// Issue #144: the non-interactive tooling-layer error tells the user to
    /// "Re-run with --yes", so *every* launch verb — not just `shell` — must
    /// register and consume that flag. An unregistered `--`-flag is not
    /// rejected here: the trailing `agent_args` positional has
    /// `allow_hyphen_values`, so clap would silently forward it to the agent.
    /// Asserting `agent_args` stays empty therefore distinguishes "consumed as
    /// a flag" from "swallowed as an agent argument".
    #[test]
    fn every_launch_verb_consumes_yes_as_a_flag() {
        let catalog = default_catalog();
        // Read from the catalog rather than a literal list, so a tool added to
        // `default-tools.toml` inherits this guarantee instead of escaping it.
        let verbs: Vec<String> = catalog
            .as_slice()
            .iter()
            .map(|entry| entry.tool().name().to_owned())
            .collect();
        // Issue #144 names `pi` and `shell`; a vacuous catalog must not make
        // the loop below pass by iterating nothing.
        for required in ["pi", "shell"] {
            assert!(
                verbs.iter().any(|verb| verb == required),
                "the shipped catalog must still declare {required}: {verbs:?}"
            );
        }
        let command = build_command(&Catalog::Ready(catalog));

        for verb in &verbs {
            let matches = command
                .clone()
                .try_get_matches_from(["agent-vm", verb, "--yes"])
                .unwrap_or_else(|error| panic!("{verb} must accept --yes: {error}"));
            let (_, sub) = matches.subcommand().expect("a launch subcommand");
            let args = <run::Args as clap::FromArgMatches>::from_arg_matches(sub)
                .expect("launch args parse");
            assert!(args.yes, "{verb}: --yes parsed but did not set the flag");
            assert!(
                args.agent_args.is_empty(),
                "{verb}: --yes leaked into agent_args: {:?}",
                args.agent_args
            );
        }

        // Control for the `agent_args` assertion: an *unregistered* hyphen flag
        // is swallowed into `agent_args` rather than rejected, so an empty
        // `agent_args` above proves `--yes` was matched as a flag.
        let matches = command
            .try_get_matches_from(["agent-vm", "pi", "--not-a-flag"])
            .expect("the trailing positional accepts hyphen values");
        let (_, sub) = matches.subcommand().expect("a launch subcommand");
        let args =
            <run::Args as clap::FromArgMatches>::from_arg_matches(sub).expect("launch args parse");
        assert_eq!(args.agent_args, ["--not-a-flag"]);
        assert!(!args.yes, "an unregistered flag must not set --yes");
    }

    #[test]
    fn parse_from_dispatches_a_project_tool_and_a_builtin() {
        let body = "[[tools]]\nname = \"mytool\"\ncommand = \"my-agent\"\nargs = [\"--fast\"]\n";

        // A launch verb carries the resolved tool and its trailing args.
        let dispatch = parse_from(
            ["agent-vm", "mytool", "--", "--resume"],
            Ok(report_from(body)),
        )
        .expect("mytool parses");
        match dispatch {
            Dispatch::Launch { entry, args, .. } => {
                assert_eq!(entry.tool().name(), "mytool");
                assert_eq!(entry.tool().command(), "my-agent");
                assert_eq!(args.agent_args, ["--resume"]);
            }
            Dispatch::Builtin { .. } => panic!("mytool should dispatch as a launch"),
        }

        // A built-in still dispatches as a built-in.
        let dispatch =
            parse_from(["agent-vm", "doctor"], Ok(report_from(body))).expect("doctor parses");
        match dispatch {
            Dispatch::Builtin {
                cmd: Cmd::Doctor(_),
                ..
            } => {}
            Dispatch::Builtin { .. } => panic!("expected the doctor built-in"),
            Dispatch::Launch { .. } => panic!("doctor is not a launch verb"),
        }
    }

    // -- T5: a dangling `tools` reference degrades (D3) -------------------

    #[test]
    fn a_dangling_tools_reference_is_a_deferred_config_error() {
        let body = "[[tools]]\nname = \"t\"\ncommand = \"t\"\ntools = [\"nope\"]\n";
        // A launch verb reports the config error, never clap's
        // unrecognized-subcommand, exactly like a syntactically broken config.
        let result = parse_from(["agent-vm", "t"], Ok(report_from(body)));
        let text = format!("{:#}", result.err().expect("`t` must fail"));
        assert!(
            text.contains("names no tool in the resolved catalog"),
            "{text}"
        );
        assert!(!text.contains("unrecognized subcommand"), "{text}");
    }

    // -- T10: the asymmetric broken-config acceptance criterion -----------

    #[test]
    fn a_broken_config_errors_a_launch_but_a_valid_one_errors_a_missing_tool() {
        // `claude` under a broken config returns *that* error.
        let result = parse_from(
            ["agent-vm", "claude"],
            Err(anyhow!("config: broken on purpose")),
        );
        match result {
            Err(error) => {
                let text = format!("{error:#}");
                assert!(text.contains("config: broken on purpose"), "{text}");
                assert!(!text.contains("unrecognized subcommand"), "{text}");
            }
            Ok(_) => panic!("a launch verb under a broken config must fail"),
        }

        // `codex` under a *valid* claude-only catalog is clap's unrecognized
        // subcommand, produced by the parser before `parse_from`'s dispatch.
        let catalog = report_from(
            "[[tools]]\nname = \"claude\"\ncommand = \"claude\"\ncredentials = [\"anthropic\"]\n",
        )
        .into_launch_catalog()
        .unwrap();
        let error = build_command(&Catalog::Ready(catalog))
            .try_get_matches_from(["agent-vm", "codex"])
            .expect_err("codex is not registered");
        assert_eq!(error.kind(), clap::error::ErrorKind::InvalidSubcommand);
    }

    // -- T10b: a broken config never degrades into clap's unrecognized ------

    #[test]
    fn a_broken_config_reports_its_error_and_hints_at_a_near_builtin_verb() {
        // A misspelled built-in keeps clap's helpfulness, but as a hint after
        // the config error — never as clap's "unrecognized subcommand".
        let result = parse_from(
            ["agent-vm", "doctro"],
            Err(anyhow!("config: broken on purpose")),
        );
        let text = format!("{:#}", result.err().expect("`doctro` must fail"));
        assert!(text.contains("config: broken on purpose"), "{text}");
        assert!(
            text.contains("tip: a similar subcommand exists: 'doctor'"),
            "{text}"
        );
        assert!(!text.contains("unrecognized subcommand"), "{text}");

        // A plausible *tool* name within distance 2 of a built-in (`docker` /
        // `doctor`) is not special-cased away: the config error stays primary.
        let result = parse_from(
            ["agent-vm", "docker"],
            Err(anyhow!("config: broken on purpose")),
        );
        let text = format!("{:#}", result.err().expect("`docker` must fail"));
        assert!(text.contains("config: broken on purpose"), "{text}");
        assert!(text.contains("'doctor'"), "{text}");
        assert!(!text.contains("unrecognized subcommand"), "{text}");

        // A verb far from every built-in gets the config error and no hint.
        let result = parse_from(
            ["agent-vm", "claude"],
            Err(anyhow!("config: broken on purpose")),
        );
        let text = format!("{:#}", result.err().expect("`claude` must fail"));
        assert!(text.contains("config: broken on purpose"), "{text}");
        assert!(!text.contains("tip:"), "{text}");
        assert!(!text.contains("unrecognized subcommand"), "{text}");
    }

    /// clap's synthesized `help <verb>` validates its positional *before*
    /// `parse_from`'s dispatch, so on the broken path it is the only
    /// `InvalidSubcommand` clap raises. It must still report the config error.
    #[test]
    fn help_for_an_unknown_verb_under_a_broken_config_reports_the_config_error() {
        let result = parse_from(
            ["agent-vm", "help", "claude"],
            Err(anyhow!("config: broken on purpose")),
        );
        let text = format!("{:#}", result.err().expect("`help claude` must fail"));
        assert!(text.contains("config: broken on purpose"), "{text}");
        assert!(!text.contains("unrecognized subcommand"), "{text}");
    }

    // -- T11: the near-builtin predicate ----------------------------------

    #[test]
    fn nearest_builtin_detects_typos_and_rejects_real_verbs() {
        assert_eq!(nearest_builtin("doctro"), Some("doctor"));
        assert_eq!(nearest_builtin("doctr"), Some("doctor"));
        assert_eq!(nearest_builtin("setp"), Some("setup"));
        assert_eq!(nearest_builtin("clipbord"), Some("clipboard"));
        // A plausible tool name colliding with a built-in still yields a hint.
        assert_eq!(nearest_builtin("docker"), Some("doctor"));
        assert_eq!(nearest_builtin("mcp"), Some("msb"));
        // Real launch verbs, and `shell` in particular — which is distance 2
        // from the excluded `help` — do not get a hint.
        for far in ["claude", "mytool", "codex", "shell"] {
            assert_eq!(nearest_builtin(far), None, "{far} should not be near");
        }
    }

    // -- T12: the help fixtures, pinned to an explicit config -------------

    // Clap indents blank description spacers at this width. Normalize only
    // lines containing whitespace so fixtures stay clean while still pinning
    // every meaningful character, indentation, and ordering in both help
    // renderings.
    fn normalize_help_whitespace_only_lines(help: &str) -> String {
        help.split_inclusive('\n')
            .map(|line| {
                let (content, newline) = line
                    .strip_suffix('\n')
                    .map_or((line, ""), |content| (content, "\n"));
                if content.trim().is_empty() {
                    newline.to_owned()
                } else {
                    line.to_owned()
                }
            })
            .collect()
    }

    #[test]
    fn shell_accepts_network_options_and_keeps_help_stable() {
        let command = build_command(&Catalog::Ready(default_catalog())).term_width(100);
        command
            .clone()
            .try_get_matches_from([
                "agent-vm",
                "shell",
                "-p",
                "8080:3000",
                "--publish",
                "[::1]:8081:3001/tcp",
                "--auto-publish",
                "--allow-egress",
                "10.0.0.5",
                "--allow-egress",
                "fd00::1",
                "--allow-lan",
                "--allow-host",
                "--",
                "--agent-flag",
            ])
            .expect("the real shell subcommand accepts all network options");

        let mut shell = command
            .find_subcommand("shell")
            .expect("shell subcommand is registered")
            .clone()
            .bin_name("agent-vm shell")
            // These fixtures characterize the CLI contract, not ambient process
            // configuration. Keep the env-variable labels but omit their values
            // on this test-only clone so parallel tests never need setenv().
            .mut_args(|arg| arg.hide_env_values(true));

        let mut short_help = Vec::new();
        shell
            .clone()
            .write_help(&mut short_help)
            .expect("short shell help renders");
        let short_actual = normalize_help_whitespace_only_lines(
            &String::from_utf8(short_help).expect("help is UTF-8"),
        );

        let mut long_help = Vec::new();
        shell
            .write_long_help(&mut long_help)
            .expect("long shell help renders");
        let long_actual = normalize_help_whitespace_only_lines(
            &String::from_utf8(long_help).expect("help is UTF-8"),
        );

        assert_help_fixture(
            "shell-short-help-columns-100.txt",
            &short_actual,
            include_str!("../tests/fixtures/shell-short-help-columns-100.txt"),
        );
        assert_help_fixture(
            "shell-help-columns-100.txt",
            &long_actual,
            include_str!("../tests/fixtures/shell-help-columns-100.txt"),
        );
    }

    /// `UPDATE_HELP_FIXTURES=1` rewrites the pinned fixtures instead of
    /// asserting, so an intentional help change has a mechanical update path.
    /// Regenerate by running the test and writing the actual output — clap's
    /// wrapping at `term_width(100)` is unforgiving, so never hand-edit them.
    fn assert_help_fixture(name: &str, actual: &str, expected: &str) {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name);
        if std::env::var_os("UPDATE_HELP_FIXTURES").is_some() {
            std::fs::write(&path, actual).unwrap();
            return;
        }
        assert_eq!(
            actual, expected,
            "the {name} fixture drifted (rerun with UPDATE_HELP_FIXTURES=1 only if intentional)"
        );
    }

    /// The acceptance criterion "name no specific tool": neither footer nor
    /// the top-level help mentions a shipped tool by name.
    ///
    /// A **token** match, not `str::contains`: the help fixtures legitimately
    /// contain ordinary words that *contain* a tool name as a substring (the
    /// fixtures contain `copies`, which contains `pi`). The invariant is that
    /// the help text does not *name* a tool, so split the haystack on every
    /// non-name character and require no token to equal a tool name.
    #[test]
    fn the_help_text_names_no_specific_tool() {
        fn named_tool(haystack: &str) -> Option<&'static str> {
            let tokens: Vec<&str> = haystack
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
                .collect();
            ["dsh", "pi", "claude", "codex", "opencode", "copilot"]
                .into_iter()
                .find(|tool| tokens.contains(tool))
        }

        let short = run::launch_after_help("shell");
        let long = run::launch_after_long_help("shell");
        for (what, haystack) in [
            ("TOP_AFTER_HELP", TOP_AFTER_HELP),
            ("the short launch footer", short.as_str()),
            ("the long launch footer", long.as_str()),
            (
                "shell-help-columns-100.txt",
                include_str!("../tests/fixtures/shell-help-columns-100.txt"),
            ),
            (
                "shell-short-help-columns-100.txt",
                include_str!("../tests/fixtures/shell-short-help-columns-100.txt"),
            ),
        ] {
            if let Some(tool) = named_tool(haystack) {
                panic!("{what} names {tool}");
            }
        }
    }

    #[test]
    fn broken_config_help_lists_builtins_and_points_at_doctor() {
        let command = build_command(&Catalog::Broken(anyhow!("broken on purpose")));
        let mut help = Vec::new();
        command
            .clone()
            .write_long_help(&mut help)
            .expect("the broken-config help renders");
        let help = String::from_utf8(help).unwrap();
        for builtin in ["setup", "pull", "msb", "clipboard", "doctor"] {
            assert!(help.contains(builtin), "missing builtin {builtin}: {help}");
        }
        assert!(help.contains("could not be read"), "{help}");
        assert!(help.contains("agent-vm doctor"), "{help}");
    }
}
