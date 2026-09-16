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

use crate::config::{ConfigReport, LaunchCatalog, Tool};
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
/// types; a launch verb resolves to one entry of the catalog plus the shared
/// launch `Args`.
pub(crate) enum Dispatch {
    Builtin(Cmd),
    // `args` is boxed so `Dispatch` does not carry the shared launch `Args`'s
    // full size inline (clippy `large_enum_variant`); the tool itself is small.
    Launch { tool: Tool, args: Box<run::Args> },
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
    let (catalog, config_error) = match config {
        Ok(report) => (Some(report.into_launch_catalog()?), None),
        Err(error) => (None, Some(error)),
    };
    // Kept so the misspelling carve-out below can re-parse against the
    // built-ins alone, where clap's parser (not the derive) renders its
    // did-you-mean suggestion.
    let argv: Vec<OsString> = argv.into_iter().map(Into::into).collect();

    let matches = match build_command(catalog.as_ref()).try_get_matches_from(argv.clone()) {
        Ok(matches) => matches,
        // Help and version are not failures: clap's own `exit()` writes them
        // to stdout with status 0. Propagating them as `anyhow::Error` through
        // main's `?` would print help to *stderr* with status 2.
        Err(error) => error.exit(),
    };

    match matches.subcommand() {
        Some((name, sub)) => match catalog.and_then(|catalog| catalog.take(name)) {
            Some(tool) => Ok(Dispatch::Launch {
                tool,
                args: Box::new(run::Args::from_arg_matches(sub)?),
            }),
            // Not a tool. The catalog is authoritative (checked first) so a
            // future built-in added without updating `RESERVED_TOOL_NAMES`
            // fails a test rather than silently shadowing a user's tool.
            None => match Cli::from_arg_matches(&matches) {
                Ok(cli) => Ok(Dispatch::Builtin(cli.cmd)),
                // Broken-config path only (external subcommands are off
                // otherwise). A near-miss on a built-in is a typo in the
                // verb, so let clap say so — `agent-vm doctro` must not report
                // a config error when `doctor` is what we're telling the user
                // to run. Re-parsing against the built-ins alone (external
                // subcommands off) is what makes clap render its did-you-mean.
                Err(_) if near_builtin(name) => {
                    let error = Cli::command()
                        .try_get_matches_from(argv)
                        .expect_err("a near-builtin verb does not match a built-in");
                    error.exit()
                }
                Err(_) => {
                    Err(config_error.unwrap_or_else(|| anyhow!("unrecognized subcommand {name:?}")))
                }
            },
        },
        // Unreachable in practice: clap returns
        // `DisplayHelpOnMissingArgumentOrSubcommand` for a bare `agent-vm`
        // even with external subcommands enabled, so `error.exit()` above has
        // already handled it. Kept as an explicit error rather than a panic.
        None => Err(anyhow!("no subcommand")),
    }
}

/// The clap command for a given catalog. `None` is the broken-config shape.
/// Pure over its inputs so the help fixtures are pinned without touching
/// `$HOME` or the cwd.
pub(crate) fn build_command(catalog: Option<&LaunchCatalog>) -> clap::Command {
    let mut command = Cli::command();
    match catalog {
        Some(catalog) => {
            for tool in catalog.as_slice() {
                command = command.subcommand(launch_subcommand(tool));
            }
        }
        // D1: with no catalog, any unknown verb must be able to surface the
        // config error rather than clap's "unrecognized subcommand", which
        // would send the user hunting for a typo in the verb instead of in
        // their TOML.
        None => {
            command = command
                .allow_external_subcommands(true)
                .after_help(format!("{TOP_AFTER_HELP}\n\n{CONFIG_BROKEN_NOTE}"));
        }
    }
    command
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

/// True when `name` is within edit distance 2 of a built-in subcommand. Used
/// only on the broken-config path: a near-miss is a verb typo, so clap's own
/// did-you-mean is the honest message, not the config error.
fn near_builtin(name: &str) -> bool {
    // `help` is deliberately excluded. It is clap-synthesized, and including it
    // makes real launch verbs false-positive: "shell" is edit-distance 2 from
    // "help", so `agent-vm shell` under a broken config would show clap's
    // "unrecognized subcommand" instead of the config error — violating the
    // acceptance criterion that a broken config never degrades that way. A
    // typo of `help` is rare enough to fall through to the config error.
    BUILTIN_SUBCOMMANDS
        .iter()
        .filter(|builtin| **builtin != "help")
        .any(|builtin| edit_distance(name, builtin) <= 2)
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
    use crate::config::{ConfigPaths, RESERVED_TOOL_NAMES};
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
        let mut command = build_command(Some(&catalog));
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
            ["codex", "opencode", "claude", "copilot", "shell"]
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
        let command = build_command(Some(&catalog));
        assert!(command.find_subcommand("claude").is_some());
        assert!(command.find_subcommand("shell").is_some());
        for absent in ["codex", "opencode", "copilot"] {
            assert!(
                command.find_subcommand(absent).is_none(),
                "{absent} should not be registered"
            );
        }
    }

    // -- T9: dispatch to a launch verb and to a built-in ------------------

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
            Dispatch::Launch { tool, args } => {
                assert_eq!(tool.name(), "mytool");
                assert_eq!(tool.command(), "my-agent");
                assert_eq!(args.agent_args, ["--resume"]);
            }
            Dispatch::Builtin(_) => panic!("mytool should dispatch as a launch"),
        }

        // A built-in still dispatches as a built-in.
        let dispatch =
            parse_from(["agent-vm", "doctor"], Ok(report_from(body))).expect("doctor parses");
        match dispatch {
            Dispatch::Builtin(Cmd::Doctor(_)) => {}
            Dispatch::Builtin(_) => panic!("expected the doctor built-in"),
            Dispatch::Launch { .. } => panic!("doctor is not a launch verb"),
        }
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
        let error = build_command(Some(&catalog))
            .try_get_matches_from(["agent-vm", "codex"])
            .expect_err("codex is not registered");
        assert_eq!(error.kind(), clap::error::ErrorKind::InvalidSubcommand);
    }

    // -- T11: the near-builtin predicate ----------------------------------

    #[test]
    fn near_builtin_detects_typos_and_rejects_real_verbs() {
        for near in ["doctro", "doctr", "setp", "clipbord"] {
            assert!(near_builtin(near), "{near} should be near a built-in");
        }
        for far in ["claude", "mytool", "codex", "shell"] {
            assert!(!near_builtin(far), "{far} should not be near a built-in");
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
        let command = build_command(Some(&default_catalog())).term_width(100);
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
    #[test]
    fn the_help_text_names_no_specific_tool() {
        for tool in ["claude", "codex", "opencode", "copilot"] {
            assert!(
                !TOP_AFTER_HELP.contains(tool),
                "TOP_AFTER_HELP names {tool}"
            );
            assert!(
                !run::launch_after_help("shell").contains(tool),
                "the short launch footer names {tool}"
            );
            assert!(
                !run::launch_after_long_help("shell").contains(tool),
                "the long launch footer names {tool}"
            );
            for fixture in [
                include_str!("../tests/fixtures/shell-help-columns-100.txt"),
                include_str!("../tests/fixtures/shell-short-help-columns-100.txt"),
            ] {
                assert!(!fixture.contains(tool), "a fixture names {tool}");
            }
        }
    }

    #[test]
    fn broken_config_help_lists_builtins_and_points_at_doctor() {
        let command = build_command(None);
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
