//! CLI construction and dispatch.
//!
//! Everything clap-shaped lives behind this module. The set of **launch
//! verbs** is a *runtime* fact — read from the resolved tool catalog — while
//! the fixed built-ins (`setup`, `pull`, `upgrade`, `secret`, `image`, `msb`, `clipboard`, `doctor`,
//! `_intercept-hook`) are static. [`parse_from`] is the seam: argv plus the
//! *result* of `config::load` yields a [`Dispatch`] decision.
//!
//! The deferred config failure is consumed differently per verb: diagnoses
//! where it is diagnostic (`doctor`, `setup`), ignored where it is irrelevant
//! (`clipboard`, `_intercept-hook`, `image build`/`import`), and fatal for
//! `image show`, which reports a selection and so cannot use a fallback
//! configuration.
//!
//! `parse_from` takes `argv` explicitly and returns `Result`; it never calls
//! `get_matches()` and never exits on the success path, so the whole dispatch
//! table is unit-testable without spawning a process. The one place it exits
//! is clap's own `error.exit()`, which handles `--help`/`--version` (stdout,
//! status 0) and usage errors, so a launch verb cannot report a config error
//! where clap's help was asked for.
//!
//! Launch options precede the tool verb at the top level. A tool verb has one
//! raw positional and no help flag: every token after it is a **tool argument**.
//! A misplaced launch option before a built-in is returned as a clap usage error.
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
use std::os::unix::ffi::OsStrExt as _;

use anyhow::{Result, anyhow};
use clap::{Args as _, CommandFactory as _, FromArgMatches as _, Parser, Subcommand};
use vstd::prelude::*;

#[cfg(test)]
use crate::boot_image::OverrideSource;
use crate::config::{Catalog, CatalogEntry, ConfigReport, ConfiguredImages, Tool};
use crate::run;
use crate::{clipboard, doctor, intercept_hook, msb_cmd, pull, secret, setup};

verus! {

/// The literal verb name, as bytes.
pub(crate) open spec fn secret_word() -> Seq<u8> {
    b"secret"@
}

/// Whether any token after the binary name is `secret`. Launch options can
/// precede the verb, and help traversal can reach it too. Over-scrubbing is
/// accepted: only this predicate decides whether a value-bearing parse error
/// gets the fixed scrub.
pub(crate) open spec fn route_is_secret(argv: Seq<Seq<u8>>) -> bool {
    exists|i: int| 1 <= i < argv.len() && argv[i] =~= secret_word()
}

/// Whole-token equality, never a prefix or a substring: a token that merely
/// *starts* with `secret` must not select the scrub.
fn token_equals(token: &[u8], word: &[u8]) -> (equal: bool)
    ensures equal == (token@ =~= word@),
{
    if token.len() != word.len() {
        return false;
    }
    let mut index = 0;
    while index < token.len()
        invariant
            index <= token.len(),
            token@.len() == word@.len(),
            forall|j: int| 0 <= j < index ==> token@[j] == word@[j],
        decreases token.len() - index,
    {
        if token[index] != word[index] {
            return false;
        }
        index += 1;
    }
    assert(token@ =~= word@);
    true
}

/// The route decision over already-measured argv tokens. The `OsString` → bytes
/// measurement (`OsStrExt::as_bytes`) is the trusted adapter [`is_secret_route`],
/// and it is faithful on Unix: an `OsString` is exactly its bytes, so no
/// non-UTF-8 argument can be mistaken for `secret`.
fn route_is_secret_tokens(argv: &[&[u8]]) -> (out: bool)
    ensures
        out == route_is_secret(argv@.map_values(|token: &[u8]| token@)),
{
    let mut index: usize = 1;
    while index < argv.len()
        invariant
            1 <= index,
            forall|j: int|
                1 <= j < index && j < argv@.len() ==> !(#[trigger] argv@[j]@ =~= secret_word()),
        decreases argv.len() - index,
    {
        if token_equals(argv[index], &b"secret"[..]) {
            assert(argv@.map_values(|token: &[u8]| token@)[index as int] =~= secret_word());
            return true;
        }
        index += 1;
    }
    assert(!route_is_secret(argv@.map_values(|token: &[u8]| token@)));
    false
}

/// Import routes whose parse errors must never render supplied values. The
/// trigger is explicit: no single token in the disjunction (`import` or
/// `help import`) covers every witness on its own.
pub(crate) open spec fn route_is_image_import(argv: Seq<Seq<u8>>) -> bool {
    exists|i: int| 1 <= i && i + 1 < argv.len()
        && #[trigger] argv[i] =~= b"image"@
        && (argv[i + 1] =~= b"import"@
            || (i + 2 < argv.len() && argv[i + 1] =~= b"help"@ && argv[i + 2] =~= b"import"@))
}

fn route_is_image_import_tokens(argv: &[&[u8]]) -> (out: bool)
    ensures out == route_is_image_import(argv@.map_values(|token: &[u8]| token@)),
{
    let mut index: usize = 1;
    while index < argv.len()
        invariant
            1 <= index,
            forall|j: int| 1 <= j < index && j + 1 < argv.len() ==>
                !(#[trigger] argv@[j]@ =~= b"image"@ &&
                    (argv@[j + 1]@ =~= b"import"@ ||
                        (j + 2 < argv.len() && argv@[j + 1]@ =~= b"help"@ && argv@[j + 2]@ =~= b"import"@))),
        decreases argv.len() - index,
    {
        if token_equals(argv[index], &b"image"[..]) && argv.len() - index > 1 {
            if token_equals(argv[index + 1], &b"import"[..]) {
                assert(argv@.map_values(|token: &[u8]| token@)[index as int] =~= b"image"@);
                assert(argv@.map_values(|token: &[u8]| token@)[index as int + 1] =~= b"import"@);
                assert(route_is_image_import(argv@.map_values(|token: &[u8]| token@)));
                return true;
            }
            if argv.len() - index > 2 && token_equals(argv[index + 1], &b"help"[..])
                && token_equals(argv[index + 2], &b"import"[..]) {
                assert(argv@.map_values(|token: &[u8]| token@)[index as int] =~= b"image"@);
                assert(argv@.map_values(|token: &[u8]| token@)[index as int + 1] =~= b"help"@);
                assert(argv@.map_values(|token: &[u8]| token@)[index as int + 2] =~= b"import"@);
                assert(route_is_image_import(argv@.map_values(|token: &[u8]| token@)));
                return true;
            }
        }
        index += 1;
    }
    assert(!route_is_image_import(argv@.map_values(|token: &[u8]| token@)));
    false
}

} // verus!

// Shown under the top-level `agent-vm --help`, after the command list. Names
// no specific tool: the verbs come from configuration, so a hard-coded name
// would be wrong for a user who does not have it.
pub(crate) const TOP_AFTER_HELP: &str = "\
Getting started:
  agent-vm setup       fetch and verify the boot image (run once first)
  cd ~/your-project
  agent-vm <tool>      launch one of the tools listed above

Launch options go before the tool: agent-vm [launch options] <tool> [tool arguments...]
Every argument after the tool is forwarded to it verbatim, including --help and --.
Built-in commands take their own options after the command and no launch options.
`agent-vm help <tool>` shows examples; `agent-vm doctor` shows which config files were
found and what they resolved to.";

/// Shown under `agent-vm --help` when the config could not be read, so the
/// absent verb list is explained rather than silently empty.
const CONFIG_BROKEN_NOTE: &str = "\
Your tool configuration could not be read, so no launch verbs are listed.
Run `agent-vm doctor` to see the error.";

#[derive(Parser)]
#[command(
    name = "agent-vm",
    // The release number plus the source revision this binary was built from
    // (issue #335), captured once by `build.rs`. Never a runtime Git call.
    version = env!("AGENT_VM_BUILD_VERSION"),
    about = "Sandboxed microVMs for AI coding agents.",
    after_help = TOP_AFTER_HELP
)]
struct Cli {
    /// Meaningful only before a tool verb; built-ins reject command-line values.
    #[command(flatten)]
    launch: run::Args,
    #[command(subcommand)]
    cmd: Cmd,
}

/// The fixed, compiled-in subcommands. Launch verbs are **not** variants here:
/// they are generated per catalog entry (see [`launch_subcommand`]).
#[derive(Subcommand)]
pub(crate) enum Cmd {
    /// Pull and verify the boot image (run once first).
    Setup(setup::Args),

    /// Refresh the cached boot image.
    Pull(pull::Args),

    /// Explicitly acquire and select a new default boot image.
    Upgrade(crate::boot_image::upgrade::Args),

    /// Forward arguments to the bundled `msb` with agent-vm's MSB_HOME/MSB_PATH
    /// pinned (e.g. `agent-vm msb ls`, `agent-vm msb status`). Relies on
    /// `needs_msb_setup` staying true for this variant — see main().
    Msb(msb_cmd::Args),

    /// Exchange a string between the host and the sandbox.
    Clipboard(clipboard::Args),

    /// Diagnostic / maintenance operations for agent-vm's private
    /// microsandbox state (e.g. --reset-msb-db).
    Doctor(doctor::Args),

    /// Manage agent-vm's own values in the host system keychain.
    Secret(secret::Args),

    /// Inspect the selected boot image, or explicitly build/import a finished
    /// one into agent-vm's own image cache. Nothing boots; only build/import
    /// may invoke Docker.
    Image(crate::image_cmd::Args),

    /// Internal: invoked by msb's interceptor hook for matched OAuth
    /// and scoped GitHub requests. Reads stdin and writes the protocol
    /// response on stdout. Not meant for direct use.
    #[command(name = "_intercept-hook", hide = true)]
    InterceptHook(intercept_hook::Args),
}

/// What [`parse_from`] decided to do. Built-in verbs keep their derived clap
/// types **and** the loaded catalog: only `Cmd::Setup` consumes the ready tool
/// catalog (it verifies every configured tool's command), while `image show`
/// checks catalog health without consuming its entries. Every built-in carries
/// the same catalog a launch *would* have used.
///
/// `catalog` keeps the *deferred* config failure, and the policy over it is
/// deliberately asymmetric: `doctor` diagnoses it, `clipboard`/`_intercept-hook`
/// ignore it (they run inside the guest), `image build`/`import` ignore it, and
/// `image show` treats it as fatal — a report about a selection cannot be
/// trusted when the configuration that would have produced it is broken.
pub(crate) enum Dispatch {
    Builtin {
        cmd: Cmd,
        catalog: Catalog,
        /// Both config tiers' `image` settings, read before the report was
        /// consumed to build the catalog. Carried to `pull`/`setup`/`image show`
        /// so they can select the same image a launch would.
        images: ConfiguredImages,
    },
    // `entry` and `args` are boxed so `Dispatch` does not carry the two large
    // launch-side values inline (clippy `large_enum_variant`); `entry` grew
    // when #161 added the launch's requested credential names.
    Launch {
        entry: Box<CatalogEntry>,
        /// The two tiers' `image` settings (see the `Builtin` arm).
        images: ConfiguredImages,
        /// Verified user authority captured before consuming the report, like images.
        user_network: Option<crate::user_network::UserNetwork>,
        /// The launch options.
        args: Box<run::Args>,
        /// Every argv token after the tool verb, verbatim.
        tool_args: Vec<String>,
    },
}

/// Every subcommand name `build_command` registers that is not a tool,
/// including clap's synthesized `help`. Used for the misspelling check below
/// and asserted against `config::RESERVED_TOOL_NAMES` by a test, so a future
/// built-in cannot silently shadow — or be shadowed by — a config tool.
pub(crate) const BUILTIN_SUBCOMMANDS: &[&str] = &[
    "setup",
    "pull",
    "upgrade",
    "msb",
    "clipboard",
    "doctor",
    "secret",
    "image",
    "_intercept-hook",
    "help",
];

/// The fixed replacement for any unparseable `agent-vm secret …` argv.
///
/// clap renders supplied values on some parse errors — `agent-vm secret set svc
/// --help=SECRET` produces `unexpected value 'SECRET' for '--help'` — and
/// `parse_from` hands those to `error.exit()`, where no downstream handler can
/// intervene. So the whole `secret` subtree gets a value-free error instead.
/// Help and version still render (see the kind whitelist in `parse_from`).
const SECRET_ARGV_ERROR: &str = "\
`agent-vm secret` could not parse its arguments. The arguments are not shown, \
because a secret value may have been among them. Supported forms:
  agent-vm secret set SERVICE     (hidden prompt, or pipe the value on stdin)
  agent-vm secret ls
  agent-vm secret rm SERVICE";

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
    let (catalog, images, user_network) = match config {
        // A dangling `tools` reference is *user* input, so it must degrade to
        // the deferred-error path (ADR-0015) rather than `?`-propagate and take
        // `doctor`/`--help`/`clipboard` down with it. The readable `image` is
        // captured first so a catalog error cannot erase it (§5.3).
        Ok(report) => {
            let images = report.images().clone();
            let user_network = report.user_network().cloned();
            match report.into_launch_catalog() {
                Ok(catalog) => (Catalog::Ready(catalog), images, user_network),
                Err(error) => (Catalog::Broken(error), images, None),
            }
        }
        // The configured tiers are unknown, so the recovery builtins fall back
        // to `--image`/env or the default boot image (D7).
        Err(error) => (Catalog::Broken(error), ConfiguredImages::default(), None),
    };

    // Collected so the `secret` scrub below can look at the verb without
    // consuming the iterator twice; the bound is already `Into<OsString>`.
    let argv: Vec<OsString> = argv.into_iter().map(Into::into).collect();
    let secret_route = is_secret_route(&argv);
    let import_route = is_image_import_route(&argv);

    let mut command = build_command(&catalog);
    if argv.len() <= 1 {
        command = command_without_launch_env(&command);
    }
    let matches = match command.clone().try_get_matches_from(&argv) {
        Ok(matches) => matches,
        Err(error) => match (!clap_outcome_is_help_or_version(error.kind()))
            .then(|| reparse_without_launch_env(&command, &argv, &catalog))
            .flatten()
        {
            Some(matches) => matches,
            None => {
                // `secret` may have carried a value in any position on either entry
                // path, and clap prints supplied values on some parse errors, so
                // replace every non-help, non-version error in that subtree with a
                // fixed value-free message. A whitelist of *kinds*, not of argv
                // shapes, so a future clap error variant is scrubbed by default.
                if secret_route && !clap_outcome_is_help_or_version(error.kind()) {
                    return Err(anyhow!(SECRET_ARGV_ERROR));
                }
                if import_route && !clap_outcome_is_help_or_version(error.kind()) {
                    return Err(anyhow::Error::new(import_argv_error(&command, &error)));
                }
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
        },
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
            match catalog.take_entry(name) {
                Some(entry) => {
                    let mut args = run::Args::from_arg_matches(&matches)?;
                    args.image.reconcile(&matches);
                    Ok(Dispatch::Launch {
                        entry: Box::new(entry),
                        images,
                        user_network,
                        args: Box::new(args),
                        tool_args: tool_args(
                            &argv,
                            sub.get_many::<String>(TOOL_ARGS)
                                .map(|values| values.cloned().collect())
                                .unwrap_or_default(),
                        ),
                    })
                }
                // Not a tool, so a fixed built-in: the two name sets are disjoint
                // (`RESERVED_TOOL_NAMES`, asserted by a test) and external
                // subcommands are off on this path, so clap could not have accepted
                // anything else. The catalog (minus the taken launch entry, which
                // only a launch verb would have matched) is carried to the built-in
                // so `setup` can read it.
                None => {
                    reject_launch_options(&mut command, &matches, name)?;
                    let mut cmd = Cli::from_arg_matches(&matches)?.cmd;
                    reconcile_image_args(sub, &mut cmd);
                    validate_builtin_args(&command, &cmd)?;
                    Ok(Dispatch::Builtin {
                        cmd,
                        catalog: Catalog::Ready(catalog),
                        images,
                    })
                }
            }
        }
        (Some((name, sub)), Catalog::Broken(config_error)) => {
            // A registered built-in still works; anything else is an unknown
            // verb clap accepted as an external subcommand, and carries the
            // config error.
            match Cli::from_arg_matches(&matches) {
                Ok(mut cli) => {
                    reject_launch_options(&mut command, &matches, name)?;
                    reconcile_image_args(sub, &mut cli.cmd);
                    validate_builtin_args(&command, &cli.cmd)?;
                    Ok(Dispatch::Builtin {
                        cmd: cli.cmd,
                        catalog: Catalog::Broken(config_error),
                        images,
                    })
                }
                Err(_) => Err(config_error_with_hint(&config_error, name)),
            }
        }
    }
}

/// [`ImageArgs::reconcile`] on whichever built-in declares `--image`.
///
/// Deliberately exhaustive rather than `_ => {}`: it forces whoever adds a
/// `Cmd` variant to say whether that verb carries the image argument. A
/// wildcard would let a new `--image` verb skip the origin/env-empty rule
/// silently, which is exactly the bug (issue #189).
fn reconcile_image_args(sub: &clap::ArgMatches, cmd: &mut Cmd) {
    match cmd {
        Cmd::Pull(args) => args.image.reconcile(sub),
        Cmd::Setup(args) => args.image.reconcile(sub),
        // The `image` group deliberately carries no `ImageArgs`: `build`'s and
        // `import`'s `--tag` is a result reference in msb's cache, not a launch
        // image selection, and `show` reads `AGENT_VM_IMAGE_TAG` itself through
        // `boot_image` (where empty-is-unset and non-Unicode refusal live). None
        // of them consumes a `--image` override.
        Cmd::Msb(_)
        | Cmd::Clipboard(_)
        | Cmd::Doctor(_)
        | Cmd::Secret(_)
        | Cmd::Upgrade(_)
        | Cmd::Image(_)
        | Cmd::InterceptHook(_) => {}
    }
}

/// Whether any token after the binary name is `secret`, regardless of position.
///
/// The decision is the verified [`route_is_secret_tokens`]; this function is the
/// trusted `OsString` → bytes adapter.
fn is_secret_route(argv: &[OsString]) -> bool {
    let tokens: Vec<&[u8]> = argv.iter().map(|arg| arg.as_bytes()).collect();
    route_is_secret_tokens(&tokens)
}

/// Help and version are not failures: clap's own `exit()` writes them to
/// stdout with status 0, so the `secret` scrub must not turn them into an
/// error. Every other kind in that subtree is replaced by [`SECRET_ARGV_ERROR`]
/// because clap renders supplied values on some of them.
fn clap_outcome_is_help_or_version(kind: clap::error::ErrorKind) -> bool {
    matches!(
        kind,
        clap::error::ErrorKind::DisplayHelp
            | clap::error::ErrorKind::DisplayVersion
            | clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
    )
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
    let short = match catalog {
        Catalog::Ready(_) => TOP_AFTER_HELP.to_owned(),
        Catalog::Broken(_) => format!("{TOP_AFTER_HELP}\n\n{CONFIG_BROKEN_NOTE}"),
    };
    command
        .after_help(short.clone())
        .after_long_help(format!("{short}\n\n{}", run::LAUNCH_OPTIONS_LONG_HELP))
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

/// A raw tool verb: no flags or help flag can claim a tool argument.
/// Only validated tool names, never guest commands, enter rendered help.
fn launch_subcommand(tool: &Tool) -> clap::Command {
    clap::Command::new(tool.name().to_owned())
        .about(format!(
            "Launch {} in a per-project sandbox; tool arguments are forwarded verbatim",
            tool.name()
        ))
        .disable_help_flag(true)
        .arg(
            clap::Arg::new(TOOL_ARGS)
                .value_name("TOOL_ARGS")
                .help("Forwarded to the tool verbatim, including --help and --")
                .num_args(0..)
                .action(clap::ArgAction::Append)
                .trailing_var_arg(true)
                .allow_hyphen_values(true),
        )
        .after_help(run::LAUNCH_AFTER_HELP)
}

/// The id of a tool verb's single positional: every **tool argument**.
const TOOL_ARGS: &str = "tool_args";

/// Every argv token after the tool verb, verbatim.
///
/// clap delivers them as `values`, a suffix of `argv` with one exception: it
/// consumes a `--` that directly follows the verb, even under
/// `trailing_var_arg`. That is the only token it can drop (the tool
/// subcommand has no flags, no subcommands and no help flag), and the verb
/// itself is never `--` (a tool name cannot start with `-`), so a `--` just
/// before the suffix is the consumed one and is restored.
fn tool_args(argv: &[OsString], values: Vec<String>) -> Vec<String> {
    let consumed_escape = argv
        .len()
        .checked_sub(values.len() + 1)
        .is_some_and(|index| argv[index] == *"--");
    if consumed_escape {
        std::iter::once("--".to_owned()).chain(values).collect()
    } else {
        values
    }
}

/// Every **launch option**, read from [`run::Args`] itself so a new launch
/// option is covered without a list to keep in step.
fn launch_options() -> Vec<clap::Arg> {
    run::Args::augment_args(clap::Command::new("launch-options"))
        .get_arguments()
        .cloned()
        .collect()
}

/// Remove only the top-level launch options' env bindings. Built-in
/// subcommands keep their own bindings (notably pull/setup's --image).
fn command_without_launch_env(command: &clap::Command) -> clap::Command {
    let launch = launch_options();
    command.clone().mut_args(|arg| {
        if launch.iter().any(|option| option.get_id() == arg.get_id()) {
            arg.env(None)
        } else {
            arg
        }
    })
}

/// A launch option's environment binding (`AGENT_VM_MEMORY_GIB`, `AGENT_VM_CPUS`,
/// `AGENT_VM_IMAGE_TAG`) lives on the top-level command, so clap reads and
/// validates it for every verb. A malformed value must still fail a launch,
/// but must not take down a built-in that never reads it — `doctor` reports an
/// unreadable `AGENT_VM_IMAGE_TAG` itself. So retry without those bindings,
/// and keep the retry only when the verb does not launch.
fn reparse_without_launch_env(
    command: &clap::Command,
    argv: &[OsString],
    catalog: &Catalog,
) -> Option<clap::ArgMatches> {
    let matches = command_without_launch_env(command)
        .try_get_matches_from(argv)
        .ok()?;
    let verb = matches.subcommand_name()?;
    let launches = matches!(catalog, Catalog::Ready(_)) && !BUILTIN_SUBCOMMANDS.contains(&verb);
    (!launches).then_some(matches)
}

/// A built-in takes no launch options. Only a value typed on the command
/// line counts: an environment variable (`AGENT_VM_IMAGE_TAG`, …) or a default
/// is not a misplaced option. Names the first one in argv and never a value,
/// so the message is safe on the `secret` route.
fn reject_launch_options(
    command: &mut clap::Command,
    matches: &clap::ArgMatches,
    verb: &str,
) -> Result<()> {
    let misplaced = launch_options()
        .into_iter()
        .filter(|option| {
            matches.value_source(option.get_id().as_str())
                == Some(clap::parser::ValueSource::CommandLine)
        })
        .min_by_key(|option| matches.index_of(option.get_id().as_str()));
    match misplaced {
        None => Ok(()),
        Some(option) => {
            let long = option
                .get_long()
                .unwrap_or_else(|| option.get_id().as_str());
            Err(anyhow::Error::new(command.error(
                clap::error::ErrorKind::ArgumentConflict,
                format!(
                    "the launch option '--{long}' cannot be used with '{verb}': \
                     launch options apply only to tool verbs \
                     (agent-vm [launch options] <tool>)"
                ),
            )))
        }
    }
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

fn is_image_import_route(argv: &[OsString]) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    let tokens: Vec<&[u8]> = argv
        .iter()
        .map(|token| token.as_os_str().as_bytes())
        .collect();
    route_is_image_import_tokens(&tokens)
}

/// The fixed usage line for `image import`; names the optional-`--tag` form
/// truthfully rather than clap's rendering of the current argv.
const IMAGE_IMPORT_USAGE: &str =
    "agent-vm image import <--docker <REF> [--tag <REF>]|--input <PATH> --tag <REF>>";

/// A value-free `agent-vm image import` usage error with our own fixed usage
/// and the caller's fixed text. Never renders the original clap error, which
/// may carry arbitrary supplied values.
fn import_usage_error(
    command: &clap::Command,
    kind: clap::error::ErrorKind,
    text: impl Into<String>,
) -> clap::Error {
    let mut import = command
        .find_subcommand("image")
        .and_then(|image| image.find_subcommand("import"))
        .cloned()
        .unwrap_or_else(|| clap::Command::new("import"))
        .bin_name("agent-vm image import")
        .override_usage(IMAGE_IMPORT_USAGE);
    import.error(kind, text.into())
}

fn import_argv_error(command: &clap::Command, error: &clap::Error) -> clap::Error {
    use clap::error::{ContextKind, ContextValue, ErrorKind};
    let text = match error.kind() {
        ErrorKind::ArgumentConflict => "`agent-vm image import` accepts exactly one source, --docker REF or --input PATH, and at most one --tag REF; the arguments are not shown".to_string(),
        ErrorKind::MissingRequiredArgument => "`agent-vm image import` needs exactly one source, --docker REF or --input PATH; --tag REF is required with --input and defaults to --docker".to_string(),
        // The argument is accepted; its value is missing (`--tag` last on the
        // line). Never clap's own rendering: it would restate the argv.
        ErrorKind::InvalidValue => {
            "`agent-vm image import`: an option is missing its value; the arguments are not shown".to_string()
        }
        ErrorKind::ValueValidation => {
            match (error.get(ContextKind::InvalidArg), std::error::Error::source(error)) {
                (Some(ContextValue::String(arg)), Some(reason)) if arg == "--tag <REF>" || arg == "--docker <REF>" => format!("invalid value for {arg}: {reason}"),
                _ => "`agent-vm image import`: an argument value was rejected; the value is not shown".to_string(),
            }
        }
        _ => "`agent-vm image import` does not accept that argument; the arguments are not shown. Supported: --docker REF [--tag REF] | --input PATH --tag REF".to_string(),
    };
    import_usage_error(command, error.kind(), text)
}

/// Post-parse validation for built-in inputs whose value clap accepts but whose
/// verb cannot act on it. Runs on the ready *and* the broken catalog path, and
/// is input-only: it stats no file and resolves no configuration.
///
/// Deliberately exhaustive over `Cmd` so a new verb must state whether it needs
/// this. Today only `image import` does: its result reference can be inferred
/// from `--docker`, which must be refused as a usage error (exit 2) before the
/// MSB prologue rather than surfacing later as an operational failure.
fn validate_builtin_args(command: &clap::Command, cmd: &Cmd) -> Result<()> {
    let validated = match cmd {
        Cmd::Image(args) => args.validate_result_reference(),
        Cmd::Setup(_)
        | Cmd::Pull(_)
        | Cmd::Upgrade(_)
        | Cmd::Msb(_)
        | Cmd::Clipboard(_)
        | Cmd::Doctor(_)
        | Cmd::Secret(_)
        | Cmd::InterceptHook(_) => Ok(()),
    };
    validated.map_err(|error| {
        // The value-free reason is fixed text from the result-reference or
        // inference boundary; the rejected token is never attached.
        anyhow::Error::new(import_usage_error(
            command,
            clap::error::ErrorKind::ValueValidation,
            format!("`agent-vm image import`: {error}"),
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ConfigPaths, LaunchCatalog, RESERVED_TOOL_NAMES};
    use std::path::Path;

    const MYTOOL: &str = "[[tools]]\nname = \"mytool\"\ncommand = \"my-agent\"\n";
    const SHELL_ONLY: &str =
        "[[tools]]\nname = \"shell\"\ncommand = \"bash\"\ninteractive_shell = true\n";

    fn launch_of(dispatch: Dispatch) -> (Box<run::Args>, Vec<String>) {
        match dispatch {
            Dispatch::Launch {
                args, tool_args, ..
            } => (args, tool_args),
            Dispatch::Builtin { .. } => panic!("expected a launch"),
        }
    }

    #[test]
    fn launch_options_before_the_verb_configure_the_launch() {
        let mut env = crate::test_env::guard();
        for name in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(name);
        }
        let (args, tool_args) = launch_of(
            parse_from(
                [
                    "agent-vm", "--mount", "/x", "--memory", "4", "mytool", "--resume",
                ],
                Ok(report_from(MYTOOL)),
            )
            .unwrap(),
        );
        assert_eq!(args.mount, ["/x"]);
        assert_eq!(args.memory, 4);
        assert_eq!(tool_args, ["--resume"]);
        let (args, tool_args) = launch_of(
            parse_from(
                [
                    "agent-vm",
                    "--memory",
                    "4",
                    "--cpus",
                    "2",
                    "-p",
                    "8080:3000",
                    "--root",
                    "--no-git",
                    "mytool",
                ],
                Ok(report_from(MYTOOL)),
            )
            .unwrap(),
        );
        assert_eq!(args.memory, 4);
        assert!(args.root);
        assert!(tool_args.is_empty());
        let (args, tool_args) = launch_of(
            parse_from(
                ["agent-vm", "--image", "x", "shell", "my-program"],
                Ok(report_from(MYTOOL)),
            )
            .unwrap(),
        );
        assert!(args.image.requested().unwrap().is_some());
        assert_eq!(tool_args, ["my-program"]);
    }

    #[test]
    fn every_token_after_the_verb_is_a_tool_argument() {
        let mut env = crate::test_env::guard();
        for name in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(name);
        }
        for tokens in [
            vec!["--mount", "/x", "--root", "--image", "y"],
            vec!["--help"],
            vec!["-h"],
            vec!["help"],
            vec!["-V"],
            vec!["--", "foo"],
            vec!["--", "--", "x"],
            vec!["--"],
            vec!["a", "--", "b"],
            vec![],
        ] {
            let argv: Vec<_> = ["agent-vm", "mytool"]
                .into_iter()
                .chain(tokens.iter().copied())
                .collect();
            let (args, tool_args) = launch_of(parse_from(argv, Ok(report_from(MYTOOL))).unwrap());
            assert_eq!(tool_args, tokens);
            assert!(args.mount.is_empty());
            assert!(!args.root);
            assert!(args.image.requested().unwrap().is_none());
        }
    }

    #[test]
    fn a_launch_option_before_a_builtin_is_a_usage_error() {
        let mut env = crate::test_env::guard();
        for name in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(name);
        }
        for broken in [false, true] {
            for (argv, option, verb) in [
                (
                    vec!["agent-vm", "--mount", "/x", "doctor"],
                    "--mount",
                    "doctor",
                ),
                (vec!["agent-vm", "-p", "1:2", "pull"], "--publish", "pull"),
                (
                    vec!["agent-vm", "--root", "--mount", "/x", "doctor"],
                    "--root",
                    "doctor",
                ),
                (
                    vec!["agent-vm", "--mount", "sk-ant-REAL-VALUE", "secret", "ls"],
                    "--mount",
                    "secret",
                ),
            ] {
                let config = if broken {
                    Err(anyhow::anyhow!("broken"))
                } else {
                    Ok(report_from(MYTOOL))
                };
                let error = parse_from(argv, config).err().expect("misplaced option");
                let usage = error.downcast_ref::<clap::Error>().unwrap();
                assert_eq!(usage.kind(), clap::error::ErrorKind::ArgumentConflict);
                assert_eq!(usage.exit_code(), 2);
                let text = usage.to_string();
                assert!(
                    text.contains(&format!("'{option}'")) && text.contains(&format!("'{verb}'")),
                    "{text}"
                );
                assert!(!text.contains("sk-ant"));
            }
        }
    }

    #[test]
    fn environment_values_are_not_misplaced_launch_options() {
        let mut env = crate::test_env::guard();
        env.set_var("AGENT_VM_IMAGE_TAG", "env:1");
        env.set_var("AGENT_VM_MEMORY_GIB", "4");
        env.remove_var("AGENT_VM_CPUS");
        for broken in [false, true] {
            for verb in ["pull", "doctor"] {
                let config = if broken {
                    Err(anyhow::anyhow!("broken"))
                } else {
                    Ok(report_from(MYTOOL))
                };
                assert!(matches!(
                    parse_from(["agent-vm", verb], config).unwrap(),
                    Dispatch::Builtin { .. }
                ));
            }
        }
    }

    #[test]
    fn a_malformed_launch_env_value_fails_a_launch_but_not_a_builtin() {
        let mut env = crate::test_env::guard();
        env.set_var("AGENT_VM_MEMORY_GIB", "abc");
        env.remove_var("AGENT_VM_CPUS");
        env.remove_var("AGENT_VM_IMAGE_TAG");
        for argv in [vec!["agent-vm", "doctor"], vec!["agent-vm", "secret", "ls"]] {
            assert!(matches!(
                parse_from(argv, Ok(report_from(SHELL_ONLY))).unwrap(),
                Dispatch::Builtin { .. }
            ));
        }
        let catalog = Catalog::Ready(report_from(SHELL_ONLY).into_launch_catalog().unwrap());
        let command = build_command(&catalog);
        let argv: Vec<OsString> = ["agent-vm", "shell"].into_iter().map(Into::into).collect();
        assert_eq!(
            command
                .clone()
                .try_get_matches_from(&argv)
                .unwrap_err()
                .kind(),
            clap::error::ErrorKind::ValueValidation
        );
        assert!(reparse_without_launch_env(&command, &argv, &catalog).is_none());
        let error = parse_from(
            [
                "agent-vm",
                "secret",
                "set",
                "svc",
                "--help=sk-ant-REAL-VALUE",
            ],
            Ok(report_from(SHELL_ONLY)),
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains(SECRET_ARGV_ERROR));
        assert!(!error.to_string().contains("sk-ant"));
    }

    #[test]
    fn a_broken_config_still_reports_its_error_after_launch_options() {
        let mut env = crate::test_env::guard();
        env.remove_var("AGENT_VM_IMAGE_TAG");
        env.remove_var("AGENT_VM_CPUS");
        for memory in ["4", "abc"] {
            env.set_var("AGENT_VM_MEMORY_GIB", memory);
            let error = parse_from(
                ["agent-vm", "--mount", "x", "anything"],
                Err(anyhow::anyhow!("config: broken on purpose")),
            )
            .err()
            .unwrap();
            assert!(error.to_string().contains("config: broken on purpose"));
            assert!(!error.to_string().contains("unrecognized subcommand"));
            assert!(error.downcast_ref::<clap::Error>().is_none());
        }
    }

    #[test]
    fn unknown_or_spaced_flags_before_the_verb_are_usage_errors() {
        let mut env = crate::test_env::guard();
        for name in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(name);
        }
        let command = build_command(&Catalog::Ready(
            report_from(SHELL_ONLY).into_launch_catalog().unwrap(),
        ));
        for argv in [
            vec!["agent-vm", "--bogus", "shell"],
            vec!["agent-vm", "--allow-lan", "false", "shell"],
        ] {
            assert_eq!(
                command
                    .clone()
                    .try_get_matches_from(argv)
                    .unwrap_err()
                    .exit_code(),
                2
            );
        }
    }

    #[test]
    fn is_secret_route_finds_secret_anywhere_after_the_binary() {
        for (argv, expected) in [
            (vec!["agent-vm", "secret", "ls"], true),
            (vec!["agent-vm", "--root", "secret", "ls"], true),
            (vec!["agent-vm", "help", "secret"], true),
            (
                vec!["agent-vm", "--memory", "4", "help", "secret", "set"],
                true,
            ),
            (vec!["agent-vm"], false),
            (vec!["secret"], false),
            (vec!["agent-vm", "secretx"], false),
            (vec!["agent-vm", "shell"], false),
        ] {
            let argv: Vec<OsString> = argv.into_iter().map(Into::into).collect();
            assert_eq!(is_secret_route(&argv), expected, "{argv:?}");
        }
    }

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
        let mut env = crate::test_env::guard();
        for name in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(name);
        }
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
        let mut env = crate::test_env::guard();
        for name in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(name);
        }
        // Set equality, not just built-in ⊆ reserved: a reserved name with no
        // built-in would silently forbid a tool name for no reason, which is
        // the other half of the drift this test exists to catch.
        let builtins: std::collections::BTreeSet<&str> =
            BUILTIN_SUBCOMMANDS.iter().copied().collect();
        let reserved: std::collections::BTreeSet<&str> =
            RESERVED_TOOL_NAMES.iter().copied().collect();
        assert_eq!(builtins, reserved);
    }

    // -- T8: a one-tool catalog registers only it plus the shell fallback --

    #[test]
    fn a_claude_only_catalog_registers_only_claude_and_shell() {
        let mut env = crate::test_env::guard();
        for name in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(name);
        }
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

    #[test]
    fn parse_from_carries_the_image_tiers_without_the_catalog() {
        let mut env = crate::test_env::guard();
        for name in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(name);
        }
        // A project `image` and a tool declaration: the dispatch must carry both
        // the tool entry and the readable image tiers (§5.3).
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("config.toml");
        std::fs::write(
            &project,
            "image = \"localhost:1/p:latest\"\n[[tools]]\nname = \"t\"\ncommand = \"t\"\n",
        )
        .unwrap();
        let report = crate::config::load(&ConfigPaths {
            user: Some(dir.path().join("no-user-config.toml")),
            project,
        })
        .unwrap();
        let images = report.images().clone();
        let dispatch = parse_from(["agent-vm", "t"], Ok(report)).expect("t parses");
        match dispatch {
            Dispatch::Launch {
                entry,
                images: carried,
                ..
            } => {
                assert_eq!(entry.tool().name(), "t");
                assert_eq!(carried, images);
            }
            Dispatch::Builtin { .. } => panic!("t is a launch verb"),
        }
    }

    // -- image argument: typed beats env, empty env is unset --------------

    /// The single `--image`/`AGENT_VM_IMAGE_TAG` precedence table, driven
    /// through [`parse_from`] — the seam that can see clap's `ValueSource` — so a
    /// future refactor that stops reconciling fails here. The environment is
    /// pinned under [`crate::test_env::guard`] so the process-wide variable
    /// cannot race a parallel test.
    #[test]
    fn an_empty_environment_image_tag_is_unset_and_a_typed_flag_wins() {
        struct Case {
            env: Option<&'static str>,
            argv: &'static [&'static str],
            expected: Option<(&'static str, OverrideSource)>,
        }
        impl std::fmt::Debug for Case {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("Case")
                    .field("env", &self.env)
                    .field("argv", &self.argv)
                    .field("expected", &self.expected.map(|(reference, _)| reference))
                    .finish()
            }
        }
        let cases = [
            Case {
                env: Some("env:1"),
                argv: &[],
                expected: Some(("env:1", OverrideSource::Environment)),
            },
            Case {
                env: Some("env:1"),
                argv: &["--image", "cli:1"],
                expected: Some(("cli:1", OverrideSource::CommandLine)),
            },
            // An empty environment value is unset, not an empty reference.
            Case {
                env: Some(""),
                argv: &[],
                expected: None,
            },
            // An empty env does not mask a typed flag.
            Case {
                env: Some(""),
                argv: &["--image", "cli:1"],
                expected: Some(("cli:1", OverrideSource::CommandLine)),
            },
            // Whitespace is *present*, not unset (never trimmed).
            Case {
                env: Some(" "),
                argv: &[],
                expected: Some((" ", OverrideSource::Environment)),
            },
            Case {
                env: None,
                argv: &[],
                expected: None,
            },
        ];

        let mut env = crate::test_env::guard();
        for case in cases {
            match case.env {
                Some(value) => env.set_var("AGENT_VM_IMAGE_TAG", value),
                None => env.remove_var("AGENT_VM_IMAGE_TAG"),
            }
            let mut argv = vec!["agent-vm", "pull"];
            argv.extend_from_slice(case.argv);
            let dispatch = parse_from(argv, Ok(report_from("tools = []\n")))
                .unwrap_or_else(|error| panic!("case {case:?} must parse: {error}"));
            let requested = match dispatch {
                Dispatch::Builtin {
                    cmd: Cmd::Pull(args),
                    ..
                } => args.image.requested().expect("a valid override or none"),
                _ => panic!("pull must dispatch as a built-in"),
            };
            match case.expected {
                Some((reference, source)) => {
                    let override_ = requested.expect("an override is present");
                    assert_eq!(override_.reference().as_str(), reference);
                    assert_eq!(override_.source(), source);
                }
                None => assert!(requested.is_none(), "empty env must be unset"),
            }
        }
    }

    /// Every dispatch arm that carries the image argument runs the same
    /// reconciliation. The launch arm, the ready-catalog built-in arm (`pull`,
    /// `setup`) and the broken-config built-in arm each call it separately, so
    /// dropping any one of them would bring the bug back silently.
    #[test]
    fn every_dispatch_arm_reconciles_the_image_arg() {
        let mut env = crate::test_env::guard();
        env.set_var("AGENT_VM_IMAGE_TAG", "env:1");

        let source_of = |requested: Option<crate::boot_image::ImageOverride>| {
            requested.map(|override_| override_.source())
        };

        // The launch arm (a tool verb): env only.
        let dispatch = parse_from(["agent-vm", "shell"], Ok(report_from("tools = []\n")))
            .expect("shell parses");
        match dispatch {
            Dispatch::Launch { args, .. } => {
                assert_eq!(
                    source_of(args.image.requested().unwrap()),
                    Some(OverrideSource::Environment)
                );
            }
            Dispatch::Builtin { .. } => panic!("shell is a launch verb"),
        }

        // The launch arm with a typed flag beats the env.
        let dispatch = parse_from(
            ["agent-vm", "--image", "cli:1", "shell"],
            Ok(report_from("tools = []\n")),
        )
        .expect("shell parses");
        match dispatch {
            Dispatch::Launch { args, .. } => {
                let requested = args.image.requested().unwrap().expect("present");
                assert_eq!(requested.reference().as_str(), "cli:1");
                assert_eq!(requested.source(), OverrideSource::CommandLine);
            }
            Dispatch::Builtin { .. } => panic!("shell is a launch verb"),
        }

        // The ready-catalog built-in arm, and the deferred-config-error arm.
        for verb in ["pull", "setup"] {
            for catalog in [
                Ok(report_from("tools = []\n")),
                Err(anyhow::anyhow!("broken")),
            ] {
                let dispatch = parse_from(["agent-vm", verb, "--image", "cli:1"], catalog)
                    .unwrap_or_else(|error| panic!("{verb} must parse: {error}"));
                let requested = match dispatch {
                    Dispatch::Builtin {
                        cmd: Cmd::Pull(args),
                        ..
                    } => args.image.requested().unwrap(),
                    Dispatch::Builtin {
                        cmd: Cmd::Setup(args),
                        ..
                    } => args.image.requested().unwrap(),
                    _ => panic!("{verb} must dispatch as a built-in"),
                };
                let requested = requested.expect("present");
                assert_eq!(requested.reference().as_str(), "cli:1", "{verb}");
                assert_eq!(requested.source(), OverrideSource::CommandLine, "{verb}");
            }
        }
    }

    #[test]
    fn parse_from_dispatches_a_project_tool_and_a_builtin() {
        let mut env = crate::test_env::guard();
        for name in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(name);
        }
        let body = "[[tools]]\nname = \"mytool\"\ncommand = \"my-agent\"\nargs = [\"--fast\"]\n";

        // A launch verb carries the resolved tool and its tool arguments.
        let dispatch = parse_from(["agent-vm", "mytool", "--resume"], Ok(report_from(body)))
            .expect("mytool parses");
        match dispatch {
            Dispatch::Launch {
                entry, tool_args, ..
            } => {
                assert_eq!(entry.tool().name(), "mytool");
                assert_eq!(entry.tool().command(), "my-agent");
                assert_eq!(tool_args, ["--resume"]);
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
        let mut env = crate::test_env::guard();
        for name in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(name);
        }
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

    #[test]
    fn network_table_rejection_is_a_deferred_catalog_error() {
        let mut env = crate::test_env::guard();
        for name in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(name);
        }
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project.toml");
        std::fs::write(&project, "[network]\nallow_lan = true").unwrap();
        let load = || {
            crate::config::load(&crate::config::ConfigPaths {
                user: None,
                project: project.clone(),
            })
        };
        assert!(matches!(
            parse_from(["agent-vm", "doctor"], load()).unwrap(),
            Dispatch::Builtin {
                cmd: Cmd::Doctor(_),
                ..
            }
        ));
        assert!(matches!(
            parse_from(["agent-vm", "msb", "--version"], load()).unwrap(),
            Dispatch::Builtin {
                cmd: Cmd::Msb(_),
                ..
            }
        ));
        let help = build_command(&Catalog::Broken(load().unwrap_err()))
            .try_get_matches_from(["agent-vm", "--help"])
            .unwrap_err();
        assert_eq!(help.kind(), clap::error::ErrorKind::DisplayHelp);
        assert!(help.to_string().contains(CONFIG_BROKEN_NOTE));
        let error = parse_from(["agent-vm", "shell"], load())
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("network.allow_lan"));
        assert!(error.contains("network access cannot be granted by the project config"));
    }

    #[test]
    fn parse_from_carries_the_user_network_into_a_launch() {
        let mut env = crate::test_env::guard();
        for name in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(name);
        }
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("user.toml");
        std::fs::write(&file, "[network]\nallow_lan = true\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let load = || {
            crate::config::load(&crate::config::ConfigPaths {
                user: Some(file.clone()),
                project: dir.path().join("absent.toml"),
            })
        };
        let expected = load().unwrap().user_network().cloned();
        let Dispatch::Launch { user_network, .. } =
            parse_from(["agent-vm", "shell"], load()).unwrap()
        else {
            panic!("launch")
        };
        assert_eq!(user_network, expected);
        assert!(matches!(
            parse_from(["agent-vm", "doctor"], load()).unwrap(),
            Dispatch::Builtin {
                cmd: Cmd::Doctor(_),
                ..
            }
        ));
    }

    // -- T10: the asymmetric broken-config acceptance criterion -----------

    #[test]
    fn a_broken_config_errors_a_launch_but_a_valid_one_errors_a_missing_tool() {
        let mut env = crate::test_env::guard();
        for name in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(name);
        }
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
        let mut env = crate::test_env::guard();
        for name in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(name);
        }
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
        let mut env = crate::test_env::guard();
        for name in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(name);
        }
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
        assert_eq!(nearest_builtin("imgae"), Some("image"));
        assert_eq!(nearest_builtin("build"), None);
        let mut env = crate::test_env::guard();
        for name in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(name);
        }
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
    fn launch_options_parse_before_the_verb_and_help_is_stable() {
        let mut env = crate::test_env::guard();
        for name in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(name);
        }
        let catalog = report_from(SHELL_ONLY).into_launch_catalog().unwrap();
        let command = build_command(&Catalog::Ready(catalog))
            .term_width(100)
            .mut_args(|arg| arg.hide_env_values(true));
        let mut built = command.clone();
        built.build();
        assert_eq!(
            subcommand_names(&built),
            [
                "setup",
                "pull",
                "upgrade",
                "msb",
                "clipboard",
                "doctor",
                "secret",
                "image",
                "_intercept-hook",
                "shell",
                "help"
            ]
        );
        command
            .clone()
            .try_get_matches_from([
                "agent-vm",
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
                "shell",
                "--agent-flag",
            ])
            .expect("every network option parses before the verb");
        let render = |argv: &[&str]| {
            let error = command
                .clone()
                .try_get_matches_from(argv)
                .expect_err("help is an Err");
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp,
                "{argv:?}"
            );
            normalize_help_whitespace_only_lines(&error.to_string())
        };
        assert_help_fixture(
            "top-help-columns-100.txt",
            &render(&["agent-vm", "--help"]),
            include_str!("../tests/fixtures/top-help-columns-100.txt"),
        );
        assert_help_fixture(
            "top-short-help-columns-100.txt",
            &render(&["agent-vm", "-h"]),
            include_str!("../tests/fixtures/top-short-help-columns-100.txt"),
        );
        assert_help_fixture(
            "help-shell-columns-100.txt",
            &render(&["agent-vm", "help", "shell"]),
            include_str!("../tests/fixtures/help-shell-columns-100.txt"),
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
        let mut env = crate::test_env::guard();
        for name in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(name);
        }
        fn named_tool(haystack: &str) -> Option<&'static str> {
            let tokens: Vec<&str> = haystack
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
                .collect();
            ["dsh", "pi", "claude", "codex", "opencode", "copilot"]
                .into_iter()
                .find(|tool| tokens.contains(tool))
        }

        let short = run::LAUNCH_AFTER_HELP;
        let long = run::LAUNCH_OPTIONS_LONG_HELP;
        for (what, haystack) in [
            ("TOP_AFTER_HELP", TOP_AFTER_HELP),
            (
                "help shell",
                include_str!("../tests/fixtures/help-shell-columns-100.txt"),
            ),
            ("the short launch footer", short),
            ("the long launch footer", long),
            (
                "top-help-columns-100.txt",
                include_str!("../tests/fixtures/top-help-columns-100.txt"),
            ),
            (
                "top-short-help-columns-100.txt",
                include_str!("../tests/fixtures/top-short-help-columns-100.txt"),
            ),
        ] {
            if let Some(tool) = named_tool(haystack) {
                panic!("{what} names {tool}");
            }
        }
    }

    #[test]
    fn broken_config_help_lists_builtins_and_points_at_doctor() {
        let mut env = crate::test_env::guard();
        for name in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(name);
        }
        let command = build_command(&Catalog::Broken(anyhow!("broken on purpose")));
        let mut help = Vec::new();
        command
            .clone()
            .write_long_help(&mut help)
            .expect("the broken-config help renders");
        let help = String::from_utf8(help).unwrap();
        for builtin in [
            "setup",
            "pull",
            "upgrade",
            "msb",
            "clipboard",
            "doctor",
            "secret",
            "image",
        ] {
            assert!(help.contains(builtin), "missing builtin {builtin}: {help}");
        }
        assert!(help.contains("could not be read"), "{help}");
        assert!(help.contains("agent-vm doctor"), "{help}");
    }

    // -- image group: routing, diagnostics and selection handling ------------

    #[test]
    fn is_image_import_route_finds_adjacent_pairs() {
        for (argv, expected) in [
            (vec!["av", "image", "import"], true),
            (vec!["av", "--root", "image", "import"], true),
            (vec!["av", "help", "image", "import"], true),
            (vec!["av", "image", "help", "import"], true),
            (
                vec!["av", "--memory", "4", "image", "import", "--docker", "x"],
                true,
            ),
            (vec!["av", "image", "build"], false),
            (vec!["av", "image"], false),
            (vec!["av", "import"], false),
            (vec!["av", "imagex", "import"], false),
            (vec!["av", "image", "importx"], false),
            (vec!["image", "import"], false),
            (vec!["av", "image", "build", "--tag", "image"], false),
        ] {
            assert_eq!(
                is_image_import_route(&argv.iter().map(OsString::from).collect::<Vec<_>>()),
                expected,
                "{argv:?}"
            );
        }
    }

    #[test]
    fn image_import_parse_errors_are_value_free() {
        use clap::error::ErrorKind::*;
        let mut env = crate::test_env::guard();
        for key in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(key);
        }
        let digest = format!("app:SENTINEL_A5@sha256:{}", "a".repeat(64));
        let inferred_digest = format!("app@sha256:{}", "a".repeat(64));
        for (args, kind, text) in [
            (
                vec![
                    "--docker",
                    "SENTINEL_A1",
                    "--input",
                    "SENTINEL_A2",
                    "--tag",
                    "app:dev",
                ],
                ArgumentConflict,
                "accepts exactly one source",
            ),
            (
                vec!["--tag", "app:SENTINEL_A3"],
                MissingRequiredArgument,
                "needs exactly one source",
            ),
            (
                vec!["--input", "SENTINEL_A4"],
                MissingRequiredArgument,
                "--tag REF is required with --input and defaults to --docker",
            ),
            // Omitted `--tag` + a source that cannot also be a destination:
            // post-parse validation, on both catalog paths.
            (
                vec!["--docker", inferred_digest.as_str()],
                ValueValidation,
                "`agent-vm image import`: --docker cannot supply the default --tag",
            ),
            (
                vec!["--docker", "./SENTINEL_A12"],
                ValueValidation,
                "Pass an explicit mutable --tag REF",
            ),
            (
                vec!["--docker", "x", "--tag", digest.as_str()],
                ValueValidation,
                "invalid value for --tag <REF>",
            ),
            (
                vec!["--docker", "x", "--tag", "./SENTINEL_A6"],
                ValueValidation,
                "invalid value for --tag <REF>",
            ),
            (
                vec!["--docker=-SENTINEL_A7", "--tag", "app:dev"],
                ValueValidation,
                "invalid value for --docker <REF>",
            ),
            (
                vec!["--docker=--privileged", "--tag", "app:dev"],
                ValueValidation,
                "invalid value for --docker <REF>",
            ),
            (
                vec!["--docker", "SENTINEL_A8 x", "--tag", "app:dev"],
                ValueValidation,
                "invalid value for --docker <REF>",
            ),
            (
                vec!["--docker", "x", "--tag"],
                InvalidValue,
                "an option is missing its value",
            ),
            (
                vec!["--docker", "SENTINEL_A4"],
                ValueValidation,
                "Pass an explicit mutable --tag REF",
            ),
            (
                vec![
                    "--docker",
                    "x",
                    "--tag",
                    "app:dev",
                    "--platform",
                    "SENTINEL_A9",
                ],
                UnknownArgument,
                "does not accept that argument",
            ),
            (
                vec![
                    "--docker",
                    "x",
                    "--tag",
                    "app:dev",
                    "--output",
                    "SENTINEL_A10",
                ],
                UnknownArgument,
                "does not accept that argument",
            ),
            (
                vec!["--docker", "x", "--tag", "app:dev", "--load"],
                UnknownArgument,
                "does not accept that argument",
            ),
            (
                vec!["--docker", "x", "--tag", "app:dev", "--push"],
                UnknownArgument,
                "does not accept that argument",
            ),
            (
                vec!["--docker", "x", "--tag", "app:dev", "SENTINEL_A11"],
                UnknownArgument,
                "does not accept that argument",
            ),
            (
                vec!["--docker", "x", "--tag", "app:dev", "--tag", "SENTINEL_A13"],
                ArgumentConflict,
                "accepts exactly one source",
            ),
        ] {
            for broken in [false, true] {
                let config = if broken {
                    Err(anyhow!("broken config"))
                } else {
                    Ok(report_from("tools = []\n"))
                };
                let argv = ["agent-vm", "image", "import"]
                    .into_iter()
                    .chain(args.iter().copied());
                let error = parse_from(argv, config)
                    .err()
                    .unwrap()
                    .downcast::<clap::Error>()
                    .unwrap();
                assert_eq!(error.kind(), kind);
                assert_eq!(error.exit_code(), 2);
                let shown = error.render().to_string();
                assert!(shown.contains(text), "{shown}");
                assert!(
                    !shown.contains("SENTINEL") && !shown.contains("--privileged"),
                    "{shown}"
                );
                assert!(
                    shown.contains(
                        "Usage: agent-vm image import <--docker <REF> [--tag <REF>]|--input <PATH> --tag <REF>>"
                    ),
                    "{shown}"
                );
            }
        }
    }

    #[test]
    fn image_build_parse_errors_keep_clap_text() {
        let mut env = crate::test_env::guard();
        for key in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(key);
        }
        let digest = format!("app:SENTINEL_B1@sha256:{}", "a".repeat(64));
        let error = build_command(&Catalog::Ready(default_catalog()))
            .try_get_matches_from(["agent-vm", "image", "build", "--tag", &digest])
            .unwrap_err();
        let shown = error.render().to_string();
        assert!(
            shown.contains("SENTINEL_B1")
                && shown.contains("cannot be updated by a later build or import"),
            "{shown}"
        );
    }

    #[test]
    fn image_verbs_dispatch_as_builtins_without_taking_an_image_selection() {
        let mut env = crate::test_env::guard();
        for name in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(name);
        }
        let broken: Result<ConfigReport, anyhow::Error> = Err(anyhow!("config: broken on purpose"));
        for config in [Ok(report_from("tools = []\n")), broken] {
            let dispatch = parse_from(
                ["agent-vm", "image", "build", "--tag", "my-app:dev"],
                config,
            )
            .unwrap_or_else(|error| panic!("build must parse: {error:#}"));
            match dispatch {
                Dispatch::Builtin {
                    cmd: Cmd::Image(_), ..
                } => {}
                _ => panic!("build must dispatch as a built-in"),
            }
        }

        for config in [
            Ok(report_from("tools = []\n")),
            Err(anyhow!("broken config")),
        ] {
            assert!(matches!(
                parse_from(
                    [
                        "agent-vm",
                        "image",
                        "import",
                        "--input",
                        "x.tar",
                        "--tag",
                        "my-app:dev"
                    ],
                    config
                )
                .unwrap(),
                Dispatch::Builtin {
                    cmd: Cmd::Image(_),
                    ..
                }
            ));
        }

        // A configured tool named `image` is rejected at validation, so it can
        // never shadow the built-in (asserted over RESERVED_TOOL_NAMES too).
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("config.toml");
        std::fs::write(
            &project,
            "[[tools]]\nname = \"image\"\ncommand = \"build\"\n",
        )
        .unwrap();
        let error = crate::config::load(&ConfigPaths {
            user: Some(dir.path().join("no-user-config.toml")),
            project,
        })
        .expect_err("a tool named image must be refused");
        assert!(format!("{error:#}").contains("reserved"));
    }

    #[test]
    fn build_help_is_available_under_a_ready_and_a_broken_catalog() {
        let mut env = crate::test_env::guard();
        for name in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(name);
        }
        for command in [
            build_command(&Catalog::Ready(default_catalog())),
            build_command(&Catalog::Broken(anyhow!("broken on purpose"))),
        ] {
            let mut help = Vec::new();
            command
                .find_subcommand("image")
                .unwrap()
                .find_subcommand("build")
                .expect("build is registered")
                .clone()
                .bin_name("agent-vm image build")
                .write_long_help(&mut help)
                .expect("build help renders");
            let help = String::from_utf8(help).unwrap();
            assert!(
                help.contains("Import the built image under this reference"),
                "{help}"
            );
            assert!(help.contains("--build-arg"), "{help}");
            let mut import = command
                .find_subcommand("image")
                .unwrap()
                .find_subcommand("import")
                .unwrap()
                .clone();
            let help = import.render_long_help().to_string();
            assert!(
                help.contains("--docker") && help.contains("--input"),
                "{help}"
            );
            for argv in [
                vec!["agent-vm", "image", "import", "--help"],
                vec!["agent-vm", "help", "image", "import"],
                vec!["agent-vm", "image", "help", "import"],
            ] {
                assert_eq!(
                    command
                        .clone()
                        .try_get_matches_from(argv)
                        .unwrap_err()
                        .kind(),
                    clap::error::ErrorKind::DisplayHelp
                );
            }
        }
    }

    #[test]
    fn upgrade_requires_typed_target_independent_of_config_and_environment() {
        let mut env = crate::test_env::guard();
        env.set_var("AGENT_VM_IMAGE_TAG", "ignored:ambient");
        for config in [
            Ok(report_from("image = \"project:tag\"\n")),
            Err(anyhow!("broken TOML")),
        ] {
            assert!(matches!(
                parse_from(
                    ["agent-vm", "upgrade", "--image", "localhost:1234/a:tag"],
                    config
                )
                .unwrap(),
                Dispatch::Builtin {
                    cmd: Cmd::Upgrade(_),
                    ..
                }
            ));
        }
        for args in [
            vec!["agent-vm", "upgrade"],
            vec!["agent-vm", "upgrade", "--image", "/path"],
            vec!["agent-vm", "upgrade", "--image", "a:tag", "--yes"],
        ] {
            assert_eq!(
                build_command(&Catalog::Ready(default_catalog()))
                    .try_get_matches_from(args)
                    .unwrap_err()
                    .exit_code(),
                2
            );
        }
        for args in [
            ["agent-vm", "upgrade", "--help"],
            ["agent-vm", "help", "upgrade"],
        ] {
            let error = build_command(&Catalog::Broken(anyhow!("broken")))
                .try_get_matches_from(args)
                .unwrap_err();
            assert_eq!(error.exit_code(), 0);
            assert!(error.to_string().contains("--image <REF>"));
        }
        let error = build_command(&Catalog::Ready(default_catalog()))
            .try_get_matches_from(["agent-vm", "upgrade"])
            .unwrap_err();
        assert_eq!(error.exit_code(), 2);
    }

    // -- P1/P2: the `secret` verbs dispatch -------------------------------

    /// The parsed `Op` of a `Cmd::Secret` dispatch, so the tests below read the
    /// same fields clap filled.
    fn secret_set_parts(dispatch: Dispatch) -> (String, Vec<String>, Option<String>) {
        match dispatch {
            Dispatch::Builtin {
                cmd: Cmd::Secret(secret::Args { op }),
                ..
            } => match op {
                secret::Op::Set {
                    service,
                    rejected_positional,
                    rejected_token,
                } => (service, rejected_positional, rejected_token),
                _ => panic!("expected `set`"),
            },
            _ => panic!("expected a `secret` built-in"),
        }
    }

    fn secret_op(dispatch: &Dispatch) -> &'static str {
        match dispatch {
            Dispatch::Builtin {
                cmd: Cmd::Secret(secret::Args { op }),
                ..
            } => match op {
                secret::Op::Set { .. } => "set",
                secret::Op::Ls => "ls",
                secret::Op::Rm { .. } => "rm",
            },
            _ => panic!("expected a `secret` built-in"),
        }
    }

    #[test]
    fn secret_verbs_dispatch_with_their_service() {
        let mut env = crate::test_env::guard();
        for name in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(name);
        }
        let dispatch = parse_from(["agent-vm", "secret", "ls"], Ok(report_from("")))
            .expect("`secret ls` parses");
        assert_eq!(secret_op(&dispatch), "ls");

        let dispatch = parse_from(
            ["agent-vm", "secret", "set", "anthropic"],
            Ok(report_from("")),
        )
        .expect("`secret set NAME` parses");
        assert_eq!(secret_op(&dispatch), "set");
        assert_eq!(secret_set_parts(dispatch).0, "anthropic");

        let dispatch = parse_from(
            ["agent-vm", "secret", "rm", "anthropic"],
            Ok(report_from("")),
        )
        .expect("`secret rm NAME` parses");
        assert_eq!(secret_op(&dispatch), "rm");
    }

    /// P2 — the deferred-config-error path builds a different clap command
    /// (no tool subcommands, external subcommands enabled), so `secret` must
    /// be exercised there too.
    #[test]
    fn secret_verbs_still_dispatch_on_the_broken_config_path() {
        let mut env = crate::test_env::guard();
        for name in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(name);
        }
        for argv in [
            vec!["agent-vm", "secret", "ls"],
            vec!["agent-vm", "secret", "set", "anthropic"],
            vec!["agent-vm", "secret", "rm", "anthropic"],
        ] {
            let dispatch = parse_from(argv.clone(), Err(anyhow!("config: broken on purpose")))
                .unwrap_or_else(|error| panic!("{argv:?} must parse: {error:#}"));
            match dispatch {
                Dispatch::Builtin {
                    cmd: Cmd::Secret(_),
                    ..
                } => {}
                _ => panic!("{argv:?} must dispatch as a secret built-in"),
            }
        }
    }

    // -- P5/P6: no `secret` argv shape can render a value ----------------

    /// The shapes clap itself rejects inside the `secret` subtree. The scrub
    /// replaces each with one fixed message, because clap prints supplied
    /// values on some of them (its help flag's attached value, for one). The
    /// needle is interpolated by `format!` and asserted by the same binding, so
    /// a case whose argv no longer carries the needle cannot make the leak
    /// assertion vacuous.
    #[test]
    fn clap_errors_in_the_secret_subtree_are_scrubbed() {
        let mut env = crate::test_env::guard();
        for name in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(name);
        }
        let needle = "sk-ant-REAL-VALUE";
        let flag = format!("--{needle}");
        let attached = format!("--help={needle}");
        let argv = |parts: &[&str]| -> Vec<String> {
            parts.iter().map(|part| (*part).to_owned()).collect()
        };
        let cases = vec![
            argv(&["agent-vm", "--memory", "4", "secret", &flag]),
            argv(&["agent-vm", "--memory", "4", "secret", &attached]),
            argv(&["agent-vm", "--root", "help", "secret", needle]),
            argv(&["agent-vm", "secret", &flag]),
            argv(&["agent-vm", "secret", &attached]),
            argv(&["agent-vm", "secret", "rm", "svc", "extra"]),
            argv(&["agent-vm", "secret", "set"]),
            argv(&["agent-vm", "secret", "bogus-subcommand"]),
            // Both help entry paths descend into the subtree and can render the
            // token they were asked to explain (review finding 1).
            argv(&["agent-vm", "help", "secret", needle]),
            argv(&["agent-vm", "help", "secret", "set", needle]),
            argv(&["agent-vm", "secret", "help", needle]),
        ];
        for argv in cases {
            let error = parse_from(argv.clone(), Ok(report_from("")))
                .err()
                .unwrap_or_else(|| panic!("{argv:?} must be refused"));
            let text = format!("{error:#}");
            assert!(
                text.contains("could not parse its arguments"),
                "{argv:?}: {text}"
            );
            assert!(!text.contains(needle), "{argv:?} echoed the value: {text}");
            assert!(
                !text.contains("sk-ant"),
                "{argv:?} echoed the value: {text}"
            );
        }
    }

    /// The shapes the declared refusal arguments swallow: parsing *succeeds*,
    /// and the value can only have landed in the two refusal fields, which no
    /// code path renders. `secret::run` refuses them (see `secret.rs`'s C3).
    #[test]
    fn swallowed_argument_shapes_confine_the_value_to_the_refusal_fields() {
        let mut env = crate::test_env::guard();
        for name in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(name);
        }
        const SECRET: &str = "sk-ant-REAL-VALUE";
        let cases = vec![
            vec!["agent-vm", "secret", "set", "svc", SECRET],
            vec!["agent-vm", "secret", "set", "svc", "--token", SECRET],
            vec!["agent-vm", "secret", "set", "svc", "--", SECRET],
            vec!["agent-vm", "secret", "set", SECRET, "extra"],
        ];
        for argv in cases {
            let dispatch = parse_from(argv.clone(), Ok(report_from("")))
                .unwrap_or_else(|error| panic!("{argv:?} must parse: {error:#}"));
            let (service, positional, token) = secret_set_parts(dispatch);
            let value_bearing = std::iter::once(service.as_str())
                .chain(positional.iter().map(String::as_str))
                .chain(token.as_deref())
                .filter(|text| text.contains(SECRET))
                .count();
            assert_eq!(
                value_bearing, 1,
                "{argv:?} must carry the value exactly once, in the fields nothing renders"
            );
            // The value can only sit in the *name* slot if a refusal field is
            // also populated, so layer 1 still refuses it (see `secret.rs` C3)
            // rather than storing a value the user never meant as a name.
            assert!(
                service.as_str() != SECRET || !positional.is_empty() || token.is_some(),
                "{argv:?}: a value in the name slot must still be refused by layer 1"
            );
        }

        // Extra positionals after a valid name need no value at all to be
        // refused: they land in the same refusal field.
        let dispatch = parse_from(
            ["agent-vm", "secret", "set", "svc", "a", "b"],
            Ok(report_from("")),
        )
        .expect("the refusal field swallows them");
        let (service, positional, token) = secret_set_parts(dispatch);
        assert_eq!(service, "svc");
        assert_eq!(positional, ["a", "b"]);
        assert!(token.is_none());
    }

    /// P6 — help and version are the scrub's whitelist, so `secret --help`,
    /// `secret set --help` and `help secret` still render.
    #[test]
    fn secret_help_is_never_scrubbed() {
        let mut env = crate::test_env::guard();
        for name in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(name);
        }
        let command = build_command(&Catalog::Ready(default_catalog()));
        for argv in [
            vec!["agent-vm", "secret", "--help"],
            vec!["agent-vm", "secret", "set", "--help"],
            vec!["agent-vm", "help", "secret"],
        ] {
            let error = command
                .clone()
                .try_get_matches_from(argv.clone())
                .expect_err("clap returns help as an Err");
            assert!(
                clap_outcome_is_help_or_version(error.kind()),
                "{argv:?} must survive the scrub: {:?}",
                error.kind()
            );
            let rendered = error.to_string();
            assert!(rendered.contains("keychain"), "{argv:?}: {rendered}");
        }
    }

    /// P6's other half — the whitelist is exactly help and version.
    #[test]
    fn the_scrub_whitelist_is_only_help_and_version() {
        let mut env = crate::test_env::guard();
        for name in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(name);
        }
        use clap::error::ErrorKind;
        for kind in [
            ErrorKind::DisplayHelp,
            ErrorKind::DisplayVersion,
            ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand,
        ] {
            assert!(clap_outcome_is_help_or_version(kind), "{kind:?}");
        }
        for kind in [
            ErrorKind::InvalidSubcommand,
            ErrorKind::TooManyValues,
            ErrorKind::UnknownArgument,
            ErrorKind::MissingRequiredArgument,
            ErrorKind::InvalidValue,
        ] {
            assert!(!clap_outcome_is_help_or_version(kind), "{kind:?}");
        }
    }

    /// The top-level help still lists `secret` with its one-line description.
    #[test]
    fn the_top_level_help_lists_the_secret_verb() {
        let mut env = crate::test_env::guard();
        for name in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(name);
        }
        let mut help = Vec::new();
        build_command(&Catalog::Ready(default_catalog()))
            .write_long_help(&mut help)
            .expect("help renders");
        let help = String::from_utf8(help).unwrap();
        assert!(
            help.contains("Manage agent-vm's own values in the host system keychain"),
            "{help}"
        );
    }
}
