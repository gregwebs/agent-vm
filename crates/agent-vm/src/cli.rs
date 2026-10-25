//! CLI construction and dispatch.
//!
//! Everything clap-shaped lives behind this module. The set of **launch
//! verbs** is a *runtime* fact — read from the resolved tool catalog — while
//! the fixed built-ins (`setup`, `secret`, `image`, `msb`, `clipboard`, `doctor`,
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
use crate::config::{Catalog, ConfigReport, ConfiguredImages, Tool};
use crate::launch_target::LaunchTarget;
use crate::run;
use crate::{clipboard, doctor, intercept_hook, msb_cmd, secret, setup};

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
  agent-vm run <program> [arguments...]
                       run a guest executable directly; its arguments are literal

Launch options go before the tool or the runner:
  agent-vm [launch options] <tool> [tool arguments...]
  agent-vm [launch options] run PROGRAM [ARG...]
  agent-vm [launch options] -- PROGRAM [ARG...]
Every argument after the tool or program is forwarded verbatim, including --help and --.
Built-in commands take their own options after the command and no launch options.
`agent-vm help <tool>` and `agent-vm help run` show examples; `agent-vm doctor` shows
which config files were found and what they resolved to.";

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
    /// Acquire and verify the boot image (run once first).
    Setup(setup::Args),

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

    /// Inspect the selected boot image, acquire it into the image cache,
    /// explicitly retain a default, or build/import a finished image.
    /// Only `show` is offline; only build/import may invoke Docker.
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
        /// consumed to build the catalog. Carried to `image refresh`/`setup`/`image show`
        /// so they can select the same image a launch would.
        images: ConfiguredImages,
    },
    // Large launch-side values are boxed to keep dispatch compact.
    Launch {
        target: LaunchTarget,
        /// The two tiers' `image` settings (see the `Builtin` arm).
        images: ConfiguredImages,
        /// Verified user authority captured before consuming the report, like images.
        user_network: Option<crate::user_network::UserNetwork>,
        /// Verified user `mounts`, captured the same way (ADR-0046). `None` when
        /// the file declared none, so a launch can tell "no declarations" from
        /// "an empty list" — but both select nothing.
        user_mounts: Option<crate::config_mounts::UserMounts>,
        /// The launch options.
        args: Box<run::Args>,
    },
}

impl Dispatch {
    /// Whether this dispatch executes a direct command (`run` / top-level `--`,
    /// issue #398). Main's exit-status policy is the only consumer: a returned
    /// failure on a direct route is 125, on every other route anyhow's 1.
    ///
    /// A closed (fully stated) match, so a new variant must say whether it is
    /// direct.
    pub(crate) fn is_direct_launch(&self) -> bool {
        match self {
            Self::Launch { target, .. } => target.is_direct(),
            Self::Builtin { .. } => false,
        }
    }
}

/// Every subcommand name `build_command` registers that is not a tool,
/// including clap's synthesized `help`. Used for the misspelling check below
/// and asserted against `config::RESERVED_TOOL_NAMES` by a test, so a future
/// built-in cannot silently shadow — or be shadowed by — a config tool.
pub(crate) const BUILTIN_SUBCOMMANDS: &[&str] = &[
    "setup",
    "msb",
    "clipboard",
    "doctor",
    "secret",
    "image",
    "_intercept-hook",
    // The direct runner (issue #398) is a fixed launch route, so it is a
    // built-in *name* even though its target is user-supplied argv.
    "run",
    "help",
];

/// The fixed replacement for any unparseable `agent-vm secret …` argv.
///
/// clap renders supplied values on some parse errors — `agent-vm secret set svc
/// --help=SECRET` produces `unexpected value 'SECRET' for '--help'` — and
/// `parse_from` hands those to `error.exit()`, where no downstream handler can
/// intervene. So the whole `secret` subtree gets a value-free error instead.
/// Help and version still render (see the kind whitelist in `parse_from`).
///
/// Only the administrative route uses this text. A **known-direct** route whose
/// argv merely contains the token `secret` answers with
/// [`run::DIRECT_SECRET_SCRUB_ERROR`]: also value-free, but with the direct usage
/// and without these `agent-vm secret …` forms, which cannot describe a guest
/// command vector (issue #398).
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
    let (catalog, images, user_network, user_mounts) = match config {
        // A dangling `tools` reference is *user* input, so it must degrade to
        // the deferred-error path (ADR-0015) rather than `?`-propagate and take
        // `doctor`/`--help`/`clipboard` down with it. The readable `image` is
        // captured first so a catalog error cannot erase it (§5.3).
        Ok(report) => {
            let images = report.images().clone();
            let user_network = report.user_network().cloned();
            let user_mounts = report.user_mounts().cloned();
            match report.into_launch_catalog() {
                Ok(catalog) => (Catalog::Ready(catalog), images, user_network, user_mounts),
                Err(error) => (Catalog::Broken(error), images, None, None),
            }
        }
        // The configured tiers are unknown, so the recovery builtins fall back
        // to `--image`/env or the default boot image (D7).
        Err(error) => (
            Catalog::Broken(error),
            ConfiguredImages::default(),
            None,
            None,
        ),
    };

    // Collected so the `secret` scrub below can look at the verb without
    // consuming the iterator twice; the bound is already `Into<OsString>`.
    let argv: Vec<OsString> = argv.into_iter().map(Into::into).collect();
    // The scrub predicates and the route hint read the **original** argv:
    // replacing `--` with `run` neither creates nor deletes a `secret` or
    // `image import` witness, and the hint is only error classification.
    let secret_route = is_secret_route(&argv);
    let import_route = is_image_import_route(&argv);
    let route_hint = launch_route_hint(&argv);
    let mut argv = argv;
    // A top-level `--` whose launch-option prefix does not parse is not
    // rewritten, so clap would answer with "unrecognized subcommand" for the
    // first payload word. Its prefix error is the useful diagnostic, and it is
    // returned below instead of that route noise.
    let refused_prefix = rewrite_direct_separator(&mut argv, route_hint);

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
                let direct_route = matches!(route_hint, LaunchRouteHint::Direct { .. });
                if secret_route && !clap_outcome_is_help_or_version(error.kind()) {
                    // Same fixed, value-free selection on both routes; only a
                    // known-direct route answers with clap's formatter and
                    // status 2 (issue #398), because a direct launch must never
                    // turn a usage error into an ordinary launcher failure. Its
                    // text is direct-specific: the administrative `agent-vm
                    // secret …` forms are not what a guest command vector
                    // containing the token `secret` could have meant.
                    let kind = error.kind();
                    let scrubbed = if direct_route {
                        anyhow::Error::new(direct_usage_error(kind, run::DIRECT_SECRET_SCRUB_ERROR))
                    } else {
                        anyhow!(SECRET_ARGV_ERROR)
                    };
                    return Err(scrubbed);
                }
                if import_route && !clap_outcome_is_help_or_version(error.kind()) {
                    let kind = error.kind();
                    let scrubbed = if direct_route {
                        anyhow::Error::new(direct_usage_error(kind, run::DIRECT_SCRUB_ERROR))
                    } else {
                        anyhow::Error::new(import_argv_error(&command, &error))
                    };
                    return Err(scrubbed);
                }
                // A known-direct route whose separator was refused already has
                // the real cause: its launch-option prefix. clap reported the
                // first payload word as an unknown subcommand instead, which
                // names neither the option nor its value.
                if direct_route
                    && error.kind() == clap::error::ErrorKind::InvalidSubcommand
                    && let Some(prefix_error) = refused_prefix
                {
                    return Err(anyhow::Error::new(prefix_error));
                }
                // Any other syntax error on a known-direct route: clap's own
                // usage error and status 2, returned rather than exiting so the
                // caller applies the same policy to every route.
                if direct_route {
                    return Err(anyhow::Error::new(error));
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
        // The direct runner is checked first: `run` is never a catalog entry, so
        // it must not take one (not even shell's fallback) and must not consult
        // the catalog for anything but its health.
        (Some((name, sub)), catalog) if name == crate::launch_target::DIRECT_RUN_VERB => {
            direct_dispatch(
                &argv,
                sub,
                catalog,
                &matches,
                images,
                user_network,
                user_mounts,
            )
        }
        // The catalog is authoritative (checked first) so a future built-in
        // added without updating `RESERVED_TOOL_NAMES` fails a test rather
        // than silently shadowing a user's tool.
        (Some((name, sub)), Catalog::Ready(mut catalog)) => {
            match catalog.take_entry(name) {
                Some(entry) => {
                    let mut args = run::Args::from_arg_matches(&matches)?;
                    args.image.reconcile(&matches);
                    Ok(Dispatch::Launch {
                        images,
                        user_network,
                        user_mounts,
                        args: Box::new(args),
                        target: LaunchTarget::Tool {
                            entry: Box::new(entry),
                            tool_args: tool_args(
                                &argv,
                                sub.get_many::<String>(TOOL_ARGS)
                                    .map(|values| values.cloned().collect())
                                    .unwrap_or_default(),
                            ),
                        },
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

/// The direct runner's dispatch (issue #398).
///
/// Validation order is fixed: the raw suffix is restored, the newtype rejects a
/// missing/empty/non-Unicode program as a usage error (2), and only then does a
/// broken catalog surface its own failure (125). A ready catalog is dropped
/// without taking an entry, so no tool command, argv transform, environment,
/// provisioning closure or declared request can be inherited.
fn direct_dispatch(
    argv: &[OsString],
    sub: &clap::ArgMatches,
    catalog: Catalog,
    matches: &clap::ArgMatches,
    images: ConfiguredImages,
    user_network: Option<crate::user_network::UserNetwork>,
    user_mounts: Option<crate::config_mounts::UserMounts>,
) -> Result<Dispatch> {
    let vector = after_raw_verb(
        argv,
        sub.get_many::<OsString>(DIRECT_PROGRAM)
            .map(|values| values.cloned().collect())
            .unwrap_or_default(),
        || OsString::from("--"),
    );
    let direct = crate::launch_target::DirectCommand::from_os_args(vector)
        .map_err(|error| anyhow::Error::new(direct_program_error(&error)))?;
    let mut args = run::Args::from_arg_matches(matches)?;
    args.image.reconcile(matches);
    match catalog {
        Catalog::Broken(config_error) => Err(anyhow::Error::new(
            crate::launch_target::DirectLaunchFailure(config_error),
        )),
        Catalog::Ready(_) => Ok(Dispatch::Launch {
            target: LaunchTarget::Direct(direct),
            images,
            user_network,
            user_mounts,
            args: Box::new(args),
        }),
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
        Cmd::Setup(args) => args.image.reconcile(sub),
        // Only `image refresh` carries a launch-image selection, and its flag
        // lives on the subcommand: reconciling against these group matches would
        // lose the value's origin and the empty-env rule (issue #189).
        Cmd::Image(args) => args.reconcile_image_args(sub),
        // `build`'s and `import`'s `--tag` is a result reference in msb's cache,
        // not a launch image selection, and `show` reads `AGENT_VM_IMAGE_TAG`
        // itself through `boot_image` (where empty-is-unset and non-Unicode
        // refusal live). None of them consumes a `--image` override.
        Cmd::Msb(_)
        | Cmd::Clipboard(_)
        | Cmd::Doctor(_)
        | Cmd::Secret(_)
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
    // Registered for every catalog state and before the catalog verbs: the
    // direct route must exist even when the config is broken (its own dispatch
    // reports the config failure as 125), and a tool can never share the name.
    let mut command = refresh_image_help(Cli::command()).subcommand(direct_run_subcommand());
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

/// The refresh subcommand's own `--image` help.
///
/// `image refresh` flattens the launch-image argument type so its precedence,
/// environment binding and empty-env rule stay shared with launch. That type's
/// help says it *boots* the image, which is exactly what refresh does not do. The
/// flag keeps its id, value source and reconciliation; only its rendered help
/// differs.
const REFRESH_IMAGE_HELP: &str = "OCI image to acquire instead of the configured selection";

const REFRESH_IMAGE_LONG_HELP: &str = "OCI image to acquire into the image cache instead of the configured selection.\n\nPrecedence: this flag (or `AGENT_VM_IMAGE_TAG`), then the user config `image`, then the project config `image`, then the default boot image. See USAGE.md → \"Selecting the boot image\".";

fn refresh_image_help(mut command: clap::Command) -> clap::Command {
    // Mutating the `image` subcommand in place, rather than through
    // `Command::mut_subcommand` on the top-level command: that API removes the
    // subcommand and pushes it back last, which would silently reorder the
    // user-facing `--help` verb list (a pinned contract). The nested mutation
    // is safe because it only reorders `image`'s own children.
    let Some(index) = command
        .get_subcommands()
        .position(|subcommand| subcommand.get_name() == "image")
    else {
        return command;
    };
    let image = std::mem::take(
        command
            .get_subcommands_mut()
            .nth(index)
            .expect("the image subcommand was just found"),
    );
    let image = image.mut_subcommand("refresh", |refresh| {
        refresh.mut_arg("image", |arg| {
            arg.help(REFRESH_IMAGE_HELP)
                .long_help(REFRESH_IMAGE_LONG_HELP)
                .help_heading("Image")
        })
    });
    *command
        .get_subcommands_mut()
        .nth(index)
        .expect("the image subcommand slot is stable") = image;
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
    after_raw_verb(argv, values, || "--".to_owned())
}

/// The one clap limitation shared by every raw verb: a `--` immediately after
/// the verb is consumed, so it is restored from the argv **token count** rather
/// than by inspecting values (which would make a literal payload `--`
/// indistinguishable from the consumed one). The verb cannot itself end in
/// `--`, so the token just before the suffix is the only candidate.
fn after_raw_verb<T>(argv: &[OsString], values: Vec<T>, escape: impl FnOnce() -> T) -> Vec<T> {
    let consumed_escape = argv
        .len()
        .checked_sub(values.len() + 1)
        .is_some_and(|index| argv[index] == *"--");
    if consumed_escape {
        std::iter::once(escape()).chain(values).collect()
    } else {
        values
    }
}

/// The id of the direct runner's single positional: the program and its args.
const DIRECT_PROGRAM: &str = "program";

/// The direct runner (`agent-vm [launch options] run PROGRAM [ARG...]`).
///
/// Help is disabled so `run --help` is the guest's argument, not ours; the
/// program is not `required` so an absent PROGRAM is our own newtype error with
/// the direct usage line rather than clap's rendering. `help run` still works:
/// clap synthesizes it for every subcommand.
fn direct_run_subcommand() -> clap::Command {
    clap::Command::new(crate::launch_target::DIRECT_RUN_VERB)
        .about("Run a guest executable directly; every argument after it is literal")
        .override_usage(run::DIRECT_USAGE)
        .disable_help_flag(true)
        .arg(
            clap::Arg::new(DIRECT_PROGRAM)
                .value_name("PROGRAM")
                .help("Guest executable and its arguments, verbatim; --help and -- belong to it")
                .num_args(0..)
                .action(clap::ArgAction::Append)
                .value_parser(clap::builder::OsStringValueParser::new())
                .trailing_var_arg(true)
                .allow_hyphen_values(true),
        )
        .after_help(run::DIRECT_AFTER_HELP)
}

/// One launch option's argv shape, derived from clap metadata so the route
/// walker below cannot drift from the real parser's own list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OptionShape {
    /// Never consumes a following token (`--root`).
    Flag,
    /// Consumes the next token unless the value is attached (`--memory 4`).
    RequiredValue,
    /// Takes a value only in the `--name=value` form (`require_equals`).
    EqualsOnlyValue,
}

struct LaunchOption {
    long: String,
    short: Option<char>,
    shape: OptionShape,
}

fn launch_option_table() -> Vec<LaunchOption> {
    launch_options()
        .iter()
        .map(|option| LaunchOption {
            long: option
                .get_long()
                .expect("every launch option has a long name")
                .to_owned(),
            short: option.get_short(),
            shape: match option.get_action() {
                clap::ArgAction::SetTrue | clap::ArgAction::SetFalse | clap::ArgAction::Count => {
                    OptionShape::Flag
                }
                _ if option.is_require_equals_set() => OptionShape::EqualsOnlyValue,
                _ => OptionShape::RequiredValue,
            },
        })
        .collect()
}

/// Which spelling of the direct route a token vector uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DirectSpelling {
    /// `agent-vm [launch options] run PROGRAM`
    Verb,
    /// `agent-vm [launch options] -- PROGRAM`
    Separator,
}

/// What the **original** argv says about the route.
///
/// Computed before the separator rewrite and used only to classify a clap error
/// (issue #398): a known-direct route answers a usage error with status 2 and
/// the direct usage line instead of a legacy value-free plain error with status
/// 1. It authorizes nothing — the real parse and the dispatch decide.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LaunchRouteHint {
    Direct {
        /// Index in argv of the route token itself.
        boundary: usize,
        spelling: DirectSpelling,
    },
    /// The first positional is a verb other than `run`, an option without a
    /// value, or no positional at all.
    Other,
    /// A token that is not valid UTF-8 where an option or verb would be.
    Unknown,
}

/// Walk launch options by **arity**, then stop at the first positional.
///
/// Only enough of clap's grammar to find the route: env, value validation,
/// repetition and conflicts are ignored, but option consumption is respected so
/// an option value is never mistaken for a verb or a separator. An unknown
/// hyphen option is traversed as a flag — the real parse still rejects it — and
/// its possible separate value is deliberately not guessed, so a later `run`
/// never relabels an unknown-verb route.
fn launch_route_hint(argv: &[OsString]) -> LaunchRouteHint {
    let options = launch_option_table();
    let mut index = 1;
    while index < argv.len() {
        let Some(token) = argv[index].to_str() else {
            return LaunchRouteHint::Unknown;
        };
        if token == "--" {
            return LaunchRouteHint::Direct {
                boundary: index,
                spelling: DirectSpelling::Separator,
            };
        }
        if let Some(body) = token.strip_prefix("--") {
            let (name, value_attached) = match body.split_once('=') {
                Some((name, _)) => (name, true),
                None => (body, false),
            };
            if matches!(name, "help" | "version") {
                return LaunchRouteHint::Other;
            }
            index += match options.iter().find(|option| option.long == name) {
                Some(option) => consumed(option.shape, value_attached),
                None => 1,
            };
            continue;
        }
        if token.len() > 1 && token.starts_with('-') {
            let mut characters = token.chars();
            characters.next();
            // The only short launch option takes a value, so a cluster cannot
            // hide a second one; the first character decides.
            let short = characters.next().unwrap_or('-');
            if matches!(short, 'h' | 'V') {
                return LaunchRouteHint::Other;
            }
            index += match options.iter().find(|option| option.short == Some(short)) {
                Some(option) => consumed(option.shape, characters.next().is_some()),
                None => 1,
            };
            continue;
        }
        return if token == crate::launch_target::DIRECT_RUN_VERB {
            LaunchRouteHint::Direct {
                boundary: index,
                spelling: DirectSpelling::Verb,
            }
        } else {
            LaunchRouteHint::Other
        };
    }
    LaunchRouteHint::Other
}

/// How many argv tokens one launch option consumes.
fn consumed(shape: OptionShape, value_attached: bool) -> usize {
    match (shape, value_attached) {
        (OptionShape::RequiredValue, false) => 2,
        _ => 1,
    }
}

/// Rewrite the top-level separator into the verb, so both spellings share one
/// parse and one dispatch. Only a separator that clap accepts as the end of an
/// options-only prefix is rewritten; `--mount --` (a value) and a prefix with
/// its own syntax error keep clap's own diagnostics.
///
/// A prefix that does not parse returns its own error instead of being dropped:
/// leaving the separator in place makes clap report the first **payload** word
/// as an unrecognized subcommand, which names neither the launcher option nor
/// the value that was actually wrong.
fn rewrite_direct_separator(argv: &mut [OsString], hint: LaunchRouteHint) -> Option<clap::Error> {
    let LaunchRouteHint::Direct {
        boundary,
        spelling: DirectSpelling::Separator,
    } = hint
    else {
        return None;
    };
    match launch_prefix_error(&argv[..boundary]) {
        None => {
            argv[boundary] = OsString::from(crate::launch_target::DIRECT_RUN_VERB);
            None
        }
        Some(error) if reportable_prefix_error(error.kind()) => Some(error),
        Some(_) => None,
    }
}

/// The launch-option prefix as clap itself reads it: `Err` is that prefix's own
/// parse error, already formatted with the direct usage line.
fn launch_prefix_error(prefix: &[OsString]) -> Option<clap::Error> {
    launch_prefix_command().try_get_matches_from(prefix).err()
}

/// The command a launch-option prefix is read with: the launch options alone,
/// no positional/subcommand grammar, no help/version flag, and the direct usage
/// line so a surfaced prefix error names the direct forms. Environment bindings
/// are removed so the check is about argv only; the full parse still validates
/// the environment.
fn launch_prefix_command() -> clap::Command {
    command_without_launch_env(
        &run::Args::augment_args(clap::Command::new("agent-vm"))
            .disable_help_flag(true)
            .disable_version_flag(true)
            .override_usage(run::DIRECT_USAGE),
    )
}

/// The prefix error kinds whose text names launcher options and the typed value
/// supplied to them, never a free-form token. Surfacing these cannot echo argv
/// that a scrubbed route withheld; a prefix that failed on any other shape keeps
/// clap's separator-form diagnostic instead.
fn reportable_prefix_error(kind: clap::error::ErrorKind) -> bool {
    use clap::error::ErrorKind;
    matches!(
        kind,
        ErrorKind::InvalidValue
            | ErrorKind::ValueValidation
            | ErrorKind::ArgumentConflict
            | ErrorKind::MissingRequiredArgument
            | ErrorKind::NoEquals
    )
}

/// A fixed-value direct usage error: the direct usage lines, never rendered
/// argv and never a value-bearing clap context.
fn direct_usage_error(kind: clap::error::ErrorKind, text: impl std::fmt::Display) -> clap::Error {
    clap::Command::new("agent-vm")
        .override_usage(run::DIRECT_USAGE)
        .error(kind, text)
}

/// The newtype's own validation as a usage error (status 2). The message names
/// the position of an invalid argument, never its bytes.
fn direct_program_error(error: &crate::launch_target::DirectCommandError) -> clap::Error {
    use crate::launch_target::DirectCommandError;
    let kind = match error {
        DirectCommandError::MissingProgram => clap::error::ErrorKind::MissingRequiredArgument,
        DirectCommandError::EmptyProgram | DirectCommandError::NonUnicode { .. } => {
            clap::error::ErrorKind::ValueValidation
        }
    };
    direct_usage_error(kind, error)
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
/// subcommands keep their own bindings (notably image refresh/setup's --image).
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
    // `run` launches even though it is a fixed subcommand name, so malformed
    // launch environment fails a ready direct launch instead of being retried
    // away. A broken catalog keeps the retry precedence and then reports the
    // actual config failure.
    let launches = matches!(catalog, Catalog::Ready(_))
        && (verb == crate::launch_target::DIRECT_RUN_VERB || !BUILTIN_SUBCOMMANDS.contains(&verb));
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
                args,
                target: LaunchTarget::Tool { tool_args, .. },
                ..
            } => (args, tool_args),
            _ => panic!("expected a tool launch"),
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
                (vec!["agent-vm", "-p", "1:2", "setup"], "--publish", "setup"),
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
            for verb in ["setup", "doctor"] {
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

            home: None,
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
            home: None,
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

            home: None,
        })
        .unwrap();
        let images = report.images().clone();
        let dispatch = parse_from(["agent-vm", "t"], Ok(report)).expect("t parses");
        match dispatch {
            Dispatch::Launch {
                target: LaunchTarget::Tool { entry, .. },
                images: carried,
                ..
            } => {
                assert_eq!(entry.tool().name(), "t");
                assert_eq!(carried, images);
            }
            _ => panic!("t is a tool launch verb"),
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
            let mut argv = vec!["agent-vm", "image", "refresh"];
            argv.extend_from_slice(case.argv);
            let dispatch = parse_from(argv, Ok(report_from("tools = []\n")))
                .unwrap_or_else(|error| panic!("case {case:?} must parse: {error}"));
            let requested = match dispatch {
                Dispatch::Builtin {
                    cmd:
                        Cmd::Image(crate::image_cmd::Args {
                            cmd: crate::image_cmd::ImageCmd::Refresh(args),
                        }),
                    ..
                } => args.image.requested().expect("a valid override or none"),
                _ => panic!("image refresh must dispatch as a built-in"),
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
    /// reconciliation. The launch arm, the ready-catalog built-in arm (`image refresh`,
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

        // The ready-catalog built-in arm, and the deferred-config-error arm:
        // `image refresh`'s flag lives on the refresh subcommand, so these also
        // prove the nested reconciliation runs.
        for argv in [
            vec!["agent-vm", "image", "refresh", "--image", "cli:1"],
            vec!["agent-vm", "setup", "--image", "cli:1"],
        ] {
            let verb = argv[1];
            for catalog in [
                Ok(report_from("tools = []\n")),
                Err(anyhow::anyhow!("broken")),
            ] {
                let dispatch = parse_from(argv.clone(), catalog)
                    .unwrap_or_else(|error| panic!("{verb} must parse: {error}"));
                let requested = match dispatch {
                    Dispatch::Builtin {
                        cmd:
                            Cmd::Image(crate::image_cmd::Args {
                                cmd: crate::image_cmd::ImageCmd::Refresh(args),
                            }),
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
                target: LaunchTarget::Tool { entry, tool_args },
                ..
            } => {
                assert_eq!(entry.tool().name(), "mytool");
                assert_eq!(entry.tool().command(), "my-agent");
                assert_eq!(tool_args, ["--resume"]);
            }
            _ => panic!("mytool should dispatch as a tool launch"),
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

                home: None,
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

                home: None,
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

    #[test]
    fn parse_from_carries_the_user_mounts_into_a_launch() {
        let _env = clear_launch_env();
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("user.toml");
        std::fs::write(&file, "mounts = [\"/ref:ro\", \"/srv/data:/data:rw\"]\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let load = || {
            crate::config::load(&crate::config::ConfigPaths {
                user: Some(file.clone()),
                project: dir.path().join("absent.toml"),
                home: None,
            })
        };
        // `UserMounts` compares by the facts a launch reads, not by value: it is
        // not `PartialEq` because no production caller compares two of them.
        let describe = |mounts: &Option<crate::config_mounts::UserMounts>| {
            mounts
                .as_ref()
                .map(|mounts| (mounts.file().to_path_buf(), mounts.len()))
        };
        let expected = load().unwrap().user_mounts().cloned();
        assert_eq!(describe(&expected), Some((file.clone(), 2)));
        // Tool and direct arms alike: config mounts are ambient, so they reach
        // every launch route, and `--mount` is not required.
        for tokens in [
            vec!["agent-vm", "shell"],
            vec!["agent-vm", "run", "probe"],
            vec!["agent-vm", "--", "probe"],
        ] {
            let Dispatch::Launch { user_mounts, .. } =
                parse_from(argv_of(&tokens), load()).unwrap()
            else {
                panic!("expected a launch: {tokens:?}")
            };
            assert_eq!(describe(&user_mounts), describe(&expected), "{tokens:?}");
        }

        // A file without `mounts` selects nothing: `None`, not an empty list.
        std::fs::write(&file, "image = \"localhost:1/only:latest\"\n").unwrap();
        let Dispatch::Launch { user_mounts, .. } =
            parse_from(["agent-vm", "shell"], load()).unwrap()
        else {
            panic!("launch")
        };
        assert!(user_mounts.is_none());

        // A `mounts` file whose catalog is broken never reaches a launch, so the
        // deferred-error path (not selection) is what a broken config reports.
        std::fs::write(
            &file,
            "mounts = [\"/ref:ro\"]\n[[tools]]\nname = \"t\"\ncommand = \"t\"\ntools = [\"nope\"]\n",
        )
        .unwrap();
        let error = parse_from(["agent-vm", "shell"], load())
            .err()
            .expect("a dangling tools reference still fails the launch")
            .to_string();
        assert!(
            error.contains("names no tool in the resolved catalog"),
            "{error}"
        );
    }

    /// A `mounts` value that fails its own checks is a *deferred* catalog error:
    /// every built-in still dispatches, help renders with the broken-config
    /// note, and a launch reports the mounts sentence rather than an
    /// unknown-subcommand failure.
    #[test]
    fn a_broken_mounts_config_is_a_deferred_catalog_error() {
        let _env = clear_launch_env();
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("user.toml");
        std::fs::write(&file, "mounts = [1]\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let load = || {
            crate::config::load(&crate::config::ConfigPaths {
                user: Some(file.clone()),
                project: dir.path().join("absent.toml"),
                home: None,
            })
        };
        for (tokens, check) in [
            (
                vec!["agent-vm", "doctor"],
                matches!(
                    parse_from(["agent-vm", "doctor"], load()).unwrap(),
                    Dispatch::Builtin {
                        cmd: Cmd::Doctor(_),
                        ..
                    }
                ),
            ),
            (
                vec!["agent-vm", "msb", "--version"],
                matches!(
                    parse_from(["agent-vm", "msb", "--version"], load()).unwrap(),
                    Dispatch::Builtin {
                        cmd: Cmd::Msb(_),
                        ..
                    }
                ),
            ),
        ] {
            assert!(check, "{tokens:?} must still dispatch");
        }
        let help = build_command(&Catalog::Broken(load().unwrap_err()))
            .try_get_matches_from(["agent-vm", "--help"])
            .unwrap_err();
        assert_eq!(help.kind(), clap::error::ErrorKind::DisplayHelp);
        assert!(help.to_string().contains(CONFIG_BROKEN_NOTE));
        for argv in [
            vec!["agent-vm", "shell"],
            vec!["agent-vm", "run", "true"],
            vec!["agent-vm", "--", "true"],
        ] {
            let error = parse_from(argv_of(&argv), load())
                .err()
                .unwrap_or_else(|| panic!("{argv:?} must report the config error"))
                .to_string();
            assert!(error.contains("mounts[0]: must be a string"), "{error}");
            assert!(!error.contains("unrecognized subcommand"), "{error}");
        }
    }

    #[test]
    fn no_config_mounts_is_a_launch_option_before_the_verb() {
        let _env = clear_launch_env();
        use crate::mount_selection::ConfigMountPolicy;
        for tokens in [
            vec!["agent-vm", "--no-config-mounts", "shell"],
            vec!["agent-vm", "--no-config-mounts", "run", "probe"],
            vec!["agent-vm", "--no-config-mounts", "--", "probe"],
        ] {
            let Dispatch::Launch { args, target, .. } =
                parse_from(argv_of(&tokens), Ok(report_from(MYTOOL))).unwrap()
            else {
                panic!("expected a launch: {tokens:?}")
            };
            assert_eq!(
                args.config_mount_policy(),
                ConfigMountPolicy::Suppress,
                "{tokens:?}"
            );
            // Launcher-side only: the guest program and its argv are untouched.
            if target.is_direct() {
                let (_, invocation) = target.into_parts();
                assert_eq!(invocation.program(), "probe", "{tokens:?}");
                assert!(invocation.argv().is_empty(), "{tokens:?}");
            }
        }

        // After the verb it belongs to the tool, which is why the opt-out is
        // documented as a launch option and never read from the forwarded list.
        let (args, tool_args) = launch_of(
            parse_from(
                ["agent-vm", "mytool", "--no-config-mounts"],
                Ok(report_from(MYTOOL)),
            )
            .unwrap(),
        );
        assert_eq!(args.config_mount_policy(), ConfigMountPolicy::Apply);
        assert_eq!(tool_args, ["--no-config-mounts"]);

        // Before a built-in it is a launch option used where built-ins take
        // none, so clap's existing rejection names it.
        let error = usage_error(parse_from(
            ["agent-vm", "--no-config-mounts", "doctor"],
            Ok(report_from(MYTOOL)),
        ));
        assert_eq!(error.exit_code(), 2);
        assert!(
            error
                .to_string()
                .contains("the launch option '--no-config-mounts' cannot be used with 'doctor'"),
            "{error}"
        );
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
                "msb",
                "clipboard",
                "doctor",
                "secret",
                "image",
                "_intercept-hook",
                "run",
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
        assert_help_fixture(
            "help-run-columns-100.txt",
            &render(&["agent-vm", "help", "run"]),
            include_str!("../tests/fixtures/help-run-columns-100.txt"),
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
            (
                "help run",
                include_str!("../tests/fixtures/help-run-columns-100.txt"),
            ),
            ("the runner footer", run::DIRECT_AFTER_HELP),
            ("the runner usage", run::DIRECT_USAGE),
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
        for builtin in ["setup", "msb", "clipboard", "doctor", "secret", "image"] {
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

            home: None,
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
    fn set_default_requires_typed_target_independent_of_config_and_environment() {
        let mut env = crate::test_env::guard();
        env.set_var("AGENT_VM_IMAGE_TAG", "ignored:ambient");
        for config in [
            Ok(report_from("image = \"project:tag\"\n")),
            Err(anyhow!("broken TOML")),
        ] {
            assert!(matches!(
                parse_from(
                    [
                        "agent-vm",
                        "image",
                        "set-default",
                        "--image",
                        "localhost:1234/a:tag"
                    ],
                    config
                )
                .unwrap(),
                Dispatch::Builtin {
                    cmd: Cmd::Image(crate::image_cmd::Args {
                        cmd: crate::image_cmd::ImageCmd::SetDefault(_),
                    }),
                    ..
                }
            ));
        }
        for args in [
            vec!["agent-vm", "image", "set-default"],
            vec!["agent-vm", "image", "set-default", "--image", "/path"],
            // Launch options precede the verb; `image` is not a tool verb.
            vec!["agent-vm", "--image", "a:tag", "image", "set-default"],
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
            ["agent-vm", "image", "set-default", "--help"],
            ["agent-vm", "help", "image", "set-default"],
        ] {
            let error = build_command(&Catalog::Broken(anyhow!("broken")))
                .try_get_matches_from(args)
                .unwrap_err();
            assert_eq!(error.exit_code(), 0);
            assert!(error.to_string().contains("--image <REF>"));
        }
        let error = build_command(&Catalog::Ready(default_catalog()))
            .try_get_matches_from(["agent-vm", "image", "set-default"])
            .unwrap_err();
        assert_eq!(error.exit_code(), 2);
    }

    #[test]
    fn removed_image_verbs_can_be_configured_tools_with_verbatim_arguments() {
        let mut env = crate::test_env::guard();
        for name in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(name);
        }
        for name in ["pull", "upgrade"] {
            let config = format!("[[tools]]\nname = {name:?}\ncommand = \"probe\"\n");
            let (_, forwarded) = launch_of(
                parse_from(
                    ["agent-vm", name, "--image", "tool-value", "--help", "--"],
                    Ok(report_from(&config)),
                )
                .unwrap(),
            );
            assert_eq!(forwarded, ["--image", "tool-value", "--help", "--"]);
            let error = parse_from(["agent-vm", name], Err(anyhow!("deferred config sentinel")))
                .err()
                .expect("broken catalog must not launch a tool");
            assert!(format!("{error:#}").contains("deferred config sentinel"));
        }
    }

    #[test]
    fn image_refresh_takes_its_own_flag_and_removed_verbs_are_not_aliases() {
        let mut env = crate::test_env::guard();
        env.remove_var("AGENT_VM_IMAGE_TAG");
        for args in [
            vec![
                "agent-vm",
                "image",
                "refresh",
                "--image",
                "localhost:1/a:tag",
            ],
            vec!["agent-vm", "image", "refresh"],
            vec!["agent-vm", "image", "refresh", "--yes"],
            vec!["agent-vm", "image", "refresh", "--help"],
            vec!["agent-vm", "help", "image", "refresh"],
        ] {
            // Help short-circuits as a zero-exit `Err`, so only a non-zero exit
            // is a parse failure here.
            if let Err(error) =
                build_command(&Catalog::Ready(default_catalog())).try_get_matches_from(args.clone())
            {
                assert_eq!(error.exit_code(), 0, "{args:?} must parse: {error}");
            }
        }
        for args in [
            // The launch option must not be accepted on the group.
            vec![
                "agent-vm",
                "image",
                "--image",
                "localhost:1/a:tag",
                "refresh",
            ],
            vec!["agent-vm", "image", "refresh", "--dockerfile", "x"],
        ] {
            let error = build_command(&Catalog::Ready(default_catalog()))
                .try_get_matches_from(args.clone())
                .unwrap_err();
            assert_eq!(error.exit_code(), 2, "{args:?}");
        }
        // Removed built-ins leave no alias and no hidden route.
        for args in [
            vec!["agent-vm", "pull"],
            vec!["agent-vm", "upgrade"],
            vec!["agent-vm", "help", "pull"],
            vec!["agent-vm", "help", "upgrade"],
        ] {
            let error = build_command(&Catalog::Ready(default_catalog()))
                .try_get_matches_from(args.clone())
                .unwrap_err();
            assert_eq!(error.exit_code(), 2, "{args:?}");
        }
    }

    /// The removed launch-time advisory leaves no alias, no deprecation hint and
    /// no environment authority. The routing rule itself is unchanged: an
    /// unknown launch option *before* the tool verb is a usage error, and every
    /// token *after* the verb is forwarded to the tool verbatim.
    #[test]
    fn removed_update_check_leaves_no_alias_and_forwards_after_the_verb() {
        let mut env = crate::test_env::guard();
        for name in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(name);
        }
        for argv in [
            vec!["agent-vm", "--update-check", "shell"],
            vec!["agent-vm", "--update-check", "pi", "--flag"],
            // No no-op alias and no hint spelling either.
            vec!["agent-vm", "--no-update-check", "shell"],
            vec!["agent-vm", "--update-checks", "shell"],
        ] {
            let error = build_command(&Catalog::Ready(default_catalog()))
                .try_get_matches_from(argv.clone())
                .unwrap_err();
            assert_eq!(error.exit_code(), 2, "{argv:?}");
            let text = error.to_string();
            assert!(!text.contains("deprecat"), "{argv:?}: {text}");
            assert!(!text.contains("UpdateCheck"), "{argv:?}: {text}");
        }
        // After the verb it is the tool's argument, deliberately unremarked.
        let (_, forwarded) = launch_of(
            parse_from(
                ["agent-vm", "shell", "--update-check", "--"],
                Ok(report_from(
                    "[[tools]]\nname = \"probe\"\ncommand = \"probe\"\n",
                )),
            )
            .unwrap(),
        );
        assert_eq!(forwarded, ["--update-check", "--"]);
        // `--yes` is nested only: the launch and `setup` refuse it, the two
        // explicit update verbs accept it.
        let error = build_command(&Catalog::Ready(default_catalog()))
            .try_get_matches_from(["agent-vm", "--yes", "shell"])
            .unwrap_err();
        assert_eq!(error.exit_code(), 2);
        for argv in [
            vec!["agent-vm", "setup", "--yes"],
            vec!["agent-vm", "image", "import", "--yes"],
            vec!["agent-vm", "image", "build", "--yes"],
        ] {
            let error = build_command(&Catalog::Ready(default_catalog()))
                .try_get_matches_from(argv.clone())
                .unwrap_err();
            assert_eq!(error.exit_code(), 2, "{argv:?}");
        }
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

    // -- #398: the direct runner (`run` / top-level `--`) -------------------

    fn clear_launch_env() -> crate::test_env::EnvGuard {
        let mut env = crate::test_env::guard();
        for name in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(name);
        }
        env
    }

    /// The lowered invocation of a direct launch: program, literal argv and the
    /// guard the shared pipeline will render.
    fn direct_of(dispatch: Dispatch) -> (crate::launch_target::GuestInvocation, Vec<String>) {
        let Dispatch::Launch { target, .. } = dispatch else {
            panic!("expected a launch");
        };
        assert!(target.is_direct(), "expected a direct launch");
        let (_, invocation) = target.into_parts();
        let argv = invocation.argv().to_vec();
        (invocation, argv)
    }

    fn argv_of(tokens: &[&str]) -> Vec<OsString> {
        tokens.iter().map(OsString::from).collect()
    }

    /// The usage error a direct route returns, with its status.
    fn usage_error(dispatch: Result<Dispatch>) -> clap::Error {
        let error = dispatch.err().expect("a usage error");
        error
            .downcast::<clap::Error>()
            .expect("a clap usage error, not a plain launcher error")
    }

    #[test]
    fn both_direct_forms_agree_on_the_program_and_its_literal_argv() {
        let _env = clear_launch_env();
        let config = || Ok(report_from(MYTOOL));
        for (program, rest) in [
            ("p", vec!["--help"]),
            ("p", vec!["-h"]),
            ("p", vec!["help"]),
            ("p", vec!["-V"]),
            ("p", vec!["--"]),
            ("p", vec!["--", "x"]),
            ("p", vec![]),
            (
                "p",
                vec![
                    "",
                    "x",
                    "x",
                    "  spaced  ",
                    "日本語",
                    "$HOME",
                    "*",
                    ";",
                    "|",
                    "a\nb",
                    "trail\n\n",
                ],
            ),
            ("--", vec![]),
            ("--", vec!["x"]),
            ("--", vec!["--", "x"]),
        ] {
            let mut by_verb = argv_of(&["agent-vm", "run", program]);
            by_verb.extend(rest.iter().map(OsString::from));
            let mut by_separator = argv_of(&["agent-vm", "--", program]);
            by_separator.extend(rest.iter().map(OsString::from));
            let (verb, verb_args) = direct_of(parse_from(by_verb, config()).unwrap());
            let (separator, separator_args) =
                direct_of(parse_from(by_separator, config()).unwrap());
            assert_eq!(
                (verb.program(), verb.argv(), verb.guard()),
                (separator.program(), separator.argv(), separator.guard()),
                "program {program:?} args {rest:?}"
            );
            assert_eq!(verb.program(), program);
            assert_eq!(verb_args, rest, "program {program:?}");
            assert_eq!(separator_args, rest);
        }
    }

    #[test]
    fn launch_options_precede_either_direct_spelling_and_stay_launcher_side() {
        let _env = clear_launch_env();
        for route in [
            vec!["run", "p", "--memory", "9"],
            vec!["--", "p", "--memory", "9"],
        ] {
            let argv: Vec<OsString> = argv_of(&["agent-vm"])
                .into_iter()
                .chain(argv_of(&[
                    "--mount",
                    "/x",
                    "--memory",
                    "4",
                    "-p",
                    "8080:3000",
                ]))
                .chain(argv_of(&["--root"]))
                .chain(route.iter().map(OsString::from))
                .collect();
            match parse_from(argv, Ok(report_from(MYTOOL))).unwrap() {
                Dispatch::Launch { target, args, .. } => {
                    assert!(target.is_direct());
                    let (_, invocation) = target.into_parts();
                    // Only the launch side sees the option; the guest argv keeps
                    // its own identically named token.
                    assert_eq!(args.mount, ["/x"]);
                    assert_eq!(args.memory, 4);
                    assert!(args.root);
                    assert_eq!(invocation.program(), "p");
                    assert_eq!(invocation.argv(), ["--memory", "9"]);
                }
                _ => panic!("expected a launch"),
            }
        }
    }

    #[test]
    fn an_absent_or_empty_program_is_a_direct_usage_error_in_both_forms() {
        let _env = clear_launch_env();
        for (tokens, expected) in [
            (vec!["agent-vm", "run"], "a program is required"),
            (vec!["agent-vm", "--"], "a program is required"),
            (vec!["agent-vm", "run", ""], "must not be empty"),
            (vec!["agent-vm", "--", ""], "must not be empty"),
        ] {
            let error = usage_error(parse_from(argv_of(&tokens), Ok(report_from(MYTOOL))));
            assert_eq!(error.exit_code(), 2, "{tokens:?}");
            let text = error.to_string();
            assert!(text.contains(expected), "{tokens:?}: {text}");
            assert!(
                text.contains("agent-vm [launch options] run PROGRAM [ARG]...")
                    && text.contains("agent-vm [launch options] -- PROGRAM [ARG]..."),
                "{tokens:?}: {text}"
            );
        }
    }

    #[test]
    fn non_unicode_direct_argv_is_rejected_by_position_without_replacement() {
        use std::os::unix::ffi::OsStringExt as _;
        let _env = clear_launch_env();
        let invalid = || OsString::from_vec(vec![0xff, 0xfe]);
        for (tokens, expected) in [
            (
                vec!["agent-vm", "run"],
                "the program name is not valid UTF-8",
            ),
            (
                vec!["agent-vm", "--"],
                "the program name is not valid UTF-8",
            ),
            (
                vec!["agent-vm", "run", "--"],
                "argument 1 is not valid UTF-8",
            ),
            (
                vec!["agent-vm", "--", "--"],
                "argument 1 is not valid UTF-8",
            ),
            (
                vec!["agent-vm", "run", "p", "--"],
                "argument 2 is not valid UTF-8",
            ),
            (
                vec!["agent-vm", "--", "p", "--"],
                "argument 2 is not valid UTF-8",
            ),
        ] {
            let mut argv = argv_of(&tokens);
            argv.push(invalid());
            let error = usage_error(parse_from(argv, Ok(report_from(MYTOOL))));
            assert_eq!(error.exit_code(), 2, "{tokens:?}");
            let text = error.to_string();
            assert!(text.contains(expected), "{tokens:?}: {text}");
            // No rejected bytes and no lossy replacement.
            assert!(!text.contains('\u{fffd}'), "{tokens:?}: {text}");
            assert!(!text.contains("255"), "{tokens:?}: {text}");
        }
        // An empty program wins over an invalid later argument.
        let mut argv = argv_of(&["agent-vm", "run", ""]);
        argv.push(invalid());
        let error = usage_error(parse_from(argv, Ok(report_from(MYTOOL))));
        assert!(error.to_string().contains("must not be empty"));
        // Non-Unicode *before* the route is never guessed as a direct verb: the
        // separator rewrite leaves argv alone, and clap keeps its own verb
        // error (which `parse_from` passes to `error.exit()`, so it is pinned
        // here rather than through an exit inside the test process).
        let mut argv = argv_of(&["agent-vm"]);
        argv.push(invalid());
        argv.push(OsString::from("run"));
        assert_eq!(launch_route_hint(&argv), LaunchRouteHint::Unknown);
        let mut rewritten = argv.clone();
        rewrite_direct_separator(&mut rewritten, launch_route_hint(&argv));
        assert_eq!(rewritten, argv);
        assert_eq!(
            build_command(&Catalog::Ready(default_catalog()))
                .try_get_matches_from(&argv)
                .expect_err("clap's own verb error")
                .kind(),
            clap::error::ErrorKind::InvalidSubcommand
        );
    }

    #[test]
    fn run_of_a_catalog_tool_name_is_direct_and_takes_no_entry() {
        let _env = clear_launch_env();
        let argv = argv_of(&["agent-vm", "run", "claude", "--x", "x", "", "x"]);
        let (command, args) = direct_of(parse_from(argv, Ok(report_from(MYTOOL))).unwrap());
        assert_eq!(command.program(), "claude");
        assert_eq!(args, ["--x", "x", "", "x"]);
        // Launch options before the runner are not administrative misuse.
        let argv = argv_of(&["agent-vm", "--mount", "/x", "run", "p"]);
        assert!(matches!(
            parse_from(argv, Ok(report_from(MYTOOL))).unwrap(),
            Dispatch::Launch {
                target: LaunchTarget::Direct(_),
                ..
            }
        ));
    }

    #[test]
    fn a_broken_catalog_fails_a_direct_launch_without_clap_noise() {
        let _env = clear_launch_env();
        for tokens in [vec!["agent-vm", "run", "p"], vec!["agent-vm", "--", "p"]] {
            let error = parse_from(argv_of(&tokens), Err(anyhow!("broken catalog")))
                .err()
                .expect("a direct launch failure");
            // Not clap's "unrecognized subcommand" and no did-you-mean tip.
            assert!(error.downcast_ref::<clap::Error>().is_none(), "{tokens:?}");
            assert!(
                error.to_string().contains("broken catalog"),
                "{tokens:?}: {error}"
            );
            let failure = error
                .downcast::<crate::launch_target::DirectLaunchFailure>()
                .expect("the deferred direct failure marker");
            assert!(failure.to_string().contains("broken catalog"));
            // The program is still validated first.
            let error = usage_error(parse_from(
                argv_of(&["agent-vm", "run"]),
                Err(anyhow!("broken catalog")),
            ));
            assert_eq!(error.exit_code(), 2);
        }
    }

    #[test]
    fn an_invalid_unused_tool_still_blocks_a_direct_launch() {
        let _env = clear_launch_env();
        // `run` is reserved, and so is any invalid declaration: a direct launch
        // must not proceed with an unreadable catalog.
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("config.toml");
        std::fs::write(&project, "[[tools]]\nname = \"run\"\ncommand = \"x\"\n").unwrap();
        let load = || {
            crate::config::load(&crate::config::ConfigPaths {
                user: Some(dir.path().join("no-user.toml")),
                project: dir.path().join("config.toml"),

                home: None,
            })
        };
        let error = parse_from(argv_of(&["agent-vm", "run", "p"]), load())
            .err()
            .expect("the reserved name breaks the catalog");
        assert!(
            error
                .downcast_ref::<crate::launch_target::DirectLaunchFailure>()
                .is_some()
        );
        // Built-ins keep working with that broken catalog.
        assert!(matches!(
            parse_from(argv_of(&["agent-vm", "doctor"]), load()).unwrap(),
            Dispatch::Builtin {
                cmd: Cmd::Doctor(_),
                ..
            }
        ));
    }

    #[test]
    fn the_route_hint_never_turns_a_value_or_a_later_token_into_a_direct_route() {
        let run_hint = |tokens: &[&str]| launch_route_hint(&argv_of(tokens));
        assert_eq!(
            run_hint(&["agent-vm", "--mount", "run", "secret"]),
            LaunchRouteHint::Other
        );
        assert_eq!(
            run_hint(&["agent-vm", "--mount", "--"]),
            LaunchRouteHint::Other
        );
        assert_eq!(
            run_hint(&["agent-vm", "--unknown", "x", "run", "secret"]),
            LaunchRouteHint::Other
        );
        assert_eq!(
            run_hint(&["agent-vm", "shell", "run", "secret"]),
            LaunchRouteHint::Other
        );
        assert_eq!(run_hint(&["agent-vm"]), LaunchRouteHint::Other);
        assert_eq!(run_hint(&["agent-vm", "--help"]), LaunchRouteHint::Other);
        assert_eq!(run_hint(&["agent-vm", "-V"]), LaunchRouteHint::Other);
        assert_eq!(
            run_hint(&["agent-vm", "--unknown", "run", "secret"]),
            LaunchRouteHint::Direct {
                boundary: 2,
                spelling: DirectSpelling::Verb
            }
        );
        for tokens in [
            vec!["agent-vm", "--"],
            vec!["agent-vm", "--memory", "4", "--"],
            vec!["agent-vm", "-p", "1:2", "--root", "--"],
        ] {
            assert_eq!(
                run_hint(&tokens),
                LaunchRouteHint::Direct {
                    boundary: tokens.len() - 1,
                    spelling: DirectSpelling::Separator
                },
                "{tokens:?}"
            );
        }
        for tokens in [
            vec!["agent-vm", "--memory", "4", "run", "p"],
            vec!["agent-vm", "--allow-internet-egress=true", "run", "p"],
            vec!["agent-vm", "-p1:2", "run", "p"],
        ] {
            let boundary = tokens.iter().position(|token| *token == "run").unwrap();
            assert_eq!(
                run_hint(&tokens),
                LaunchRouteHint::Direct {
                    boundary,
                    spelling: DirectSpelling::Verb
                },
                "{tokens:?}"
            );
        }
        // A single token that is not UTF-8 where an option or verb would be.
        use std::os::unix::ffi::OsStringExt as _;
        assert_eq!(
            launch_route_hint(&[OsString::from("agent-vm"), OsString::from_vec(vec![0xff])]),
            LaunchRouteHint::Unknown
        );
        // Invalid bytes *after* a recognized boundary stay direct argv.
        assert_eq!(
            launch_route_hint(&[
                OsString::from("agent-vm"),
                OsString::from("run"),
                OsString::from_vec(vec![0xff])
            ]),
            LaunchRouteHint::Direct {
                boundary: 1,
                spelling: DirectSpelling::Verb
            }
        );
    }

    #[test]
    fn launch_option_metadata_shapes_are_pinned_for_the_route_walker() {
        let _env = clear_launch_env();
        let table: Vec<(String, Option<char>, OptionShape)> = launch_option_table()
            .into_iter()
            .map(|option| (option.long, option.short, option.shape))
            .collect();
        assert_eq!(
            table,
            [
                ("memory".to_string(), None, OptionShape::RequiredValue),
                ("cpus".to_string(), None, OptionShape::RequiredValue),
                ("no-git".to_string(), None, OptionShape::Flag),
                ("repo".to_string(), None, OptionShape::RequiredValue),
                (
                    "allow-missing-credentials".to_string(),
                    None,
                    OptionShape::Flag
                ),
                ("mount".to_string(), None, OptionShape::RequiredValue),
                ("no-config-mounts".to_string(), None, OptionShape::Flag),
                ("publish".to_string(), Some('p'), OptionShape::RequiredValue),
                ("auto-publish".to_string(), None, OptionShape::Flag),
                ("allow-egress".to_string(), None, OptionShape::RequiredValue),
                (
                    "allow-internet-egress".to_string(),
                    None,
                    OptionShape::EqualsOnlyValue
                ),
                ("allow-lan".to_string(), None, OptionShape::EqualsOnlyValue),
                ("allow-host".to_string(), None, OptionShape::EqualsOnlyValue),
                ("image".to_string(), None, OptionShape::RequiredValue),
                ("root".to_string(), None, OptionShape::Flag),
            ]
        );
    }

    #[test]
    fn the_route_hint_agrees_with_clap_on_every_accepted_prefix() {
        let _env = clear_launch_env();
        // A prefix clap accepts as options-only must be classified Other (no
        // route yet) and must be rewritable-safe: only a separator after it is
        // ever replaced.
        for tokens in [
            vec!["agent-vm"],
            vec!["agent-vm", "--memory", "4"],
            vec!["agent-vm", "--root", "--no-git"],
            vec!["agent-vm", "-p", "1:2"],
            vec!["agent-vm", "--allow-lan", "--allow-host=true"],
            vec!["agent-vm", "--image", "x", "--recipe-dir", "y"],
        ] {
            let accepted = launch_prefix_error(&argv_of(&tokens)).is_none();
            if tokens.contains(&"--recipe-dir") {
                assert!(!accepted, "{tokens:?} is not a launch option");
                continue;
            }
            assert!(accepted, "{tokens:?} should be an accepted prefix");
            assert_eq!(launch_route_hint(&argv_of(&tokens)), LaunchRouteHint::Other);
        }
        // A `--` consumed as an option value is not a separator, and the prefix
        // before the *first* `--` is not options-only either way.
        assert_eq!(
            launch_route_hint(&argv_of(&["agent-vm", "--mount", "--", "run", "p"])),
            LaunchRouteHint::Direct {
                boundary: 3,
                spelling: DirectSpelling::Verb
            }
        );
        assert!(launch_prefix_error(&argv_of(&["agent-vm", "--mount"])).is_some());
    }

    #[test]
    fn direct_routes_classify_b5_scrub_and_syntax_errors_as_usage() {
        let mut env = clear_launch_env();
        // 1. A malformed launch environment reaches no launch on a ready catalog.
        env.set_var("AGENT_VM_MEMORY_GIB", "abc");
        for tokens in [
            vec!["agent-vm", "run", "secret"],
            vec!["agent-vm", "--", "secret"],
            vec!["agent-vm", "run", "image", "import"],
            vec!["agent-vm", "--", "image", "import"],
        ] {
            let error = usage_error(parse_from(argv_of(&tokens), Ok(report_from(MYTOOL))));
            assert_eq!(error.exit_code(), 2, "{tokens:?}");
            let text = error.to_string();
            assert!(!text.contains("abc"), "{tokens:?}: {text}");
            assert!(
                text.contains("agent-vm [launch options] run PROGRAM [ARG]..."),
                "{tokens:?}: {text}"
            );
        }
        env.remove_var("AGENT_VM_MEMORY_GIB");
        // 2. An invalid typed value, an unknown option and a repeated conflict
        //    are all usage errors on both spellings.
        for tokens in [
            vec!["agent-vm", "--memory", "abc", "run", "p"],
            vec!["agent-vm", "--memory", "abc", "--", "p"],
            vec!["agent-vm", "--unknown=CANARY", "run", "p"],
            vec!["agent-vm", "--memory", "4", "--memory", "8", "run", "p"],
        ] {
            let error = usage_error(parse_from(argv_of(&tokens), Ok(report_from(MYTOOL))));
            assert_eq!(error.exit_code(), 2, "{tokens:?}");
            let text = error.to_string();
            assert!(!text.contains("CANARY"), "{tokens:?}: {text}");
            // The separator spelling reports the invalid launch option, not the
            // first payload word as an unknown subcommand (#398 review SP4).
            if tokens.contains(&"--memory") && tokens.contains(&"abc") {
                assert!(
                    text.contains("invalid value 'abc' for '--memory"),
                    "{tokens:?}: {text}"
                );
                assert!(
                    !text.contains("unrecognized subcommand"),
                    "{tokens:?}: {text}"
                );
            }
        }
        // 2b. A known-direct route whose argv contains the token `secret` gets
        //     direct-specific, value-free text: the administrative
        //     `agent-vm secret …` forms are not what a guest command vector
        //     could have meant (#398 review SP4).
        for tokens in [
            vec!["agent-vm", "--memory", "abc", "run", "secret"],
            vec!["agent-vm", "--memory", "abc", "--", "secret"],
        ] {
            let error = usage_error(parse_from(argv_of(&tokens), Ok(report_from(MYTOOL))));
            assert_eq!(error.exit_code(), 2, "{tokens:?}");
            let text = error.to_string();
            for administrative in ["agent-vm secret set", "agent-vm secret ls", "secret rm"] {
                assert!(!text.contains(administrative), "{tokens:?}: {text}");
            }
            assert!(
                text.contains("agent-vm [launch options] run PROGRAM [ARG]..."),
                "{tokens:?}: {text}"
            );
        }
        // 3. A genuine `secret` or `image import` route keeps its legacy status.
        for tokens in [
            vec!["agent-vm", "secret", "set", "svc", "--help=CANARY"],
            vec!["agent-vm", "image", "import"],
        ] {
            let error = parse_from(argv_of(&tokens), Ok(report_from(MYTOOL)))
                .err()
                .expect("a scrubbed route error");
            let is_clap = error.downcast_ref::<clap::Error>().is_some();
            // A genuine `secret` route keeps its legacy plain-anyhow scrub
            // (status 1); the administrative import route keeps clap's text.
            assert_eq!(is_clap, !tokens.contains(&"secret"), "{tokens:?}");
            assert!(!error.to_string().contains("CANARY"), "{tokens:?}: {error}");
        }
    }

    #[test]
    fn a_direct_payload_named_run_secret_or_import_is_never_diverted() {
        let _env = clear_launch_env();
        for (tokens, program) in [
            (vec!["agent-vm", "run", "secret", "p"], "secret"),
            (vec!["agent-vm", "run", "image", "import"], "image"),
            (vec!["agent-vm", "--", "secret"], "secret"),
            (vec!["agent-vm", "run", "--"], "--"),
        ] {
            match parse_from(argv_of(&tokens), Ok(report_from(MYTOOL))).unwrap() {
                Dispatch::Launch {
                    target: LaunchTarget::Direct(command),
                    ..
                } => assert_eq!(command.program(), program, "{tokens:?}"),
                _ => panic!("{tokens:?} should be a direct launch"),
            }
        }
    }

    #[test]
    fn every_command_builds_without_clap_conflicts_on_either_catalog_path() {
        let _env = clear_launch_env();
        build_command(&Catalog::Ready(default_catalog())).debug_assert();
        build_command(&Catalog::Broken(anyhow!("broken"))).debug_assert();
        // A configured `run` is rejected by the catalog, so it can never become
        // a second `run` subcommand: the command stays a valid clap tree.
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("config.toml");
        std::fs::write(&project, "[[tools]]\nname = \"run\"\ncommand = \"x\"\n").unwrap();
        let config = crate::config::load(&crate::config::ConfigPaths {
            user: Some(dir.path().join("no-user.toml")),
            project,

            home: None,
        });
        let catalog = match config {
            Ok(report) => match report.into_launch_catalog() {
                Ok(catalog) => Catalog::Ready(catalog),
                Err(error) => Catalog::Broken(error),
            },
            Err(error) => Catalog::Broken(error),
        };
        assert!(matches!(catalog, Catalog::Broken(_)));
        build_command(&catalog).debug_assert();
        assert_eq!(
            subcommand_names(&build_command(&catalog))
                .iter()
                .filter(|name| *name == "run")
                .count(),
            1
        );
    }

    #[test]
    fn run_is_reserved_in_every_config_tier_with_a_rename_diagnostic() {
        let _env = clear_launch_env();
        let body = "[[tools]]\nname = \"run\"\ncommand = \"x\"\n";
        let dir = tempfile::tempdir().unwrap();
        let user_config = dir.path().join("user.toml");
        std::fs::write(&user_config, body).unwrap();
        let user = crate::config::load(&ConfigPaths {
            user: Some(user_config),
            project: dir.path().join("no-project.toml"),

            home: None,
        })
        .unwrap_err()
        .to_string();
        let project_config = dir.path().join("project.toml");
        std::fs::write(&project_config, body).unwrap();
        let project = crate::config::load(&ConfigPaths {
            user: Some(dir.path().join("no-user.toml")),
            project: project_config,

            home: None,
        })
        .unwrap_err()
        .to_string();
        for rendered in [user, project] {
            assert!(rendered.contains("name `run` is reserved"), "{rendered}");
            assert!(rendered.contains("run-tool"), "{rendered}");
        }
        assert_eq!(nearest_builtin("rnu"), Some("run"));
    }
}
