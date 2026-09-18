//! agent-vm — sandboxed microVMs for AI coding agents on microsandbox.

mod cli;
mod clipboard;
mod config;
mod credential_injection;
mod credential_provider;
mod defaults;
mod doctor;
mod env_flag;
mod github_graphql;
mod host_paths;
mod image_api_version;
mod image_capabilities;
mod image_check;
mod intercept_hook;
mod layer;
mod mount;
mod msb_cmd;
mod msb_install;
mod msb_preflight;
mod msb_schema;
mod network;
mod pull;
mod pull_progress;
mod pulled_marker;
mod run;
mod secrets;
mod session;
mod setup;
#[cfg(test)]
mod test_env;
mod user;

use anyhow::{Context, Result};

use cli::{Cmd, Dispatch};

fn main() -> Result<()> {
    init_tracing();
    // Config is discovered and loaded *before* parsing, because the resolved
    // tool catalog determines which subcommands exist. The result is carried
    // as data, not `?`-propagated: a broken config must not break `doctor`
    // (the tool you use to diagnose it), nor `clipboard`/`_intercept-hook`
    // (which run *inside* the guest, where a project config is present). See
    // `cli::parse_from`.
    let config = config::ConfigPaths::discover().and_then(|paths| config::load(&paths));
    let dispatch = cli::parse_from(std::env::args_os(), config)?;

    // Locate and pin our patched msb binary via MSB_PATH so a user's
    // separate `~/.microsandbox/bin/msb` can't shadow ours. The hook
    // subcommand runs as a child of msb itself (the binary is
    // already resolved); the clipboard subcommand also runs in
    // contexts where the bundled msb may not be available
    // (e.g. inside the guest VM), so skip the check there too.
    //
    // CRITICAL: `point_at_msb()` / `configure_msb_home()` mutate the
    // process environment via `unsafe { std::env::set_var(...) }`.
    // setenv() is not thread-safe under POSIX. We MUST run them
    // before the tokio multi-thread runtime spawns workers (which
    // happens inside `Runtime::new()`). Hence the manual sync `fn
    // main` + manual runtime construction instead of `#[tokio::main]`.
    // `config::load` above reads files and env but spawns no threads, so it
    // is safe ahead of this block.
    let needs_msb_setup = !matches!(
        dispatch,
        Dispatch::Builtin(Cmd::InterceptHook(_) | Cmd::Clipboard(_))
    );
    if needs_msb_setup {
        msb_install::point_at_msb()?;
        // Select a rerouted msb state location off `~/.microsandbox/` and into
        // agent-vm's own state dir. msb still finds `libkrunfw.so.*`
        // via MSB_PATH → sibling `../lib/` (the bundle layout), so no
        // copy/sync into MSB_HOME is needed — only the writable state
        // (db, sandboxes, cache, tls/CA, logs) lives here.
        let msb_home = msb_install::configure_msb_home()?;
        // Launch defers state creation until `run::launch` has rejected an
        // invalid mount topology. Other commands do not have that boundary.
        if !matches!(dispatch, Dispatch::Launch { .. }) {
            msb_install::ensure_msb_home(&msb_home)?;
        }
    }
    // `msb_cmd::run` is fully synchronous (just spawns a child and waits);
    // dispatch it before paying for a tokio runtime we'd otherwise spin up
    // and immediately block on for a single `Command::status()` call.
    if let Dispatch::Builtin(Cmd::Msb(args)) = dispatch {
        return exit_with(msb_cmd::run(args)?);
    }
    // doctor is also pure sync fs work (no VM/network I/O); dispatch it
    // before the runtime for the same reason as Msb above.
    if let Dispatch::Builtin(Cmd::Doctor(args)) = dispatch {
        doctor::run(args)?;
        return Ok(());
    }
    let runtime = tokio::runtime::Runtime::new().context("starting tokio runtime")?;
    runtime.block_on(async move {
        match dispatch {
            Dispatch::Launch { entry, args } => exit_with(run::launch(&entry, *args).await?),
            Dispatch::Builtin(Cmd::Setup(args)) => setup::run(args).await,
            Dispatch::Builtin(Cmd::Pull(args)) => pull::run(args).await,
            Dispatch::Builtin(Cmd::Clipboard(args)) => clipboard::run(args),
            Dispatch::Builtin(Cmd::InterceptHook(args)) => intercept_hook::run(args).await,
            // Already dispatched and returned from, above, before the
            // runtime was built.
            Dispatch::Builtin(Cmd::Msb(_)) => {
                unreachable!("Cmd::Msb is dispatched pre-runtime, see above")
            }
            Dispatch::Builtin(Cmd::Doctor(_)) => {
                unreachable!("Cmd::Doctor is dispatched pre-runtime, see above")
            }
        }
    })
}

/// Wire `tracing` so `RUST_LOG=agent_vm=debug,microsandbox=info` works.
/// Default level is `warn` — keeps normal output clean, but anything from
/// the microsandbox stack surfaces when you ask for it.
fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(true)
        .compact()
        .init();
}

fn exit_with(code: i32) -> Result<()> {
    std::process::exit(code);
}
