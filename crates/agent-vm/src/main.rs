//! agent-vm — sandboxed microVMs for AI coding agents on microsandbox.

mod boot_image;
mod cli;
mod clipboard;
mod config;
mod config_authority;
mod credential_env;
mod credential_injection;
mod credential_provider;
mod credential_resolver;
mod credential_yaml;
mod debug_config;
mod defaults;
mod dns_name;
mod doctor;
mod egress_grammar;
mod egress_hostname;
mod egress_policy;
mod embedded_runtime;
mod env_flag;
mod github_graphql;
mod guest_home;
mod guest_paths;
mod host_paths;
mod image_acquire;
mod image_build;
mod image_capabilities;
mod image_cmd;
mod image_contract;
mod image_import;
mod image_log_guard;
mod image_miss;
mod image_pin;
mod image_publish;
mod intercept_hook;
mod launch_target;
mod mount;
mod msb_cmd;
mod msb_install;
mod msb_preflight;
mod msb_schema;
mod network;
mod network_requests;
mod pi_credential_inspection;
mod protected_config_dir;
mod protected_host_files;
mod pull;
mod pull_progress;
mod run;
mod secret;
mod secret_store;
mod secrets;
mod session;
mod setup;
#[cfg(test)]
mod test_env;
#[cfg(test)]
mod test_fixtures;
mod user;
mod user_network;

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
    let dispatch = match cli::parse_from(std::env::args_os(), config) {
        Ok(dispatch) => dispatch,
        // Parse failures already know their status: clap's own formatter and
        // status for a usage error, and 125 for a deferred direct configuration
        // failure (#398).
        Err(error) => return Err(report_dispatch_failure(error, false)),
    };

    // The status policy of everything below depends on the route, recorded
    // while it is still observable on the dispatch itself.
    let direct = dispatch.is_direct_launch();
    run_dispatch(dispatch).map_err(|error| report_dispatch_failure(error, direct))
}

/// Report a dispatch failure with its status, ending the process here when the
/// status is not anyhow's ordinary 1.
///
/// clap's own usage errors exit themselves (status 2, and 0 for help/version).
/// A direct launch's ordinary returned failure is reported and exits 125
/// (#398); every other error is returned so `main` reports it with anyhow's
/// status 1, exactly as before. Writing the 125 message is best effort: a broken
/// stderr must not turn 125 into a panic, and 125 remains the report when
/// nothing can be written.
fn report_dispatch_failure(error: anyhow::Error, direct: bool) -> anyhow::Error {
    match error.downcast::<clap::Error>() {
        Ok(usage) => usage.exit(),
        Err(error) => match failure_status(&error, direct) {
            FailureStatus::DirectLauncher => {
                use std::io::Write as _;
                let _ = writeln!(std::io::stderr(), "Error: {error:#}");
                std::process::exit(launch_target::DIRECT_LAUNCHER_FAILURE_EXIT);
            }
            FailureStatus::Ordinary => error,
        },
    }
}

/// What status a returned dispatch failure must produce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FailureStatus {
    /// anyhow's own `Error: …` report and status 1 (every shell/tool/admin path).
    Ordinary,
    /// A direct launch's ordinary failure: 125 (#398).
    DirectLauncher,
}

/// The pure half of the status policy, so the mapping is unit-tested without
/// exiting a test process. A deferred direct configuration failure carries its
/// own marker, because the route is no longer observable after a parse failure.
fn failure_status(error: &anyhow::Error, direct: bool) -> FailureStatus {
    if direct
        || error
            .downcast_ref::<launch_target::DirectLaunchFailure>()
            .is_some()
    {
        FailureStatus::DirectLauncher
    } else {
        FailureStatus::Ordinary
    }
}

/// Everything after parsing, separated so `main` owns the exit-status policy for
/// whatever this returns.
fn run_dispatch(dispatch: Dispatch) -> Result<()> {
    // `doctor` is a **diagnostic** and must not depend on a healthy runtime to
    // inspect state (issue #93): dispatching it here, before `point_at_msb` /
    // `ensure_msb_home`, keeps it independent of MSB_HOME setup and the
    // `msb --version` identity check. `doctor::run` needs only the pure
    // `msb_home_dir()` path calculation, so it works on a missing or
    // unpatched msb. Doctor avoids runtime/VM initialization; its optional
    // credential-store check may perform bounded native keychain or Secret
    // Service I/O.
    if let Dispatch::Builtin {
        cmd: Cmd::Doctor(args),
        ..
    } = dispatch
    {
        doctor::run(args)?;
        return Ok(());
    }

    // `secret` is dispatched here, for the same reasons as `doctor` and one
    // more: it needs no msb, no catalog and no async, and it must keep working
    // when msb setup is broken (a broken tool config already carries it
    // through, see `cli::parse_from`). It reads no state that `point_at_msb`
    // provides, and `secret_store::system_store` locates the OS credential
    // store through `$HOME` only.
    if let Dispatch::Builtin {
        cmd: Cmd::Secret(args),
        ..
    } = dispatch
    {
        return exit_with(secret::run(args)?);
    }

    // `image show` reports the selection a launch *here* would make (#373). It
    // is a read-only, offline observation, so it returns before the MSB
    // prologue, the embedded-runtime extraction and the Tokio runtime: it must
    // work with no runtime installed, no cached image and no registry.
    //
    // A carried configuration failure is fatal here rather than diagnostic.
    // `parse_from` substitutes empty images on a load failure and defers a
    // catalog failure; inspecting either would report a selection no launch
    // would make. `doctor` remains the verb that diagnoses a broken config.
    if let Dispatch::Builtin {
        cmd: Cmd::Image(args),
        catalog,
        images,
    } = &dispatch
        && args.is_show()
    {
        if let config::Catalog::Broken(error) = catalog {
            anyhow::bail!("{error:#}");
        }
        return image_cmd::show(images);
    }

    // Input typos must fail before the MSB prologue creates state (#359).
    if let Dispatch::Builtin {
        cmd: Cmd::Image(args),
        ..
    } = &dispatch
    {
        image_cmd::preflight(args)?;
    }

    // Capture while no child has inherited selected values and removal cannot
    // race a Tokio worker's environment read (#163).
    let credential_preflight = match &dispatch {
        Dispatch::Launch { target, .. } => {
            credential_resolver::CredentialPreflight::capture(target.requested_names())
        }
        Dispatch::Builtin { .. } => credential_resolver::CredentialPreflight::none(),
    };

    // Locate and pin our patched msb binary via MSB_PATH so a user's
    // separate `~/.microsandbox/bin/msb` can't shadow ours. The hook
    // subcommand runs as a child of msb itself (the binary is
    // already resolved); the clipboard subcommand also runs in
    // contexts where the bundled msb may not be available
    // (e.g. inside the guest VM), so skip the check there too.
    //
    // CRITICAL: `point_at_msb()` / `configure_msb_home()` mutate the
    // process environment via `unsafe { std::env::set_var(...) }`;
    // credential preflight above also uses `remove_var` under this invariant.
    // setenv() is not thread-safe under POSIX. We MUST run them
    // before the tokio multi-thread runtime spawns workers (which
    // happens inside `Runtime::new()`). Hence the manual sync `fn
    // main` + manual runtime construction instead of `#[tokio::main]`.
    // `config::load` above reads files and env but spawns no threads, so it
    // is safe ahead of this block.
    let needs_msb_setup = !matches!(
        dispatch,
        Dispatch::Builtin {
            cmd: Cmd::InterceptHook(_) | Cmd::Clipboard(_),
            ..
        }
    );
    if needs_msb_setup {
        msb_install::point_at_msb()?;
        // Select a rerouted msb state location off `~/.microsandbox/` and into
        // agent-vm's own state dir. msb still finds `libkrunfw.so.*`
        // via MSB_PATH → sibling `../lib/` (the bundle layout); the embedded
        // rung instead pins MSB_LIBKRUNFW_PATH. No
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
    // doctor is dispatched pre-runtime and pre-msb-setup, above.
    if let Dispatch::Builtin {
        cmd: Cmd::Msb(args),
        ..
    } = dispatch
    {
        return exit_with(msb_cmd::run(args)?);
    }
    let runtime = tokio::runtime::Runtime::new().context("starting tokio runtime")?;
    runtime.block_on(async move {
        match dispatch {
            Dispatch::Launch {
                target,
                images,
                user_network,
                args,
            } => exit_with(
                run::launch(
                    target,
                    &images,
                    user_network.as_ref(),
                    credential_preflight,
                    *args,
                )
                .await?,
            ),
            Dispatch::Builtin {
                cmd: Cmd::Setup(args),
                catalog,
                images,
            } => setup::run(args, catalog, images).await,
            // The image group: `refresh` acquires natively and `set-default`
            // retains explicitly (both carry the original catalog/images, so
            // their documented broken-config recovery is preserved), while
            // `build`/`import` are the explicit user-owned publication verbs
            // (#260, #359). `show` returned above, before the runtime.
            Dispatch::Builtin {
                cmd: Cmd::Image(args),
                catalog,
                images,
            } => exit_with(image_cmd::run(args, catalog, images).await?),
            Dispatch::Builtin {
                cmd: Cmd::Clipboard(args),
                ..
            } => clipboard::run(args),
            Dispatch::Builtin {
                cmd: Cmd::InterceptHook(args),
                ..
            } => intercept_hook::run(args).await,
            // Already dispatched and returned from, above, before the
            // runtime was built.
            Dispatch::Builtin {
                cmd: Cmd::Msb(_), ..
            } => {
                unreachable!("Cmd::Msb is dispatched pre-runtime, see above")
            }
            Dispatch::Builtin {
                cmd: Cmd::Doctor(_),
                ..
            } => {
                unreachable!("Cmd::Doctor is dispatched pre-runtime, see above")
            }
            Dispatch::Builtin {
                cmd: Cmd::Secret(_),
                ..
            } => {
                unreachable!("Cmd::Secret is dispatched pre-runtime, see above")
            }
        }
    })
}

/// Wire `tracing` so `RUST_LOG=agent_vm=debug,microsandbox=info` works.
/// Default level is `warn` — keeps normal output clean, but anything from
/// the microsandbox stack surfaces when you ask for it.
///
/// A second, per-layer filter ([`crate::image_log_guard`]) suppresses all
/// non-agent-vm dependency events once this invocation has selected the default
/// boot image. The dependency image stack logs the record-sourced reference at
/// debug/trace and cannot be audited field by field; agent-vm's own events (and
/// any explicit-source invocation's dependency logging) are untouched.
fn init_tracing() {
    use tracing_subscriber::{
        EnvFilter, Layer as _, filter::FilterFn, fmt, layer::SubscriberExt as _,
        util::SubscriberInitExt as _,
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let default_tier_guard = FilterFn::new(crate::image_log_guard::dependency_event_allowed);
    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_writer(std::io::stderr)
                .with_target(true)
                .compact()
                .with_filter(filter)
                .with_filter(default_tier_guard),
        )
        .init();
}

fn exit_with(code: i32) -> Result<()> {
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::launch_target::DirectLaunchFailure;

    #[test]
    fn only_a_direct_route_or_its_deferred_marker_maps_to_125() {
        let transport = anyhow::anyhow!("transport failed");
        assert_eq!(
            failure_status(&transport, true),
            FailureStatus::DirectLauncher
        );
        assert_eq!(
            failure_status(&transport, false),
            FailureStatus::Ordinary,
            "shell/tool/administrative errors keep status 1"
        );
        let deferred = anyhow::Error::new(DirectLaunchFailure(anyhow::anyhow!("broken catalog")));
        assert_eq!(
            failure_status(&deferred, false),
            FailureStatus::DirectLauncher,
            "a parse-time direct config failure has no dispatch to ask"
        );
        // The marker reports the underlying configuration error, not itself.
        assert_eq!(format!("{deferred}"), "broken catalog");
    }
}
