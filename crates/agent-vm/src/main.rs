//! agent-vm — sandboxed microVMs for AI coding agents on microsandbox.

mod boot_image;
mod cli;
mod clipboard;
mod config;
mod config_authority;
mod config_mounts;
mod credential_env;
mod credential_injection;
mod credential_provider;
mod credential_resolver;
mod credential_yaml;
mod debug_config;
mod defaults;
mod direct_input;
mod direct_terminal;
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
mod mount_selection;
mod msb_cmd;
mod msb_install;
mod msb_preflight;
mod msb_schema;
mod network;
mod network_requests;
mod one_line;
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
mod shell;
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
                user_mounts,
                args,
            } => exit_with(
                run::launch(
                    target,
                    &images,
                    user_network.as_ref(),
                    user_mounts.as_ref(),
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

    // -------------------------------------------------------------------------
    // Full-but-open stdout pipe (issue #400, plan control "B1")
    //
    // The defect this exists for: a checked terminal session used to write guest
    // output with `tokio::io::stdout()`. Dropping that write future cannot cancel
    // a blocking write it already dispatched, and `Runtime::drop` waits for
    // blocking tasks — so a session that failed while its consumer stopped
    // draining could not report the failure at all: the process would hang inside
    // runtime destruction instead of exiting 125. The regression therefore needs
    // a *real* full pipe, the *real* checked bridge and the *real* launcher exit
    // policy, and it must prove the runtime was dropped **before** reporting.
    //
    // It runs as a child process because the bridge reads the process's own stdin
    // and writes its own stdout.
    // -------------------------------------------------------------------------

    /// Turns this test binary into a one-shot case child (see `full_pipe_parent`).
    const FULL_PIPE_DIR: &str = "AGENT_VM_FULL_PIPE_DIR";
    const FULL_PIPE_CASE: &str = "AGENT_VM_FULL_PIPE_CASE";
    const FULL_PIPE_CHILD: &str = "tests::checked_output_full_pipe_child";

    /// The child's deadline for the parent's own barrier, and the parent's
    /// deadline after injecting the fault. Both are fixed so a hang fails.
    fn full_pipe_deadline() -> std::time::Duration {
        std::time::Duration::from_secs(60)
    }

    /// Once the fault is injected the candidate must be done within this.
    fn fault_deadline() -> std::time::Duration {
        std::time::Duration::from_secs(5)
    }

    /// One guest output frame: larger than any pipe capacity, well under the
    /// session's 8 MiB pending bound, so the writer blocks without ever failing.
    const FULL_PIPE_FRAME_BYTES: usize = 2 * 1024 * 1024;

    /// The healthy control's payload: over the 8 MiB bound in total, so the
    /// session must wait for capacity repeatedly and lose nothing.
    const SLOW_CONSUMER_BYTES: usize = 9 * 1024 * 1024;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum FullPipeCase {
        /// The relay disappears without an exit event; the runtime stays alive.
        RelayLoss,
        /// The owned fake runtime is killed while the relay stays open.
        RuntimeLoss,
        /// A slow consumer: output well past the bound, then a definitive exit.
        HealthySlowConsumer,
    }

    impl FullPipeCase {
        fn name(self) -> &'static str {
            match self {
                Self::RelayLoss => "relay-loss",
                Self::RuntimeLoss => "runtime-loss",
                Self::HealthySlowConsumer => "healthy",
            }
        }

        fn parse(name: &str) -> Self {
            [
                Self::RelayLoss,
                Self::RuntimeLoss,
                Self::HealthySlowConsumer,
            ]
            .into_iter()
            .find(|case| case.name() == name)
            .unwrap_or_else(|| panic!("unknown full-pipe case {name}"))
        }
    }

    fn full_pipe_receipt(dir: &std::path::Path) -> std::path::PathBuf {
        dir.join("child.receipt")
    }

    fn append_receipt(path: &std::path::Path, lines: &[String]) {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open the receipt");
        for line in lines {
            writeln!(file, "{line}").expect("write the receipt");
        }
    }

    /// A deterministic byte pattern, so a consumer can prove order and loss
    /// without keeping a 9 MiB expectation on both sides.
    fn pattern_at(offset: usize) -> u8 {
        (offset % 251) as u8
    }

    /// The failure teardown for this fixture: a real adapter for the production
    /// `ExecTeardown` seam, so `finish_failed_exec` still owns the stage order and
    /// the primary-first message while the "VM" is an owned test process.
    struct RelayTeardown {
        receipt: std::path::PathBuf,
        runtime: std::sync::Arc<std::sync::Mutex<Option<std::process::Child>>>,
    }

    impl RelayTeardown {
        fn stage(&self, stage: &'static str) -> anyhow::Result<()> {
            append_receipt(&self.receipt, &[format!("stage={stage}")]);
            let mut slot = self.runtime.lock().expect("the fake runtime lock");
            if let Some(mut child) = slot.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            Ok(())
        }
    }

    impl crate::run::ExecTeardown for RelayTeardown {
        async fn stop_and_wait(&self) -> anyhow::Result<()> {
            self.stage("stop")
        }
        async fn kill_with_timeout(&self, _timeout: std::time::Duration) -> anyhow::Result<()> {
            self.stage("kill")
        }
        async fn wait(&self) -> anyhow::Result<()> {
            self.stage("reap")
        }
        async fn remove(&self) -> anyhow::Result<()> {
            self.stage("remove")
        }
    }

    /// A backend that routes everything to the process default and only replaces
    /// agent connectivity, so `SandboxBackend::attach`'s **default** implementation
    /// runs unmodified against an owned fake relay.
    struct RelayBackend {
        inner: std::sync::Arc<dyn microsandbox::backend::Backend>,
        client: std::sync::Mutex<Option<microsandbox::agent::AgentClient>>,
    }

    impl microsandbox::backend::Backend for RelayBackend {
        fn kind(&self) -> microsandbox::backend::BackendKind {
            self.inner.kind()
        }

        fn sandboxes(&self) -> &dyn microsandbox::backend::SandboxBackend {
            self.inner.sandboxes()
        }

        fn volumes(&self) -> &dyn microsandbox::backend::VolumeBackend {
            self.inner.volumes()
        }

        fn snapshots(&self) -> &dyn microsandbox::backend::SnapshotBackend {
            self.inner.snapshots()
        }

        fn dial_agent<'a>(
            &'a self,
            _name: &'a str,
            _timeout: std::time::Duration,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = microsandbox::MicrosandboxResult<microsandbox::agent::AgentClient>,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async move {
                self.client
                    .lock()
                    .expect("the relay client lock")
                    .take()
                    .ok_or_else(|| {
                        microsandbox::MicrosandboxError::Runtime(
                            "the fake relay hands out one connection".into(),
                        )
                    })
            })
        }
    }

    /// The owned fake runtime: a real process, so "torn down" means a real
    /// process state and not a recorded flag.
    struct FakeRuntime {
        child: std::sync::Arc<std::sync::Mutex<Option<std::process::Child>>>,
        pid: u32,
    }

    impl FakeRuntime {
        fn spawn() -> Self {
            let child = std::process::Command::new("/bin/sleep")
                .arg("300")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn the owned fake runtime");
            let pid = child.id();
            Self {
                child: std::sync::Arc::new(std::sync::Mutex::new(Some(child))),
                pid,
            }
        }

        /// Stop and reap it if it is still ours; returns whether this call did.
        fn stop_and_reap(&self) -> bool {
            let mut slot = self.child.lock().expect("the fake runtime lock");
            let Some(mut child) = slot.take() else {
                return false;
            };
            let _ = child.kill();
            let _ = child.wait();
            true
        }

        /// The runtime-wait future production shape: resolves when the owned
        /// runtime process ends, reaping it.
        async fn wait_future(
            child: std::sync::Arc<std::sync::Mutex<Option<std::process::Child>>>,
        ) -> microsandbox::MicrosandboxResult<std::process::ExitStatus> {
            {
                loop {
                    let polled = {
                        let mut slot = child.lock().expect("the fake runtime lock");
                        match slot.as_mut() {
                            Some(proc) => match proc.try_wait() {
                                Ok(Some(status)) => {
                                    slot.take();
                                    Ok(Some(status))
                                }
                                Ok(None) => Ok(None),
                                Err(error) => {
                                    Err(microsandbox::MicrosandboxError::Runtime(error.to_string()))
                                }
                            },
                            None => Ok(Some(exit_status_of(0))),
                        }
                    };
                    match polled {
                        Ok(Some(status)) => return Ok(status),
                        Ok(None) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
                        Err(error) => return Err(error),
                    }
                }
            }
        }
    }

    impl Drop for FakeRuntime {
        fn drop(&mut self) {
            self.stop_and_reap();
        }
    }

    fn exit_status_of(code: i32) -> std::process::ExitStatus {
        use std::os::unix::process::ExitStatusExt as _;
        std::process::ExitStatus::from_raw(code << 8)
    }

    /// The fake relay: the `[id_min][id_max]` + `Ready` handshake agentd's relay
    /// answers with, then one exec request, then the case's frames.
    async fn full_pipe_relay(
        mut io: tokio::io::DuplexStream,
        dir: std::path::PathBuf,
        case: FullPipeCase,
    ) {
        use microsandbox::protocol::codec;
        use microsandbox::protocol::core::Ready;
        use microsandbox::protocol::exec::{ExecExited, ExecStdout};
        use microsandbox::protocol::message::{Message, MessageType};
        use tokio::io::AsyncWriteExt as _;

        io.write_all(&1u32.to_be_bytes()).await.unwrap();
        io.write_all(&1024u32.to_be_bytes()).await.unwrap();
        let ready = Ready {
            boot_time_ns: 1,
            init_time_ns: 2,
            ready_time_ns: 3,
            agent_version: "full-pipe".to_string(),
            ..Default::default()
        };
        let frame = Message::with_payload(MessageType::Ready, 0, &ready).unwrap();
        codec::write_message(&mut io, &frame).await.unwrap();

        let request = codec::read_raw_frame(&mut io)
            .await
            .expect("the exec request");
        let id = request.id;

        // The parent proves raw mode before releasing the payload.
        wait_for_file(&dir, "go").await;

        match case {
            FullPipeCase::HealthySlowConsumer => {
                let mut offset = 0usize;
                while offset < SLOW_CONSUMER_BYTES {
                    let len = (SLOW_CONSUMER_BYTES - offset).min(1024 * 1024);
                    let data: Vec<u8> = (0..len).map(|index| pattern_at(offset + index)).collect();
                    codec::write_message(
                        &mut io,
                        &Message::with_payload(MessageType::ExecStdout, id, &ExecStdout { data })
                            .unwrap(),
                    )
                    .await
                    .expect("relay write");
                    offset += len;
                }
                codec::write_message(
                    &mut io,
                    &Message::with_payload(MessageType::ExecExited, id, &ExecExited { code: 7 })
                        .unwrap(),
                )
                .await
                .expect("relay write");
            }
            FullPipeCase::RelayLoss | FullPipeCase::RuntimeLoss => {
                let data: Vec<u8> = (0..FULL_PIPE_FRAME_BYTES).map(pattern_at).collect();
                codec::write_message(
                    &mut io,
                    &Message::with_payload(MessageType::ExecStdout, id, &ExecStdout { data })
                        .unwrap(),
                )
                .await
                .expect("relay write");
                append_receipt(&full_pipe_receipt(&dir), &["relay=frame-sent".to_string()]);
                if case == FullPipeCase::RelayLoss {
                    // Losing the relay without an exit event is not a completion.
                    wait_for_file(&dir, "fault").await;
                    drop(io);
                } else {
                    // Stay open: the runtime's own death must cancel the session.
                    wait_for_file(&dir, "fault").await;
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                }
            }
        }
    }

    async fn wait_for_file(dir: &std::path::Path, name: &str) {
        let deadline = std::time::Instant::now() + full_pipe_deadline();
        while !dir.join(name).exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "{name} was never released"
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    /// The failing child: the real checked bridge, the real supervision, the real
    /// failure teardown and the real 125 exit policy.
    ///
    /// Without the env token this is an ordinary passing test.
    #[test]
    fn checked_output_full_pipe_child() {
        let Ok(dir) = std::env::var(FULL_PIPE_DIR) else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        let case = FullPipeCase::parse(&std::env::var(FULL_PIPE_CASE).expect("a case"));
        let receipt = full_pipe_receipt(&dir);
        let runtime_process = FakeRuntime::spawn();
        append_receipt(&receipt, &[format!("runtime_pid={}", runtime_process.pid)]);

        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let relay = {
            let dir = dir.clone();
            // The relay needs a runtime of its own; it is spawned on the session
            // runtime below, so hand the pieces back here.
            (server_io, dir, case)
        };
        let (server_io, relay_dir, relay_case) = relay;

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("an owning runtime");
        let relay_task = runtime.spawn(full_pipe_relay(server_io, relay_dir, relay_case));
        let client = runtime
            .block_on(
                microsandbox::agent::AgentClient::connect_stream_with_timeout(
                    client_io,
                    std::time::Duration::from_secs(10),
                ),
            )
            .expect("the fake relay handshake");

        let backend: std::sync::Arc<dyn microsandbox::backend::Backend> =
            std::sync::Arc::new(RelayBackend {
                inner: microsandbox::backend::default_backend(),
                client: std::sync::Mutex::new(Some(client)),
            });
        let config = microsandbox::SandboxConfig::default();
        let options = microsandbox::sandbox::AttachOptionsBuilder::default()
            .args(["-c", "probe"])
            .cwd("/workspace/project")
            .disable_detach_keys()
            .checked_session();

        let runtime_wait = FakeRuntime::wait_future(std::sync::Arc::clone(&runtime_process.child));
        let teardown = RelayTeardown {
            receipt: receipt.clone(),
            runtime: std::sync::Arc::clone(&runtime_process.child),
        };

        // Everything the bridge and the failure path do happens inside this one
        // runtime scope, so the `drop` below is the thing under test.
        let outcome: anyhow::Result<i32> = {
            let sandboxes = backend.as_ref().sandboxes();
            let attach = sandboxes.attach(
                std::sync::Arc::clone(&backend),
                "probe",
                &config,
                "bash".to_string(),
                options,
            );
            runtime.block_on(async move {
                match crate::direct_terminal::supervise_attach(attach, runtime_wait).await {
                    Ok(code) => Ok(code),
                    Err(error) => {
                        Err(crate::run::finish_failed_exec(&teardown, error, "/logs/probe").await)
                    }
                }
            })
        };

        match outcome {
            Ok(code) => {
                append_receipt(&receipt, &[format!("status=ok:{code}")]);
                drop(runtime);
                relay_task.abort();
            }
            Err(error) => {
                // The runtime is dropped *before* the receipt and before the
                // report: that ordering is what the parent's deadline proves.
                drop(runtime);
                append_receipt(
                    &receipt,
                    &["runtime-dropped".to_string(), format!("error={:#}", error)],
                );
                // The real launcher policy for a direct failure: writes the
                // report and exits 125.
                let _ = report_dispatch_failure(error, true);
                panic!("report_dispatch_failure returned instead of exiting 125");
            }
        }
    }

    /// A fresh PTY pair, the parent's own terminal observation.
    struct ParentTerminal {
        master: std::os::fd::OwnedFd,
        slave: std::fs::File,
        baseline: String,
    }

    impl ParentTerminal {
        fn open() -> Self {
            use std::os::fd::{AsRawFd as _, FromRawFd as _};
            let mut master: libc::c_int = -1;
            let mut slave: libc::c_int = -1;
            let rc = unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            assert_eq!(rc, 0, "openpty: {}", std::io::Error::last_os_error());
            let size = libc::winsize {
                ws_row: 24,
                ws_col: 80,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            assert_ne!(
                unsafe { libc::ioctl(slave, libc::TIOCSWINSZ, &size) },
                -1,
                "set the terminal size"
            );
            let slave = unsafe { std::fs::File::from_raw_fd(slave) };
            let baseline = terminal_state(slave.as_raw_fd());
            Self {
                master: unsafe { std::os::fd::OwnedFd::from_raw_fd(master) },
                slave,
                baseline,
            }
        }

        fn slave_fd(&self) -> std::os::fd::RawFd {
            use std::os::fd::AsRawFd as _;
            self.slave.as_raw_fd()
        }

        fn master_fd(&self) -> std::os::fd::RawFd {
            use std::os::fd::AsRawFd as _;
            self.master.as_raw_fd()
        }

        fn is_raw(&self) -> bool {
            let mut attributes: libc::termios = unsafe { std::mem::zeroed() };
            let rc = unsafe { libc::tcgetattr(self.slave_fd(), &mut attributes) };
            assert_eq!(rc, 0, "read the terminal");
            attributes.c_lflag & libc::ICANON == 0
        }
    }

    /// The facts a raw-mode session must restore: canonical input, echo, signal
    /// generation, extended processing, the translations, the read protocol and
    /// the port parameters. macOS `PENDIN` is kernel bookkeeping about unread
    /// input, not something this interface sets.
    fn terminal_state(fd: std::os::fd::RawFd) -> String {
        let mut attributes: libc::termios = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::tcgetattr(fd, &mut attributes) };
        assert_eq!(
            rc,
            0,
            "read the terminal: {}",
            std::io::Error::last_os_error()
        );
        let local = libc::ICANON | libc::ECHO | libc::ECHONL | libc::ISIG | libc::IEXTEN;
        let input = libc::IXON | libc::ICRNL | libc::BRKINT | libc::INPCK | libc::ISTRIP;
        format!(
            "lflag={} iflag={} oflag={} cflag={} vmin={} vtime={} ispeed={} ospeed={}",
            attributes.c_lflag & local,
            attributes.c_iflag & input,
            attributes.c_oflag & libc::OPOST,
            attributes.c_cflag,
            attributes.c_cc[libc::VMIN],
            attributes.c_cc[libc::VTIME],
            attributes.c_ispeed,
            attributes.c_ospeed
        )
    }

    fn unread_pipe_bytes(fd: std::os::fd::RawFd) -> i32 {
        let mut unread: libc::c_int = 0;
        let rc = unsafe { libc::ioctl(fd, libc::FIONREAD, &mut unread) };
        assert_eq!(rc, 0, "FIONREAD: {}", std::io::Error::last_os_error());
        unread
    }

    fn pipe_is_writable(fd: std::os::fd::RawFd) -> bool {
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut poll, 1, 0) };
        ready > 0 && poll.revents & libc::POLLOUT != 0
    }

    fn wait_until(what: &str, deadline: std::time::Duration, mut ready: impl FnMut() -> bool) {
        let start = std::time::Instant::now();
        while start.elapsed() < deadline {
            if ready() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        panic!("{what} did not happen within {deadline:?}");
    }

    fn receipt_text(dir: &std::path::Path) -> String {
        std::fs::read_to_string(full_pipe_receipt(dir)).unwrap_or_default()
    }

    fn receipt_line_of(text: &str, key: &str) -> Option<String> {
        let prefix = format!("{key}=");
        text.lines()
            .find_map(|line| line.strip_prefix(&prefix).map(str::to_owned))
    }

    /// Whether the owned fake runtime process is gone (killed and reaped).
    /// A spawned case child that is killed and reaped if the parent panics.
    ///
    /// Every wait in this module is bounded, so a broken session fails instead of
    /// hanging; but an assertion that panics before the child exits would
    /// otherwise leave the child (and its fake runtime) behind for the rest of the
    /// suite.
    struct ChildGuard {
        child: Option<std::process::Child>,
    }

    impl ChildGuard {
        fn new(child: std::process::Child) -> Self {
            Self { child: Some(child) }
        }

        fn get(&mut self) -> &mut std::process::Child {
            self.child.as_mut().expect("the child is still owned")
        }

        /// Wait for the child under a parent-side deadline, then reap it.
        fn wait_within(&mut self, deadline: std::time::Duration) -> std::process::ExitStatus {
            let start = std::time::Instant::now();
            loop {
                if let Some(status) = self.get().try_wait().expect("try_wait") {
                    self.child = None;
                    return status;
                }
                assert!(
                    start.elapsed() < deadline,
                    "the case child did not exit within {deadline:?}"
                );
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if let Some(child) = self.child.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    fn process_is_gone(pid: u32) -> bool {
        let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
        if rc == 0 {
            return false;
        }
        std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    }

    /// The full-but-open-pipe regression: two fault paths, each asserted in the
    /// plan's order — terminal restored, VM torn down, exact status 125 — after a
    /// receipt proves the Tokio runtime was already dropped.
    #[test]
    fn a_full_open_pipe_still_reports_after_dropping_the_runtime() {
        for case in [FullPipeCase::RelayLoss, FullPipeCase::RuntimeLoss] {
            run_full_pipe_case(case);
        }
    }

    /// The healthy control: a consumer that stops draining must stall the session
    /// (never fail it), and every byte must still arrive in order before code 7.
    #[test]
    fn a_slow_consumer_receives_every_byte_then_the_guest_status() {
        run_full_pipe_case(FullPipeCase::HealthySlowConsumer);
    }

    fn run_full_pipe_case(case: FullPipeCase) {
        use std::io::Read as _;
        use std::os::fd::AsRawFd as _;

        let dir = tempfile::tempdir().expect("a case directory");
        let terminal = ParentTerminal::open();
        let (mut read_end, write_end) = std::io::pipe().expect("a stdout pipe");

        // Preflight the pipe's capacity on a description no child shares yet,
        // then restore blocking so the child's writes block as they would for a
        // real consumer that stopped reading.
        let poll_write = write_end.try_clone().expect("clone the write end");
        {
            let flags = unsafe { libc::fcntl(write_end.as_raw_fd(), libc::F_GETFL) };
            assert_ne!(flags, -1);
            assert_ne!(
                unsafe {
                    libc::fcntl(
                        write_end.as_raw_fd(),
                        libc::F_SETFL,
                        flags | libc::O_NONBLOCK,
                    )
                },
                -1
            );
            let filler = [b'p'; 4096];
            let mut capacity = 0usize;
            loop {
                let written = unsafe {
                    libc::write(write_end.as_raw_fd(), filler.as_ptr().cast(), filler.len())
                };
                if written <= 0 {
                    break;
                }
                capacity += written as usize;
            }
            assert!(
                capacity > 0,
                "the pipe must have a measurable capacity for this control"
            );
            assert!(
                capacity < FULL_PIPE_FRAME_BYTES,
                "the fixture needs a frame larger than the pipe's {capacity} bytes"
            );
            let mut drained = vec![0u8; capacity];
            let mut filled = 0usize;
            while filled < capacity {
                let read = read_end.read(&mut drained[filled..]).expect("drain");
                assert!(read > 0, "the preflight fill must be fully drained");
                filled += read;
            }
            assert_ne!(
                unsafe { libc::fcntl(write_end.as_raw_fd(), libc::F_SETFL, flags) },
                -1,
                "restore blocking before the child inherits this description"
            );
        }

        let child_slave = terminal.slave.try_clone().expect("clone the slave");
        let mut command =
            std::process::Command::new(std::env::current_exe().expect("the test binary"));
        command
            .args(["--exact", FULL_PIPE_CHILD, "--test-threads=1"])
            .env(FULL_PIPE_DIR, dir.path())
            .env(FULL_PIPE_CASE, case.name())
            .stdin(std::process::Stdio::from(child_slave))
            .stdout(std::process::Stdio::from(write_end))
            .stderr(std::process::Stdio::piped());
        let mut child = command.spawn().expect("spawn the case child");
        // `Command` still owns the `Stdio` values it was given, so dropping it is
        // what releases the parent's copy of the pipe's write end: without this
        // the parent's own read never reaches EOF and the control hangs.
        drop(command);
        let mut child_stderr = child.stderr.take().expect("child stderr");
        let stderr_reader = std::thread::spawn(move || {
            let mut sink = Vec::new();
            let _ = child_stderr.read_to_end(&mut sink);
            sink
        });

        // A held-open case proves raw mode before any payload is released.
        wait_until("raw mode", full_pipe_deadline(), || terminal.is_raw());
        std::fs::write(dir.path().join("go"), b"go").expect("release the payload");

        // Filled by the healthy-consumer arm, whose drain completes under its own
        // deadline; the fault arms never read it.
        let capture: Vec<u8>;
        match case {
            FullPipeCase::RelayLoss | FullPipeCase::RuntimeLoss => {
                // The guest output itself fills the pipe: positive unread bytes,
                // less than the frame that was sent, with no writable capacity.
                wait_until("the pipe to fill", full_pipe_deadline(), || {
                    let unread = unread_pipe_bytes(read_end.as_raw_fd());
                    unread > 0
                        && (unread as usize) < FULL_PIPE_FRAME_BYTES
                        && !pipe_is_writable(poll_write.as_raw_fd())
                });
                // Only now is the writer provably blocked, so a fault is a fault
                // in the checked writer rather than in a not-yet-started send.
                if case == FullPipeCase::RuntimeLoss {
                    // Kill the *owned* fake runtime: the session must be
                    // cancelled by the runtime wait, not by the relay.
                    let pid: u32 = receipt_line_of(&receipt_text(dir.path()), "runtime_pid")
                        .expect("the child's owned runtime pid")
                        .parse()
                        .expect("a pid");
                    assert!(
                        unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) } == 0,
                        "kill the owned fake runtime"
                    );
                }
                std::fs::write(dir.path().join("fault"), b"fault").expect("inject the fault");

                // The runtime must already be gone before the report: this
                // receipt is the discriminator against a Tokio blocking write
                // holding runtime destruction open.
                wait_until("the runtime-dropped receipt", fault_deadline(), || {
                    receipt_text(dir.path()).contains("runtime-dropped")
                });

                // 1. terminal restored, 2. VM torn down, 3. exact status.
                wait_until("terminal restoration", fault_deadline(), || {
                    terminal_state(terminal.master_fd()) == terminal.baseline
                });
                let receipt = receipt_text(dir.path());
                for stage in ["stage=stop", "stage=remove"] {
                    assert!(
                        receipt.contains(stage),
                        "missing {stage} in:
{receipt}"
                    );
                }
                let pid: u32 = receipt_line_of(&receipt, "runtime_pid")
                    .expect("the owned runtime pid")
                    .parse()
                    .expect("a pid");
                wait_until("the fake runtime to be gone", fault_deadline(), || {
                    process_is_gone(pid)
                });
                wait_until("the child to exit", fault_deadline(), || {
                    child.try_wait().expect("try_wait").is_some()
                });
                let status = child.wait().expect("reap the child");
                let stderr = String::from_utf8_lossy(&stderr_reader.join().unwrap()).into_owned();
                assert_eq!(
                    status.code(),
                    Some(crate::launch_target::DIRECT_LAUNCHER_FAILURE_EXIT),
                    "{case:?}: the failure must be reported as 125; stderr: {stderr}; receipt:
{receipt}"
                );
                assert!(
                    stderr.contains("Error:"),
                    "{case:?}: the production report must name the failure: {stderr}"
                );
            }
            FullPipeCase::HealthySlowConsumer => {
                // Draining is held until the session is genuinely stalled, then
                // released: capacity waits must have taken over, not failed.
                wait_until(
                    "the session to stall on a full pipe",
                    full_pipe_deadline(),
                    || unread_pipe_bytes(read_end.as_raw_fd()) > 0,
                );
                // The parent's own write-end duplicate would keep the pipe open
                // and `read_to_end` would never see EOF; the child's copy is the
                // only writer from here on.
                drop(poll_write);
                // Drain concurrently under a parent-side completion deadline: only
                // the *start* of draining used to be bounded, so a session that
                // stopped progressing after its first bytes hung the suite instead
                // of failing it.
                let mut guard = ChildGuard::new(child);
                let (finished, wait_for_finish) = std::sync::mpsc::channel();
                let drainer = std::thread::spawn(move || {
                    let mut sink = Vec::new();
                    let result = read_end.read_to_end(&mut sink);
                    let _ = finished.send(());
                    (sink, result)
                });
                wait_for_finish
                    .recv_timeout(fault_deadline())
                    .unwrap_or_else(|_| {
                        panic!(
                            "the healthy session stopped progressing: the consumer did not \
                             reach EOF within {:?}",
                            fault_deadline()
                        )
                    });
                let (drained, read) = drainer.join().expect("the drain thread");
                read.expect("drain the healthy session");
                capture = drained;
                let status = guard.wait_within(fault_deadline());
                let receipt = receipt_text(dir.path());
                let stderr = String::from_utf8_lossy(&stderr_reader.join().unwrap()).into_owned();
                assert_eq!(
                    status.code(),
                    Some(0),
                    "{stderr}
{receipt}"
                );
                assert_eq!(
                    receipt_line_of(&receipt, "status").as_deref(),
                    Some("ok:7"),
                    "{receipt}"
                );
                // Every byte, in order. The harness itself also writes to this
                // descriptor, so the payload is located exactly rather than the
                // whole capture being compared.
                let expected: Vec<u8> = (0..SLOW_CONSUMER_BYTES).map(pattern_at).collect();
                assert!(
                    capture.len() >= expected.len(),
                    "the consumer received {} of {} bytes",
                    capture.len(),
                    expected.len()
                );
                assert!(
                    capture
                        .windows(expected.len())
                        .any(|window| window == expected.as_slice()),
                    "the {SLOW_CONSUMER_BYTES}-byte payload did not arrive byte-for-byte in order"
                );
            }
        }
        assert_eq!(
            terminal_state(terminal.master_fd()),
            terminal.baseline,
            "{case:?}: the terminal must be restored"
        );
    }

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
