//! `agent-vm setup` — pull the base OCI image and verify it under microsandbox.
//!
//! The image is hosted on a registry that CI publishes on a separate
//! cadence (see `.github/workflows/build-image.yml`). Setup just
//! pulls into microsandbox's cache and verifies by booting a
//! throwaway sandbox.
//!
//! Local source builds and cache-only image imports are separate root
//! workflows; setup intentionally pulls the selected registry image.
//!
//! # Which image it verifies
//!
//! Setup verifies *the boot image this configuration would select*
//! ([`crate::boot_image::select`], the same function a launch uses):
//! `--image` / `AGENT_VM_IMAGE_TAG`, else the user config `image`, else the
//! project config `image`, else the default boot image. It never builds an
//! image and never invokes Docker; a missing program in the verified image is
//! the image's owner's to fix, not a build to run.
//!
//! # What "verify" means
//!
//! Verification runs every configured tool's `command` directly with
//! `--version` (`sandbox.exec`, argv — never a shell string), because a config
//! `command` is not validated beyond non-empty/NUL-free and must never be
//! concatenated into a script. A non-zero exit is the hard gate, matching
//! `images/Dockerfile`'s build-time check, so a present-but-broken binary fails
//! instead of slipping through a `command -v` exists-check. `command -v` runs
//! only *after* a failure, to distinguish "absent" from "present but broken" in
//! the diagnostic.
//!
//! Severity follows the **image**, not the declaring tier (D6). A `command`
//! the default boot image is contractually required to carry (see
//! [`config::shipped_tool_commands`]) is fatal **only when the verified image is
//! the default boot image**. For any image the user selected — CLI, env, user
//! config or project config — every missing command warns: the user owns that
//! image, and `setup` never installs software. A config that redeclares a
//! shipped tool cannot downgrade a default-image absence, because the contract
//! belongs to the command, not the tier.

use anyhow::{Context, Result, bail};
use clap::Args as ClapArgs;
use microsandbox::{ExecOutput, MicrosandboxError, Sandbox, sandbox::PullPolicy};

use crate::boot_image;
use crate::config::{self, Catalog, ConfiguredImages, LaunchCatalog};

#[derive(ClapArgs)]
pub struct Args {
    /// Skip the post-pull verification sandbox.
    #[arg(long)]
    no_verify: bool,

    /// The boot image to verify. Defaults to the image this configuration
    /// would boot. See "Selecting the boot image" in USAGE.md.
    #[command(flatten)]
    pub(crate) image: boot_image::ImageArgs,
}

/// One in-guest command `setup` proves works. A newtype rather than
/// `(String, String, bool)`: the two string halves are same-typed and would be
/// swappable at the call site.
#[derive(Debug)]
struct VerifyTarget {
    /// Every catalog verb sharing this command, in catalog order — a shared
    /// binary (`shell` and a user's `mysh` both `bash`) is verified once but
    /// reported against all its verbs.
    tools: Vec<String>,
    command: String,
    /// `true` iff `command` is one of the compiled-in defaults' commands (see
    /// [`config::shipped_tool_commands`]) **and** the verified image is the
    /// default boot image. The user owns any image they selected, so a missing
    /// shipped program there warns; the default image is agent-vm's to keep
    /// working, so a missing shipped program there is fatal. A config that
    /// redeclares a shipped tool cannot move a *default-image* absence to a
    /// warning, because the contract belongs to the command, not the tier.
    required: bool,
}

/// The catalog tools `setup` verifies, in catalog order, deduped by `command`.
/// `image_is_default` follows D6: a shipped command is fatal only on the
/// default boot image.
fn verification_targets(
    catalog: &LaunchCatalog,
    image_is_default: bool,
) -> Result<Vec<VerifyTarget>> {
    let shipped = config::shipped_tool_commands()?;
    let mut targets: Vec<VerifyTarget> = Vec::new();
    for entry in catalog.as_slice() {
        let tool = entry.tool();
        let required = image_is_default && shipped.iter().any(|command| command == tool.command());
        match targets
            .iter_mut()
            .find(|target| target.command == tool.command())
        {
            Some(existing) => {
                // Two tools sharing a command share `required` too (it is a
                // function of the command), so there is nothing to fold; the
                // extra verb is still listed so the diagnostic names every
                // tool that shares the missing binary.
                existing.tools.push(tool.name().to_string());
            }
            None => targets.push(VerifyTarget {
                tools: vec![tool.name().to_string()],
                command: tool.command().to_string(),
                required,
            }),
        }
    }
    Ok(targets)
}

pub async fn run(args: Args, catalog: Catalog, images: ConfiguredImages) -> Result<()> {
    // setup also reaches connect_and_migrate (via Sandbox::builder/build and
    // Sandbox::remove), so it can hit the same forward-migrated-DB crash as
    // the boot path. See src/msb_preflight.rs and issue #30.
    crate::msb_preflight::ensure_db_not_ahead().await?;

    // Resolve the verification targets *before* pulling, so a broken config
    // still pulls and boots the image — setup's recovery path must not be
    // blocked by a config typo. A broken config falls back to the compiled-in
    // default tools (which cannot themselves be broken: a missing default entry
    // is already a hard error) and reports that the configured image could not
    // be read, using `--image`/env or the default boot image (D7).
    let verify_catalog = match catalog {
        Catalog::Ready(catalog) => catalog,
        Catalog::Broken(error) => {
            println!(
                "==> WARNING: tool configuration could not be read: {error:#}; \
                 run `agent-vm doctor`"
            );
            println!("==> Falling back to the shipped default tools for verification");
            println!(
                "==> Falling back to --image/AGENT_VM_IMAGE_TAG or the default boot image: \
                 the configured image settings could not be read"
            );
            config::default_launch_catalog().context("resolving the shipped default tools")?
        }
    };

    // The one image selection for this session (D1), shared with launch/pull.
    let boot = boot_image::select(args.image.requested()?, &images);
    let image = boot.reference().as_str().to_string();

    // D6: a shipped command is fatal only when the verified image is the
    // default boot image. A user-selected image is the user's to keep working,
    // so every missing command there warns.
    let targets = verification_targets(&verify_catalog, boot.is_default())?;

    println!("==> Pulling {image} into the microsandbox cache");
    crate::pull::pull_image(&image).await?;

    if !args.no_verify {
        verify_image(&image, &targets).await?;
    }

    println!("==> {image} ready");
    Ok(())
}

async fn verify_image(image: &str, targets: &[VerifyTarget]) -> Result<()> {
    println!("==> Verifying {image}");
    println!("==> Booting throwaway sandbox (this is the first VM cold-start; ~3s on a warm host)");
    // The pull step above already pulled the new manifest, so IfMissing
    // is fine here.
    let is_local = crate::pull::is_plain_http_registry(image);
    let config = Sandbox::builder("agent-vm-setup-verify")
        .image(image)
        .registry(|r| if is_local { r.insecure() } else { r })
        .pull_policy(PullPolicy::IfMissing)
        .cpus(1)
        .memory(512)
        .replace()
        .build()
        .await
        .context("preparing verify config")?;
    // The exact config handed to the SDK, behind AGENT_VM_DEBUG_CONFIG, so the
    // native setup check can assert the verification input's image reference.
    if let Some(dump) = crate::debug_config::sandbox_config(&config)? {
        eprintln!("{dump}");
    }
    let (progress, task) = Sandbox::create_with_pull_progress(config);
    let render_task = tokio::spawn(crate::pull_progress::render(progress));
    // See pull.rs: await render before propagating errors so finish()
    // clears the bars, and use the logging helper so render-task panics
    // are visible instead of silently swallowed.
    let result = task
        .await
        .context("create-with-pull-progress join")
        .and_then(|inner| inner.context("booting verify sandbox"));
    crate::pull_progress::await_render(render_task).await;
    let sandbox = result?;

    // Per-tool `--version` checks, run independently so the error names which
    // one fails instead of a generic && short-circuit.
    println!("==> Checking in-VM agent versions");
    for target in targets {
        // A direct argv exec (never a shell string), so a present-but-broken
        // binary fails rather than passing an exists-check.
        match sandbox.exec(&target.command, ["--version"]).await {
            Ok(out) if out.status().code == 0 => println!("    {}", out.stdout()?.trim_end()),
            outcome => {
                // Diagnostic only: distinguish absent from present-but-broken.
                // A constant script; the untrusted command travels in argv ($1).
                let present = sandbox
                    .exec(
                        "sh",
                        [
                            "-c",
                            r#"command -v -- "$1" > /dev/null"#,
                            "sh",
                            &target.command,
                        ],
                    )
                    .await
                    .map(|out| out.status().code == 0)
                    .unwrap_or(false);
                if let Err(error) = report(image, target, present, outcome) {
                    sandbox.stop_and_wait().await.ok();
                    Sandbox::remove("agent-vm-setup-verify").await.ok();
                    return Err(error);
                }
            }
        }
    }

    println!("==> Stopping verify sandbox");
    sandbox.stop_and_wait().await.ok();
    Sandbox::remove("agent-vm-setup-verify").await.ok();

    Ok(())
}

/// Compose the diagnostic from the command's severity (`required`) and whether
/// the command exists at all (`present`). A required command — a shipped
/// command being verified on the **default** boot image, which agent-vm owns —
/// bails; any other command warns and `setup` continues, because a
/// user-selected image is the user's to keep working and `setup` never installs
/// software (ADR-0035, D6).
///
/// `image` is the reference `setup` verified, so the diagnostic can name the
/// image this configuration boots and point at the tool declaration that must
/// supply the command.
///
/// A transport failure — `sandbox.exec` returning `Err` because the sandbox
/// died or agentd is unreachable — is indistinguishable here from an absent
/// binary, so a non-required tool is warned about and `setup` continues. That
/// is deliberate: `setup` cannot repair a dead sandbox by failing the run, and
/// the verify sandbox has already booted by this point.
fn report(
    image: &str,
    target: &VerifyTarget,
    present: bool,
    outcome: Result<ExecOutput, MicrosandboxError>,
) -> Result<()> {
    let verbs = target
        .tools
        .iter()
        .map(|name| format!("`{name}`"))
        .collect::<Vec<_>>()
        .join(", ");
    // Never the raw `command`: it is not validated beyond non-empty/NUL-free, so
    // printing it unescaped could inject terminal control sequences.
    let command = config::escape_str(&target.command);
    let failure = match &outcome {
        Ok(out) => {
            let code = out.status().code;
            // The evidence the pre-change bail carried, kept here so the
            // "present but `--version` exited N" case is not just a verdict.
            // Escaped: it is in-guest tool output, not a trusted value.
            let mut output = out.stdout().unwrap_or_default().trim().to_string();
            if output.is_empty() {
                output = out.stderr().unwrap_or_default().trim().to_string();
            }
            if output.is_empty() {
                format!("present but `--version` exited {code}")
            } else {
                format!(
                    "present but `--version` exited {code}; output: {}",
                    config::escape_str(&output)
                )
            }
        }
        Err(error) => format!("not runnable (`--version` could not start: {error})"),
    };

    if target.required {
        // A shipped tool is contractually required to work in the published
        // image, so this is fatal. The message distinguishes absent from
        // present-but-broken via `present` (the diagnostic, not the gate).
        let because = if present {
            format!("{failure} — the shipped binary is broken in this image")
        } else {
            "missing from the image".to_string()
        };
        // `image` may be user-supplied on `--image`, so escape it before it
        // reaches a terminal.
        let image = config::escape_str(image);
        bail!(
            "{verbs}: command {command} is {because} — {image} is the default boot image this \
             configuration boots. agent-vm does not install tools; add the program to your image \
             or change the tool's command, pull a newer tag (`agent-vm pull`), or report at \
             https://github.com/wirenboard/agent-vm/issues"
        );
    }
    if present {
        println!("==> WARNING: {verbs}: command {command} is {failure}");
    } else {
        println!(
            "==> WARNING: {verbs}: command {command} is not in the selected image {}; \
             agent-vm does not install tools — add it to your image or change the tool's \
             command",
            config::escape_str(image),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigPaths;

    /// The compiled-in default catalog, resolved without touching the
    /// developer's `$HOME` or cwd.
    fn default_catalog() -> LaunchCatalog {
        config::default_launch_catalog().expect("the embedded default catalog resolves")
    }

    /// A catalog from a throwaway project file.
    fn catalog_from(body: &str) -> LaunchCatalog {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("config.toml");
        std::fs::write(&project, body).unwrap();
        config::load(&ConfigPaths {
            user: Some(dir.path().join("no-user-config.toml")),
            project,
        })
        .expect("the fixture config parses")
        .into_launch_catalog()
        .expect("the fixture catalog resolves")
    }

    /// `(verbs, command, required)` for each target, in order.
    fn summary(targets: &[VerifyTarget]) -> Vec<(String, String, bool)> {
        targets
            .iter()
            .map(|target| {
                (
                    target.tools.join(","),
                    target.command.clone(),
                    target.required,
                )
            })
            .collect()
    }

    // -- D6: which commands are fatal, by image ownership ----------------

    #[test]
    fn default_catalog_verifies_every_shipped_tool_including_dsh() {
        assert_eq!(
            summary(&verification_targets(&default_catalog(), true).expect("targets")),
            vec![
                ("dsh".to_string(), "dsh".to_string(), true),
                ("pi".to_string(), "pi".to_string(), true),
                ("codex".to_string(), "codex".to_string(), true),
                ("opencode".to_string(), "opencode".to_string(), true),
                ("claude".to_string(), "claude".to_string(), true),
                ("copilot".to_string(), "copilot".to_string(), true),
                ("shell".to_string(), "bash".to_string(), true),
            ]
        );
    }

    /// D6: on any image the user selected, the *same* shipped catalog no longer
    /// makes a missing command fatal — the user owns that image.
    #[test]
    fn a_user_selected_image_never_makes_a_shipped_command_fatal() {
        let targets = verification_targets(&default_catalog(), false).expect("targets");
        assert_eq!(targets.len(), 7);
        assert!(
            targets.iter().all(|target| !target.required),
            "a user-selected image only warns: {targets:?}"
        );
    }

    #[test]
    fn user_declared_tools_are_not_required() {
        let targets = verification_targets(
            &catalog_from("[[tools]]\nname = \"mytool\"\ncommand = \"my-agent\"\n"),
            true,
        )
        .expect("targets");
        let mytool = targets
            .iter()
            .find(|target| target.command == "my-agent")
            .expect("mytool is verified");
        assert!(!mytool.required, "a user/project tool only warns");
    }

    #[test]
    fn a_config_redeclaring_a_shipped_tool_is_still_required() {
        // On the default image a shipped command is contractually required, and
        // that contract belongs to the *command*, not to the declaring tier. A
        // user who copies `claude` into their config to change `args` must not
        // be able to turn a missing `claude` back into a warning.
        let targets = verification_targets(
            &catalog_from("[[tools]]\nname = \"claude\"\ncommand = \"claude\"\nargs = [\"--x\"]\n"),
            true,
        )
        .expect("targets");
        let claude = targets
            .iter()
            .find(|target| target.command == "claude")
            .expect("claude is verified");
        assert!(
            claude.required,
            "redeclaring a shipped tool keeps its binary required"
        );
    }

    #[test]
    fn tools_sharing_a_command_dedupe_and_list_every_verb() {
        // `bash` is the shipped `shell`'s command; a user tool also names it, so
        // the target is shared. `required` follows the command, so it stays
        // true however the sharing tool was declared — otherwise any user could
        // silence the shipped `shell` check by adding `command = "bash"`.
        let targets = verification_targets(
            &catalog_from("[[tools]]\nname = \"mysh\"\ncommand = \"bash\"\n"),
            true,
        )
        .expect("targets");
        let bash: Vec<&VerifyTarget> = targets
            .iter()
            .filter(|target| target.command == "bash")
            .collect();
        assert_eq!(bash.len(), 1, "one target per command");
        assert_eq!(bash[0].tools, vec!["mysh".to_string(), "shell".to_string()]);
        assert!(bash[0].required, "a shipped command stays required");
    }

    // -- `report`'s severity table (manual 2/3, codified) ------------------

    fn target(tools: &[&str], command: &str, required: bool) -> VerifyTarget {
        VerifyTarget {
            tools: tools.iter().map(|name| (*name).to_string()).collect(),
            command: command.to_string(),
            required,
        }
    }

    /// The shape a missing binary takes at the `sandbox.exec` boundary (a dead
    /// sandbox is indistinguishable here, deliberately — see `report`'s doc).
    fn not_runnable() -> Result<ExecOutput, MicrosandboxError> {
        Err(MicrosandboxError::InvalidConfig("test".to_string()))
    }

    /// Manual 3 (codified): a missing *shipped* command on the default image is
    /// fatal. The message names the image and says agent-vm does not install
    /// tools, rather than advising a removed `layer` declaration.
    #[test]
    fn report_bails_for_a_missing_shipped_command() {
        let err = report(
            "ghcr.io/wirenboard/agent-vm/template:latest",
            &target(&["codex"], "codex", true),
            false,
            not_runnable(),
        )
        .expect_err("a missing shipped command must be fatal");
        let rendered = format!("{err:#}");
        assert!(rendered.contains("codex"), "{rendered}");
        assert!(rendered.contains("missing from the image"), "{rendered}");
        assert!(
            rendered.contains("ghcr.io/wirenboard/agent-vm/template:latest"),
            "the diagnostic names the image: {rendered}"
        );
        assert!(rendered.contains("does not install tools"), "{rendered}");
        assert!(!rendered.contains("layer"), "{rendered}");
    }

    /// Manual 2 (codified): a missing *user/project* command warns and the run
    /// continues.
    #[test]
    fn report_warns_for_a_missing_optional_command() {
        assert!(
            report(
                "agent-vm-template:1",
                &target(&["mytool"], "mytool", false),
                false,
                not_runnable()
            )
            .is_ok(),
            "a missing user command only warns"
        );
    }

    /// A shipped command that exists but whose `--version` could not run is
    /// still fatal on the default image, and the message says "broken" rather
    /// than "missing".
    #[test]
    fn report_bails_for_a_broken_shipped_command() {
        let err = report(
            "agent-vm-base:1",
            &target(&["claude"], "claude", true),
            true,
            not_runnable(),
        )
        .expect_err("a broken shipped command must be fatal");
        let rendered = format!("{err:#}");
        assert!(rendered.contains("broken"), "{rendered}");
    }
}
