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
//! Setup verifies *the published image this configuration would boot from*
//! ([`crate::tool_layer::chain_root`]): the composed default template for the
//! shipped default tool set, or the tool-free base when the configured set
//! differs. It verifies the published root; it does **not** build a local tool
//! chain (the first launch does that), so it cannot prove a not-yet-composed
//! tool layer works.
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
//! Severity follows the `command`, not the declaring tier: a `command` the
//! verified image is contractually required to carry (see
//! [`config::shipped_tool_commands`]) is fatal. Two things soften that, and
//! only two: a command the *base* has never been expected to carry (any
//! non-shipped `command`) warns; and, when `setup` is verifying the tool-free
//! base because the launch composes locally (D10), a shipped command **that a
//! declared tool layer supplies** is downgraded to a notice — the layer carries
//! it, not the base. A shipped command no declared layer supplies stays fatal,
//! so a genuinely broken base still fails `setup`.

use anyhow::{Context, Result, bail};
use clap::Args as ClapArgs;
use microsandbox::{ExecOutput, MicrosandboxError, Sandbox, sandbox::PullPolicy};
use std::collections::BTreeMap;

use crate::config::{self, Catalog, LaunchCatalog};

#[derive(ClapArgs)]
pub struct Args {
    /// Skip the post-pull verification sandbox.
    #[arg(long)]
    no_verify: bool,

    /// Boot and verify this image verbatim, skipping tool-layer composition.
    ///
    /// Defaults to the image this configuration would boot from — the composed
    /// default template for the shipped tool set, or the tool-free base when
    /// the configured set differs. Mutually exclusive with `--base-image`.
    #[arg(long, env = "AGENT_VM_IMAGE_TAG", value_name = "REF")]
    image: Option<String>,

    /// Verify the tool-free base that tool layers are composed onto.
    ///
    /// Default `ghcr.io/wirenboard/agent-vm-base:latest`. Passing this always
    /// targets the base, even when the tool set matches the shipped default.
    /// Mutually exclusive with `--image`.
    #[arg(long = "base-image", env = "AGENT_VM_BASE_IMAGE", value_name = "REF")]
    base_image: Option<String>,
}

/// One in-guest command `setup` proves works. A newtype rather than
/// `(String, String, bool)`: the two string halves are same-typed and would be
/// swappable at the call site.
struct VerifyTarget {
    /// Every catalog verb sharing this command, in catalog order — a shared
    /// binary (`shell` and a user's `mysh` both `bash`) is verified once but
    /// reported against all its verbs.
    tools: Vec<String>,
    command: String,
    /// `true` iff `command` is one of the compiled-in defaults' commands (see
    /// [`config::shipped_tool_commands`]) **and** no declared tool layer
    /// supplies it. That contract is a property of the binary, not of the
    /// declaring tier: a user/project config that redeclares a shipped tool (or
    /// shares its command) must not be able to downgrade its absence to a
    /// warning. The one exception is D10's: when the verified image is the
    /// tool-free base and a declared tool layer supplies the command, the base
    /// is not expected to carry it.
    required: bool,
}

/// The catalog tools `setup` verifies, in catalog order, deduped by `command`.
/// `required` is true iff the `command` is one of the compiled-in defaults'
/// commands ([`config::shipped_tool_commands`]) **and** no declared tool layer
/// supplies it (`supplied`, non-empty only when the verified root is the
/// tool-free base — D10). A command a declared layer will supply is a fact
/// about a *different* image than the one being verified, so its absence from
/// the base is expected.
fn verification_targets(
    catalog: &LaunchCatalog,
    supplied: &BTreeMap<String, String>,
) -> Result<Vec<VerifyTarget>> {
    let shipped = config::shipped_tool_commands()?;
    let mut targets: Vec<VerifyTarget> = Vec::new();
    for entry in catalog.as_slice() {
        let tool = entry.tool();
        let required = shipped.iter().any(|command| command == tool.command())
            && !supplied.contains_key(tool.command());
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

pub async fn run(args: Args, catalog: Catalog) -> Result<()> {
    // setup also reaches connect_and_migrate (via Sandbox::builder/build and
    // Sandbox::remove), so it can hit the same forward-migrated-DB crash as
    // the boot path. See src/msb_preflight.rs and issue #30.
    crate::msb_preflight::ensure_db_not_ahead().await?;

    // Resolve the verification targets *before* pulling, so a broken config
    // still pulls and boots the image — setup's recovery path must not be
    // blocked by a config typo. A broken config falls back to the compiled-in
    // default tools (which cannot themselves be broken: a missing default entry
    // is already a hard error), matching today's behaviour where a broken
    // project config did not affect `setup` at all.
    let (verify_catalog, declared_layers) = match catalog {
        Catalog::Ready(catalog) => {
            let layers = catalog.declared_layers();
            (catalog, layers)
        }
        Catalog::Broken(error) => {
            println!(
                "==> WARNING: tool configuration could not be read: {error:#}; \
                 run `agent-vm doctor`"
            );
            println!("==> Falling back to the shipped default tools for verification");
            let defaults =
                config::default_launch_catalog().context("resolving the shipped default tools")?;
            let layers = defaults.declared_layers();
            (defaults, layers)
        }
    };

    // The image this configuration would boot from (issue #84). `setup`
    // verifies the published *root*; it never builds the local tool chain.
    let declared_layer_values: Vec<config::ToolLayer> =
        declared_layers.iter().map(|l| l.layer().clone()).collect();
    let root = crate::tool_layer::chain_root(
        args.image.clone(),
        args.base_image.clone(),
        &declared_layer_values,
        &config::shipped_tool_layers()?,
    )?;
    let image = root.reference().to_string();

    // D10: a shipped command is downgraded to a notice only when the launch
    // composes locally (`Base`) AND a declared tool layer supplies it. On every
    // other root, nothing is downgraded.
    let supplied: BTreeMap<String, String> = if root.composes_tool_layers() {
        declared_layers
            .iter()
            .map(|layer| (layer.command().to_string(), layer.tool().to_string()))
            .collect()
    } else {
        BTreeMap::new()
    };

    let targets = verification_targets(&verify_catalog, &supplied)?;

    // One line per layer-supplied command, naming the layer that will supply
    // it on the first composed launch.
    let shipped = config::shipped_tool_commands()?;
    for target in &targets {
        if let Some(tool) = supplied.get(&target.command)
            && !target.required
            && shipped.iter().any(|command| command == &target.command)
        {
            println!(
                "==> {} is supplied by tool layer \"{tool}\", which this base does not carry yet; \
                 verifying the published base only. The first launch composes the chain.",
                target.command
            );
        }
    }

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

    // Image-API-version range check: same path agent-vm run takes
    // on every launch. Mismatch here = an actionable error at setup
    // time rather than a mysterious failure on first `agent-vm claude`.
    println!("==> Checking image-API contract version");
    crate::image_api_version::check(&sandbox)
        .await
        .with_context(|| {
            format!(
                "image-API check during verify failed; {image} is not compatible with this agent-vm"
            )
        })?;

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
/// the command exists at all (`present`). A required command — one the verified
/// image is contractually required to carry, regardless of which tier declared
/// the tool — bails; any other command warns and `setup` continues, because
/// `setup` does not build the tooling layer that might supply it.
///
/// `image` is the reference `setup` verified, so the fatal diagnostic can name
/// the image this configuration boots and point at the `layer` field that would
/// supply the command — the failure a user hits after redeclaring a shipped tool
/// *without* a `layer` (the declaration that was cheap while `layer` was
/// metadata).
///
/// A transport failure — `sandbox.exec` returning `Err` because the sandbox
/// died or agentd is unreachable — is indistinguishable here from an absent
/// binary, so a non-required tool is warned about and `setup` continues. That
/// is deliberate: `setup` cannot repair a dead sandbox by failing the run, and
/// the image-API check has already passed by this point.
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
        // `image` is user-supplied on `--base-image`/`--image`, so escape it
        // before it reaches a terminal.
        let image = config::escape_str(image);
        bail!(
            "{verbs}: command {command} is {because} — {image} is the image this configuration \
             boots. If the tool is meant to be composed locally, declare `layer = {{ builtin = \
             … }}` (or a `path`) on it: `setup` verifies the base and the first launch composes \
             it. Otherwise pull a newer tag (`agent-vm pull`) or report at \
             https://github.com/wirenboard/agent-vm/issues"
        );
    }
    if present {
        println!("==> WARNING: {verbs}: command {command} is {failure}");
    } else {
        println!(
            "==> WARNING: {verbs}: command {command} is not in the image; if a `.agent-vm/layers/` \
             tooling layer supplies it that is expected — `setup` does not build layers; \
             otherwise check the tool's `command`"
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

    // -- V9: the default catalog verifies copilot, in catalog order ---------

    #[test]
    fn default_catalog_verifies_every_shipped_tool_including_copilot() {
        assert_eq!(
            summary(&verification_targets(&default_catalog(), &BTreeMap::new()).expect("targets")),
            vec![
                ("pi".to_string(), "pi".to_string(), true),
                ("codex".to_string(), "codex".to_string(), true),
                ("opencode".to_string(), "opencode".to_string(), true),
                ("claude".to_string(), "claude".to_string(), true),
                ("copilot".to_string(), "copilot".to_string(), true),
                ("shell".to_string(), "bash".to_string(), true),
            ]
        );
    }

    // -- V9: command-driven required, dedupe listing every verb ------------

    #[test]
    fn user_declared_tools_are_not_required() {
        let targets = verification_targets(
            &catalog_from("[[tools]]\nname = \"mytool\"\ncommand = \"my-agent\"\n"),
            &BTreeMap::new(),
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
        // The published image is contractually required to carry `claude`, and
        // that contract belongs to the *command*, not to the declaring tier. A
        // user who copies `claude` into their config to change `args` must not
        // be able to turn a missing `claude` back into a warning.
        let targets = verification_targets(
            &catalog_from("[[tools]]\nname = \"claude\"\ncommand = \"claude\"\nargs = [\"--x\"]\n"),
            &BTreeMap::new(),
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
            &BTreeMap::new(),
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

    // -- D10: the narrowed `Base`-root downgrade ----------------------------

    /// Mirrors `run`'s computation: chain_root over the catalog's declared
    /// layers, then the supplied-command set only when the root composes.
    fn targets_for(body: &str, image: Option<String>, base: Option<String>) -> Vec<VerifyTarget> {
        let catalog = catalog_from(body);
        let declared = catalog.declared_layers();
        let values: Vec<config::ToolLayer> = declared.iter().map(|l| l.layer().clone()).collect();
        let root = crate::tool_layer::chain_root(
            image,
            base,
            &values,
            &config::shipped_tool_layers().expect("shipped layers"),
        )
        .expect("chain_root");
        let supplied: BTreeMap<String, String> = if root.composes_tool_layers() {
            declared
                .iter()
                .map(|l| (l.command().to_string(), l.tool().to_string()))
                .collect()
        } else {
            BTreeMap::new()
        };
        verification_targets(&catalog, &supplied).expect("targets")
    }

    fn required_of(targets: &[VerifyTarget], command: &str) -> bool {
        targets
            .iter()
            .find(|t| t.command == command)
            .unwrap_or_else(|| panic!("{command} is verified"))
            .required
    }

    /// A `Base` root with `tools=["claude"]` (declaring the layer) downgrades
    /// `claude` —a layer supplies it—but `bash` (supplied by no layer) stays
    /// fatal, so a genuinely broken base still fails `setup`.
    #[test]
    fn base_root_downgrades_only_layer_supplied_commands() {
        let targets = targets_for(
            "[[tools]]\nname = \"claude\"\ncommand = \"claude\"\nlayer = { builtin = \"claude\" }\n",
            None,
            None,
        );
        assert!(!required_of(&targets, "claude"), "claude is layer-supplied");
        assert!(
            required_of(&targets, "bash"),
            "bash is supplied by no layer"
        );
    }

    /// A `Base` root where a shipped command is declared **without** a layer
    /// keeps that command fatal: the narrowing is by declared layer, not by
    /// tool set.
    #[test]
    fn base_root_without_a_supplying_layer_keeps_the_command_fatal() {
        let targets = targets_for(
            "[[tools]]\nname = \"mytool\"\ncommand = \"codex\"\n",
            None,
            None,
        );
        assert!(
            required_of(&targets, "codex"),
            "a shipped command no layer supplies stays fatal"
        );
    }

    /// `Template` and `Verbatim` roots downgrade nothing.
    #[test]
    fn non_composing_roots_downgrade_nothing() {
        // Template: a default-shaped layer sequence boots the composed image.
        let default_body = "[[tools]]\nname = \"pi\"\ncommand = \"pi\"\nlayer = { builtin = \"pi\" }\n\
             [[tools]]\nname = \"codex\"\ncommand = \"codex\"\nlayer = { builtin = \"codex\" }\n\
             [[tools]]\nname = \"opencode\"\ncommand = \"opencode\"\nlayer = { builtin = \"opencode\" }\n\
             [[tools]]\nname = \"claude\"\ncommand = \"claude\"\nlayer = { builtin = \"claude\" }\n\
             [[tools]]\nname = \"copilot\"\ncommand = \"copilot\"\nlayer = { builtin = \"copilot\" }\n";
        let targets = targets_for(default_body, None, None);
        assert!(
            required_of(&targets, "claude"),
            "Template downgrades nothing"
        );

        // Verbatim via --image: even a layer-supplied command is required.
        let targets = targets_for(
            "[[tools]]\nname = \"claude\"\ncommand = \"claude\"\nlayer = { builtin = \"claude\" }\n",
            Some("myimg:1".to_string()),
            None,
        );
        assert!(required_of(&targets, "claude"));
    }

    // -- V9: `report`'s severity table (manual 2/3, codified) --------------

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

    /// Manual 3 (codified): a missing *shipped* command is fatal. The real-VM
    /// run in `verifications.md` uses a derived image with `codex` removed;
    /// this pins the same decision boot-free. The message names the image this
    /// configuration boots, so a user who redeclared a shipped tool without a
    /// `layer` learns why the guest would be missing it.
    #[test]
    fn report_bails_for_a_missing_shipped_command() {
        let err = report(
            "ghcr.io/wirenboard/agent-vm-base:latest",
            &target(&["codex"], "codex", true),
            false,
            not_runnable(),
        )
        .expect_err("a missing shipped command must be fatal");
        let rendered = format!("{err:#}");
        assert!(rendered.contains("codex"), "{rendered}");
        assert!(rendered.contains("missing from the image"), "{rendered}");
        assert!(
            rendered.contains("ghcr.io/wirenboard/agent-vm-base:latest"),
            "the diagnostic names the image this configuration boots: {rendered}"
        );
        assert!(rendered.contains("layer"), "{rendered}");
    }

    /// Manual 2 (codified): a missing *user/project* command warns and the run
    /// continues — `setup` does not build `.agent-vm/layers/`.
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
    /// still fatal, and the message says "broken" rather than "missing".
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
