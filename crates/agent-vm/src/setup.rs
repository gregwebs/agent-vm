//! `agent-vm setup` — pull the selected OCI image and verify it under microsandbox.
//!
//! Standard-image releases belong to the independent agent-vm-images repo. Setup just
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
//! Verification probes exactly the tools the configuration *declares*
//! ([`LaunchCatalog::declarations`], [`Catalog::Ready`]'s two-tier merge: the
//! shipped defaults only when both tiers declare zero tools, otherwise the
//! tools the tiers declare). The synthesized `shell` fallback is a launch
//! affordance, not a declaration, so it is not verified; a command the
//! configuration does not name is never checked.
//!
//! Every declared tool is required, identically on the default boot image and
//! on any image the user selected (`--image`, `AGENT_VM_IMAGE_TAG`, or a config
//! `image`): the configuration says which commands must work, so a missing or
//! broken one always fails the run. Verification runs each target's `command`
//! directly with `--version` (`sandbox.exec`, argv — never a shell string),
//! because a config `command` is not validated beyond non-empty/NUL-free and
//! must never be concatenated into a script. `--version` is the gate: a non-zero
//! exit is fatal, so a
//! present-but-broken binary fails instead of slipping through an exists-check.
//! The diagnostic then classifies *why* the command failed by probing how the
//! `command` appears on the guest — a guest `PATH` search for a bare name, a
//! direct test for a pathname — distinguishing three cases: no entry found on
//! the guest `PATH` (for a bare name) or at the configured path (for a
//! pathname), present but not a runnable executable (a non-executable file or a
//! directory), and present but `--version` failed.
//! Only the probe's literal token establishes absence; an unclassifiable probe
//! is reported as unproven, never as missing. (`command -v` is not used, because
//! a PATH search need not report a non-executable file.) A
//! presence/executability-only mode — no `--version` probe — may be offered
//! later as an alternative; it is deliberately not implemented here.
//! `--no-verify` skips the whole step for an image the user knows is fine.

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

/// One in-guest command `setup` proves works. A newtype rather than a bare
/// pair: the verb names and the binary they run are both strings and would be
/// swappable at the call site.
#[derive(Debug)]
struct VerifyTarget {
    /// Every catalog verb sharing this command, in catalog order — a shared
    /// binary (`shell` and a user's `mysh` both `bash`) is verified once but
    /// reported against all its verbs.
    tools: Vec<String>,
    command: String,
}

/// The catalog tools `setup` verifies, in catalog order, deduped by `command`.
/// The scope is the *declared* entries ([`LaunchCatalog::declarations`]) — the
/// synthesized `shell` fallback is a launch affordance, not a declaration, so
/// an undeclared shipped command is never a target and every returned target is
/// required. `as_slice` (fallback included) stays the verb list for
/// `cli`/`doctor`.
fn verification_targets(catalog: &LaunchCatalog) -> Vec<VerifyTarget> {
    let mut targets: Vec<VerifyTarget> = Vec::new();
    for entry in catalog.declarations() {
        let tool = entry.tool();
        match targets
            .iter_mut()
            .find(|target| target.command == tool.command())
        {
            Some(existing) => {
                // The extra verb is still listed so the diagnostic names every
                // tool that shares the missing binary.
                existing.tools.push(tool.name().to_string());
            }
            None => targets.push(VerifyTarget {
                tools: vec![tool.name().to_string()],
                command: tool.command().to_string(),
            }),
        }
    }
    targets
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
    let boot = boot_image::select(args.image.requested()?, &images)?;
    let label = boot.label();
    let image = boot.reference().as_str().to_string();

    // The verification scope is the resolved configuration's *declarations*,
    // the same on the default boot image and on any image the user selected:
    // the synthesized `shell` fallback is not a target, an undeclared shipped
    // command is not probed, and every declared tool is fatal if it is missing
    // or broken.
    let targets = verification_targets(&verify_catalog);

    println!("==> Pulling {} into the microsandbox cache", label.text());
    crate::pull::pull_image(&image, &label).await?;
    // Success-before-adoption (#261): record a default-tier selection only
    // after its forced acquisition succeeded, and before verification.
    boot_image::adopt_default_selection(&boot)
        .context("retaining the selected default boot image")?;

    if !args.no_verify {
        verify_image(&boot, &targets).await?;
    }

    println!("==> {} ready", label.text());
    Ok(())
}

async fn verify_image(boot: &boot_image::BootImage, targets: &[VerifyTarget]) -> Result<()> {
    let label = boot.label();
    let image = boot.reference().as_str();
    println!("==> Verifying {}", label.text());
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
    // native setup check can assert the verification input's image reference. A
    // redacted selection renders a fixed marker instead.
    if let Some(dump) = crate::debug_config::sandbox_config(&config, label.is_redacted())? {
        eprintln!("{dump}");
    }
    let (progress, task) = Sandbox::create_with_pull_progress(config);
    let reference_label = label.is_redacted().then(|| label.text().to_string());
    let render_task = tokio::spawn(crate::pull_progress::render(progress, reference_label));
    // See pull.rs: await render before propagating errors so finish()
    // clears the bars, and use the logging helper so render-task panics
    // are visible instead of silently swallowed.
    let result = task
        .await
        .context("create-with-pull-progress join")
        .and_then(|inner| inner.context("booting verify sandbox"));
    crate::pull_progress::await_render(render_task).await;
    let sandbox = result
        .map_err(|error| label.redact_error("booting the verification sandbox from", error))?;

    // Per-tool `--version` checks, run independently so the error names which
    // one fails instead of a generic && short-circuit.
    println!("==> Checking in-VM agent versions");
    for target in targets {
        // A direct argv exec (never a shell string), so a present-but-broken
        // binary fails rather than passing an exists-check.
        match sandbox.exec(&target.command, ["--version"]).await {
            Ok(out) if out.status().code == 0 => println!("    {}", out.stdout()?.trim_end()),
            outcome => {
                // Diagnostic only: classify how the declared command appears
                // on the guest, so "not found", "found but not executable"
                // and "runs but `--version` failed" are distinct.
                let presence = probe_command_presence(&sandbox, &target.command).await;
                if let Err(error) = report(&label, target, presence, outcome) {
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

/// How a declared `command` appears on the guest, from the constant probe in
/// [`PROBE_COMMAND_PRESENCE`]: a `PATH` search when the `command` is a bare
/// name, a direct test when it names a path. "The binary is missing", "the
/// entry is there but not a runnable executable" and "it runs but rejects
/// `--version`" are different user problems with different fixes: only the last
/// is a broken tool.
///
/// `command -v` is deliberately not used: a PATH search need not report a
/// non-executable file, so it would misreport [`Self::NotExecutable`] as absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandPresence {
    /// No entry of that name exists *where the probe looked*: no `PATH`
    /// directory holds a bare name, and a pathname `command` names nothing at
    /// that path. What this proves is bounded by the search — a program
    /// installed off `PATH` (say `/opt/private/foo`) is still reported here for
    /// a bare name (the literal probe token is the only thing that establishes
    /// this).
    Absent,
    /// An entry of that name exists — on `PATH` for a bare name, at the named
    /// path otherwise — but it is not a runnable executable: a non-executable
    /// file, or a directory. A directory passes `-x`, so executability alone
    /// cannot classify it.
    NotExecutable,
    /// An executable entry of that name exists, so a `--version` failure is the
    /// binary's own rather than a lookup failure.
    Executable,
    /// The probe ran but did not print one of the three literal tokens (an
    /// unknown string or extra output, or non-UTF-8 bytes). This does **not**
    /// prove absence, so the diagnostic must not report the command as missing.
    Unknown,
}

/// Classify `$1` against `$PATH` (or, when it names a path, against that path)
/// and print one of the literal tokens `executable`, `not-executable`,
/// `absent`.
///
/// A constant script; the untrusted command name travels in argv (`$1`), never
/// interpolated into the text. Two shell-equivalence points are deliberate: an
/// empty PATH element means the current directory (including a *trailing* one,
/// which word splitting on an unquoted `$PATH` would drop), and `set -f` plus a
/// hand-rolled split keep a metacharacter in `$PATH` from being
/// pathname-expanded. `command -v` is not used (see [`CommandPresence`]).
const PROBE_COMMAND_PRESENCE: &str = r#"name=$1
# A command containing a slash is a path, not a PATH lookup. Test it directly;
# a directory is `-x` but is not a runnable command.
case $name in
    */*)
        if [ ! -e "$name" ] && [ ! -L "$name" ]; then printf absent; exit 0; fi
        if [ -d "$name" ]; then printf not-executable; exit 0; fi
        if [ -x "$name" ]; then printf executable; exit 0; fi
        printf not-executable
        exit 0
        ;;
esac
set -f
found=0
remaining=$PATH
while :; do
    case $remaining in
        *:*)
            dir=${remaining%%:*}
            remaining=${remaining#*:}
            more=1
            ;;
        *)
            dir=$remaining
            more=0
            ;;
    esac
    [ -n "$dir" ] || dir=.
    if [ -e "$dir/$name" ] || [ -L "$dir/$name" ]; then
        found=1
        if [ -x "$dir/$name" ] && [ ! -d "$dir/$name" ]; then
            printf executable
            exit 0
        fi
    fi
    [ "$more" -eq 1 ] || break
done
if [ "$found" -eq 1 ]; then printf not-executable; else printf absent; fi
"#;

/// Map the probe's stdout to a [`CommandPresence`]. Only a literal token
/// establishes a state; anything else (empty output, an unknown token, extra
/// output) is [`CommandPresence::Unknown`], never [`CommandPresence::Absent`].
fn classify_command_presence(stdout: &str) -> CommandPresence {
    match stdout.trim() {
        "executable" => CommandPresence::Executable,
        "not-executable" => CommandPresence::NotExecutable,
        "absent" => CommandPresence::Absent,
        _ => CommandPresence::Unknown,
    }
}

/// Run [`PROBE_COMMAND_PRESENCE`] in the guest. `None` means the probe itself
/// could not run (a dead sandbox or agentd), a transport failure rather than a
/// statement about the command; a probe that ran but produced no literal token
/// (including non-UTF-8 bytes) is [`CommandPresence::Unknown`].
async fn probe_command_presence(sandbox: &Sandbox, command: &str) -> Option<CommandPresence> {
    let out = sandbox
        .exec("sh", ["-c", PROBE_COMMAND_PRESENCE, "sh", command])
        .await
        .ok()?;
    if out.status().code != 0 {
        // The probe itself failed; nothing it printed is trustworthy.
        return Some(CommandPresence::Unknown);
    }
    match out.stdout() {
        Ok(stdout) => Some(classify_command_presence(&stdout)),
        Err(_) => Some(CommandPresence::Unknown),
    }
}

/// Compose the fatal diagnostic from how the declared command appears on the
/// guest (`presence`) and the `--version` outcome. Every target is a
/// configuration-declared tool, so any failure bails: the configuration says
/// the command must work, `setup` never installs software, and severity does
/// not depend on image provenance (ADR-0035).
///
/// The message separates three cases — no entry found on the guest `PATH` or at
/// the configured path, present but not a runnable executable,
/// present-but-broken — so the user knows whether to add
/// the program, fix its mode or its path entry, or fix the tool. `command
/// --version` stays the gate; a presence/executability-only mode may be offered
/// later as an alternative, but is deliberately not implemented here.
///
/// `label` is the safe name of the image `setup` verified (an escaped explicit
/// reference, or the fixed default-tier label), so the diagnostic can name the
/// image this configuration boots without echoing a record-sourced reference,
/// and point at the tool declaration that must supply the command.
///
/// When `presence` cannot establish a state — `None` (a transport failure) or
/// [`CommandPresence::Unknown`] (the probe printed no literal token) — the
/// message renders the `--version` failure itself and never claims the command
/// is missing.
fn report(
    label: &boot_image::ImageLabel,
    target: &VerifyTarget,
    presence: Option<CommandPresence>,
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

    // `Unknown` and the transport `None` both leave the command unproven:
    // render the raw failure, never "not found".
    let because = match presence {
        // A bare name is resolved by scanning the guest `PATH`, so the probe
        // can only show that no entry is there — a program installed off
        // `PATH` (say `/opt/private/foo`) is still reported absent. A `command`
        // containing a slash is tested directly at that path, so its absence
        // is a statement about that path alone. Neither case is permission to
        // claim the image does not carry the program.
        Some(CommandPresence::Absent) if target.command.contains('/') => {
            "not found at the configured path".to_string()
        }
        Some(CommandPresence::Absent) => "not found on the guest `PATH`".to_string(),
        Some(CommandPresence::NotExecutable) => {
            "present in the image but not executable: a matching entry exists, but it \
             is not a runnable program (a non-executable file or a directory)"
                .to_string()
        }
        Some(CommandPresence::Executable) => {
            format!("{failure} — the binary is broken in this image")
        }
        Some(CommandPresence::Unknown) | None => failure,
    };
    // `label` is escaped for an explicit source and a fixed phrase for the
    // default tier, so it is safe before it reaches a terminal.
    bail!(
        "{verbs}: command {command} is {because} — this configuration boots {}. \
         agent-vm does not install tools; add the program to your image or change the \
         tool's command, pull a newer tag (`agent-vm pull`), or report at \
         https://github.com/wirenboard/agent-vm/issues",
        label.text()
    )
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

    /// `(verbs, command)` for each target, in order.
    fn summary(targets: &[VerifyTarget]) -> Vec<(String, String)> {
        targets
            .iter()
            .map(|target| (target.tools.join(","), target.command.clone()))
            .collect()
    }

    // -- which commands `setup` verifies ----------------------------------

    #[test]
    fn default_catalog_verifies_every_shipped_tool_including_dsh() {
        assert_eq!(
            summary(&verification_targets(&default_catalog())),
            vec![
                ("dsh".to_string(), "dsh".to_string()),
                ("pi".to_string(), "pi".to_string()),
                ("codex".to_string(), "codex".to_string()),
                ("opencode".to_string(), "opencode".to_string()),
                ("claude".to_string(), "claude".to_string()),
                ("copilot".to_string(), "copilot".to_string()),
                ("shell".to_string(), "bash".to_string()),
            ]
        );
    }

    /// The default config declares `shell` itself, so the fallback is not
    /// synthesized and `bash` is a real declared target — not a fallback being
    /// verified.
    #[test]
    fn the_default_shell_is_a_declaration_not_a_fallback() {
        let catalog = default_catalog();
        assert!(
            !catalog.has_shell_fallback(),
            "the shipped defaults declare `shell`"
        );
        assert!(
            verification_targets(&catalog)
                .iter()
                .any(|target| target.command == "bash" && target.tools == ["shell"]),
            "the declared shell is still a target"
        );
    }

    /// The scope is the *declared* tools: undeclared shipped commands are not
    /// targets, and neither is the synthesized `shell` fallback — it is a
    /// launch affordance, not a declaration.
    #[test]
    fn only_declared_tools_are_verified() {
        let catalog = catalog_from("[[tools]]\nname = \"mytool\"\ncommand = \"my-agent\"\n");
        assert!(catalog.has_shell_fallback(), "the fallback is synthesized");
        assert_eq!(
            summary(&verification_targets(&catalog)),
            vec![("mytool".to_string(), "my-agent".to_string())],
            "undeclared shipped commands and the `shell` fallback must not be targets"
        );
    }

    #[test]
    fn a_config_redeclaring_a_shipped_tool_is_still_required() {
        // There is no per-command downgrade: a config that copies `claude` to
        // change `args` declares it like any other tool, so a missing `claude`
        // is fatal. (The old rule reached the same verdict on the default image
        // by keying severity on the command; the new rule reaches it because
        // every declared tool is required.)
        let targets = verification_targets(&catalog_from(
            "[[tools]]\nname = \"claude\"\ncommand = \"claude\"\nargs = [\"--x\"]\n",
        ));
        let claude = targets
            .iter()
            .find(|target| target.command == "claude")
            .expect("claude is verified");
        assert_eq!(claude.tools, vec!["claude".to_string()]);
        assert!(
            report(
                &boot_image::ImageLabel::for_tests("the default boot image"),
                claude,
                Some(CommandPresence::Absent),
                not_runnable(),
            )
            .is_err(),
            "a missing redeclared shipped tool must be fatal"
        );
    }

    #[test]
    fn tools_sharing_a_command_dedupe_and_list_every_verb() {
        // Two *declared* tools share `bash`, so there is one target that names
        // every verb. (Neither is named `shell`, so the synthesized fallback
        // also exists — and must not appear among the verbs.)
        let targets = verification_targets(&catalog_from(
            "[[tools]]\nname = \"mysh\"\ncommand = \"bash\"\n\
             [[tools]]\nname = \"othersh\"\ncommand = \"bash\"\n",
        ));
        let bash: Vec<&VerifyTarget> = targets
            .iter()
            .filter(|target| target.command == "bash")
            .collect();
        assert_eq!(bash.len(), 1, "one target per command");
        assert_eq!(
            bash[0].tools,
            vec!["mysh".to_string(), "othersh".to_string()]
        );
    }

    // -- `report` is fatal for every declared target ----------------------

    fn target(tools: &[&str], command: &str) -> VerifyTarget {
        VerifyTarget {
            tools: tools.iter().map(|name| (*name).to_string()).collect(),
            command: command.to_string(),
        }
    }

    /// A `--version` exec the sandbox could not even start (a dead sandbox is
    /// indistinguishable from a spawn failure here — see `report`'s doc).
    fn not_runnable() -> Result<ExecOutput, MicrosandboxError> {
        Err(MicrosandboxError::InvalidConfig("test".to_string()))
    }

    /// Case 1 of the three-case diagnostic: no entry found on the guest
    /// `PATH` (the command is a bare name). The message names the image and
    /// says agent-vm does not install tools, rather than advising a removed
    /// `layer` declaration.
    #[test]
    fn report_bails_for_a_missing_declared_command() {
        let err = report(
            &boot_image::ImageLabel::for_tests("the default boot image"),
            &target(&["codex"], "codex"),
            Some(CommandPresence::Absent),
            not_runnable(),
        )
        .expect_err("a missing declared command must be fatal");
        let rendered = format!("{err:#}");
        assert!(rendered.contains("codex"), "{rendered}");
        assert!(
            rendered.contains("not found on the guest `PATH`"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("not found at the configured path"),
            "a bare name was searched on `PATH`, not tested as a path: {rendered}"
        );
        assert!(
            rendered.contains("the default boot image"),
            "the diagnostic names the image: {rendered}"
        );
        assert!(rendered.contains("does not install tools"), "{rendered}");
        assert!(!rendered.contains("layer"), "{rendered}");
    }

    /// D4: a `command` naming a path is tested directly at that path, so its
    /// absence is a statement about that path alone. The message must name the
    /// configured path and must not claim a `PATH` search the probe never ran
    /// (nor that nothing in the image carries the program).
    #[test]
    fn report_names_the_configured_path_for_a_pathname_command() {
        let err = report(
            &boot_image::ImageLabel::for_tests("example/image:test"),
            &target(&["mytool"], "/opt/private/my-agent"),
            Some(CommandPresence::Absent),
            not_runnable(),
        )
        .expect_err("a pathname command that names nothing is fatal");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("not found at the configured path"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("PATH"),
            "a pathname command is tested directly, never on `PATH`: {rendered}"
        );
    }

    /// The new rule: a missing declared command is fatal on *any* image,
    /// including one the user selected — severity no longer depends on image
    /// provenance. (The old rule only warned here.)
    #[test]
    fn a_missing_declared_command_is_fatal_on_a_user_selected_image() {
        let err = report(
            &boot_image::ImageLabel::for_tests("localhost:5000/e2e:selected"),
            &target(&["mytool"], "my-agent"),
            Some(CommandPresence::Absent),
            not_runnable(),
        )
        .expect_err("a declared command is required on any image");
        let rendered = format!("{err:#}");
        assert!(rendered.contains("my-agent"), "{rendered}");
        assert!(
            rendered.contains("not found on the guest `PATH`"),
            "{rendered}"
        );
        assert!(
            rendered.contains("localhost:5000/e2e:selected"),
            "the diagnostic names the selected image: {rendered}"
        );
        assert!(rendered.contains("does not install tools"), "{rendered}");
    }

    /// Case 2 of the three-case diagnostic: present but not executable. The
    /// message must not claim the command is missing, nor that a binary is
    /// broken — the file is there, only its mode is wrong.
    #[test]
    fn report_bails_for_a_not_executable_declared_command() {
        let err = report(
            &boot_image::ImageLabel::for_tests("example/image:test"),
            &target(&["mytool"], "my-agent"),
            Some(CommandPresence::NotExecutable),
            not_runnable(),
        )
        .expect_err("a non-executable declared command must be fatal");
        let rendered = format!("{err:#}");
        assert!(rendered.contains("not executable"), "{rendered}");
        assert!(
            !rendered.contains("not found on the guest `PATH`"),
            "{rendered}"
        );
        assert!(!rendered.contains("broken"), "{rendered}");
        assert!(
            rendered.contains("not a runnable program"),
            "the wording is location-agnostic, true for a PATH lookup and a \
             pathname command alike: {rendered}"
        );
        assert!(
            !rendered.contains("PATH"),
            "must not claim PATH membership the pathname probe never established: {rendered}"
        );
    }

    /// Case 3 of the three-case diagnostic: present and executable, but
    /// `--version` failed. The message says "broken" rather than "not found".
    #[test]
    fn report_bails_for_a_broken_declared_command() {
        let err = report(
            &boot_image::ImageLabel::for_tests("example/image:test"),
            &target(&["claude"], "claude"),
            Some(CommandPresence::Executable),
            not_runnable(),
        )
        .expect_err("a broken declared command must be fatal");
        let rendered = format!("{err:#}");
        assert!(rendered.contains("broken"), "{rendered}");
        assert!(
            !rendered.contains("not found on the guest `PATH`"),
            "{rendered}"
        );
    }

    /// A probe that could not run (a dead sandbox) is a transport failure, not
    /// a statement that the command is missing or not executable.
    #[test]
    fn report_renders_a_transport_failure_when_presence_is_unknown() {
        let err = report(
            &boot_image::ImageLabel::for_tests("example/image:test"),
            &target(&["claude"], "claude"),
            None,
            not_runnable(),
        )
        .expect_err("an unproven declared command must be fatal");
        let rendered = format!("{err:#}");
        assert!(rendered.contains("could not start"), "{rendered}");
        assert!(
            !rendered.contains("not found on the guest `PATH`"),
            "{rendered}"
        );
        assert!(!rendered.contains("not executable"), "{rendered}");
    }

    // -- the presence probe: token mapping and the shell script -----------

    #[test]
    fn classify_command_presence_maps_the_probe_tokens() {
        assert_eq!(
            classify_command_presence("executable"),
            CommandPresence::Executable
        );
        assert_eq!(
            classify_command_presence("not-executable"),
            CommandPresence::NotExecutable
        );
        assert_eq!(classify_command_presence("absent"), CommandPresence::Absent);
        // Only a literal token establishes a state: empty or unknown output is
        // Unknown, never Absent (an image-provided `sh` that prints extra output
        // must not make an installed tool look missing).
        assert_eq!(
            classify_command_presence("executable\n"),
            CommandPresence::Executable
        );
        assert_eq!(classify_command_presence(""), CommandPresence::Unknown);
        assert_eq!(classify_command_presence("junk"), CommandPresence::Unknown);
        assert_eq!(
            classify_command_presence("absent but with extra output"),
            CommandPresence::Unknown
        );
    }

    /// Run the real [`PROBE_COMMAND_PRESENCE`] script under the host `/bin/sh`
    /// with a verbatim `PATH` and working directory, returning the raw token and
    /// its classification. The probe is plain POSIX sh that the guest agentd
    /// runs the same way, so this exercises the actual scan without a VM.
    fn run_presence_probe(
        cwd: &std::path::Path,
        path: &str,
        name: &str,
    ) -> (String, CommandPresence) {
        let out = std::process::Command::new("/bin/sh")
            .args(["-c", PROBE_COMMAND_PRESENCE, "sh", name])
            .env("PATH", path)
            .current_dir(cwd)
            .output()
            .expect("run the presence probe");
        assert!(out.status.success(), "probe failed: {out:?}");
        let stdout = String::from_utf8(out.stdout).expect("probe stdout is UTF-8");
        (
            stdout.trim().to_string(),
            classify_command_presence(&stdout),
        )
    }

    /// Assert the raw token and the classification independently, so a mapping
    /// bug is never reported as a script bug or vice versa.
    fn assert_probe(
        cwd: &std::path::Path,
        path: &str,
        name: &str,
        want_token: &str,
        want: CommandPresence,
    ) {
        let (token, got) = run_presence_probe(cwd, path, name);
        assert_eq!(
            token, want_token,
            "raw probe token for {name} on PATH={path}"
        );
        assert_eq!(got, want, "classification for {name} on PATH={path}");
    }

    fn write_mode(path: &std::path::Path, mode: u32, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn the_probe_script_classifies_absent_not_executable_and_executable() {
        let dir = tempfile::tempdir().unwrap();
        write_mode(&dir.path().join("exe-tool"), 0o755, "#!/bin/sh\nexit 0\n");
        write_mode(&dir.path().join("noexec-tool"), 0o644, "not a program\n");
        let path = dir.path().to_str().unwrap();

        assert_probe(
            dir.path(),
            path,
            "exe-tool",
            "executable",
            CommandPresence::Executable,
        );
        assert_probe(
            dir.path(),
            path,
            "noexec-tool",
            "not-executable",
            CommandPresence::NotExecutable,
        );
        assert_probe(
            dir.path(),
            path,
            "missing-tool",
            "absent",
            CommandPresence::Absent,
        );
    }

    /// F2: shell-equivalence of the PATH split. A trailing (or interior) empty
    /// element means the current directory — word splitting on an unquoted
    /// `$PATH` would drop the trailing one — and a metacharacter must not be
    /// pathname-expanded. Both reproduced the reviewer's failures before the
    /// fix.
    #[test]
    fn the_probe_preserves_empty_path_elements_and_disables_globbing() {
        let cwd = tempfile::tempdir().unwrap();
        write_mode(&cwd.path().join("here-tool"), 0o755, "#!/bin/sh\nexit 0\n");

        // Trailing empty element -> current directory.
        assert_probe(
            cwd.path(),
            "/nonexistent-e2e-path:",
            "here-tool",
            "executable",
            CommandPresence::Executable,
        );
        // Interior empty element -> current directory.
        assert_probe(
            cwd.path(),
            ":/also-nonexistent-e2e-path",
            "here-tool",
            "executable",
            CommandPresence::Executable,
        );
        // A glob metacharacter must not expand: `/bi?` must not match `/bin`.
        // `ls` exists under the literal `/bin`, so a globbing probe would report
        // `executable` where a direct exec finds nothing.
        assert_probe(cwd.path(), "/bi?", "ls", "absent", CommandPresence::Absent);
    }

    /// F3: a `command` containing a slash is a path, not a PATH lookup, and a
    /// directory is never a runnable command.
    #[test]
    fn the_probe_classifies_pathname_commands_and_directories() {
        let dir = tempfile::tempdir().unwrap();
        let abs = dir.path().join("abs-tool");
        write_mode(&abs, 0o755, "#!/bin/sh\nexit 0\n");
        let abs = abs.to_str().unwrap();
        let subdir = dir.path().join("dir-tool");
        std::fs::create_dir(&subdir).unwrap();
        let subdir = subdir.to_str().unwrap();
        // The PATH is irrelevant for a pathname command; pass an empty one.
        let nowhere = "";

        assert_probe(
            dir.path(),
            nowhere,
            abs,
            "executable",
            CommandPresence::Executable,
        );
        assert_probe(
            dir.path(),
            nowhere,
            "/no/such/e2e-path-command",
            "absent",
            CommandPresence::Absent,
        );
        // A directory named on PATH is not a runnable program.
        assert_probe(
            dir.path(),
            dir.path().to_str().unwrap(),
            "dir-tool",
            "not-executable",
            CommandPresence::NotExecutable,
        );
        // ... nor is a directory named as a path.
        assert_probe(
            dir.path(),
            nowhere,
            subdir,
            "not-executable",
            CommandPresence::NotExecutable,
        );
    }

    /// F4: a probe that ran but printed no literal token is Unknown, not Absent,
    /// and `report` must not claim such a command is missing.
    #[test]
    fn report_does_not_claim_missing_when_presence_is_unknown() {
        let err = report(
            &boot_image::ImageLabel::for_tests("example/image:test"),
            &target(&["mytool"], "my-agent"),
            Some(CommandPresence::Unknown),
            not_runnable(),
        )
        .expect_err("an unproven declared command must be fatal");
        let rendered = format!("{err:#}");
        assert!(rendered.contains("could not start"), "{rendered}");
        assert!(
            !rendered.contains("not found on the guest `PATH`"),
            "{rendered}"
        );
        assert!(!rendered.contains("not executable"), "{rendered}");
    }
}
