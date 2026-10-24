//! `agent-vm <agent> [args...]` — boot a per-project sandbox and attach to
//! the chosen agent (or a shell).
//!
use std::{
    collections::BTreeSet,
    env,
    io::IsTerminal as _,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use microsandbox::{Sandbox, sandbox::PullPolicy};

use crate::boot_image::{self, ImageArgs};
use crate::config::{self, ConfiguredImages, Tool};
use crate::credential_provider;
use crate::credential_resolver::{CredentialPreflight, MissingCredentialPolicy};
use crate::image_contract;
use crate::launch_target::{LaunchTarget, ProgramGuard};
use crate::mount;
use crate::protected_host_files::CoreHostSource;
use crate::session::ProjectSession;
use crate::user;

/// Environment variables agent-vm injects into *every* guest, regardless of
/// agent or project. Listed in one place so the set is discoverable and
/// guard-testable.
///
/// - `IS_SANDBOX=1`: Claude Code refuses to run as root with
///   `--dangerously-skip-permissions` unless this is set. The microVM is our
///   security boundary, so the in-guest CLI's extra guard is redundant; same
///   var the original Bash agent-vm used.
/// - `LANG=C.UTF-8`: the base image ships with no locale (`LANG`/`LC_*`
///   empty → C/POSIX). That breaks non-ASCII paths two ways: bash/readline
///   draws a Cyrillic cwd as `M-P…` meta-escapes instead of glyphs, and
///   locale-driven filesystem encodings default to ASCII so Python/Node/
///   ripgrep mis-handle or error on a non-ASCII path even when it mounted
///   fine. C.UTF-8 is always present in glibc (no `locale-gen`), ASCII-
///   sorting + English-messages but UTF-8-aware — the right neutral sandbox
///   default. We don't propagate the host's `$LANG` (that locale may not
///   exist in the guest image and would silently fall back to C). Also
///   pinned in the independent image repo's `images/Dockerfile` for non-agent-vm uses of the image.
const GUEST_ALWAYS_ENV: &[(&str, &str)] = &[("IS_SANDBOX", "1"), ("LANG", "C.UTF-8")];

/// The launcher's baked fallback guest `PATH`. It is an **exec-only**
/// fallback for when the acquired image's own OCI config declares no `PATH`
/// at all — never a substitute for the image PATH on a cold first
/// acquisition. The real effective PATH is read back from the created
/// sandbox's resolved config ([`resolved_exec_path`]); a cached-but-unpulled
/// image therefore keeps its OCI PATH instead of silently dropping to this
/// literal (#258).
///
/// Deliberately names no tool prefix: which tool prefixes exist is a property
/// of the boot image's OCI config. The image's own value is the correct floor.
const FALLBACK_GUEST_PATH: &str = "/usr/local/bin:/usr/bin:/usr/sbin:/bin";

/// The effective `PATH` for the launch's `bash` spawn, read from the created
/// sandbox's resolved config (the acquired image's OCI `PATH`). The **last** `PATH` entry wins, matching guest env's
/// last-wins semantics; an explicitly empty value is preserved (an image that
/// truly sets `PATH=` means it), and only *absence* falls back to
/// [`FALLBACK_GUEST_PATH`].
fn resolved_exec_path(config: &microsandbox::sandbox::SandboxConfig) -> String {
    config
        .spec
        .env
        .iter()
        .rev()
        .find(|entry| entry.key == "PATH")
        .map(|entry| entry.value.clone())
        .unwrap_or_else(|| FALLBACK_GUEST_PATH.to_string())
}

/// The booted image's own OCI config `env` entries, or `None` when the
/// metadata could not be read (best-effort, exactly like the PATH read above).
/// The `env` vector is the "image-owned ENV" contract this check pins.
async fn image_config_env(image: &str) -> Option<Vec<String>> {
    let cache_dir = crate::msb_install::effective_cache_dir().ok()?;
    let cache = microsandbox_image::GlobalCache::new_async(&cache_dir)
        .await
        .ok()?;
    let reference = image.parse::<microsandbox_image::Reference>().ok()?;
    match cache.read_image_metadata_async(&reference).await {
        Ok(Some(metadata)) => Some(metadata.config.env),
        _ => None,
    }
}

/// Translate the runtime's closed header-credential refusals into an
/// actionable message (#161).
///
/// Adds **no** reference, keychain text or service name: the runtime's error is
/// index-and-fixed-label only, and agent-vm must not re-widen it. The realistic
/// cause of a capability failure is a stale locally built `msb` that predates
/// the feature, which is exactly what the message names.
fn translate_create_error(error: anyhow::Error) -> anyhow::Error {
    let hint: Option<String> = error.chain().find_map(|cause| {
        let microsandbox::MicrosandboxError::HeaderCredential(inner) = cause.downcast_ref()? else {
            return None;
        };
        Some(match inner {
            microsandbox::HeaderCredentialError::RuntimeCapabilityMissing
            | microsandbox::HeaderCredentialError::RuntimeProbeFailed => {
                "the installed `msb` does \
                 not support origin-scoped header credentials (it does not report \
                 `header-credential-launch-v1`), so this credential-bearing launch was refused \
                 before any sandbox record was written. Rebuild `msb` from this checkout's \
                 `vendor/microsandbox` and make sure `MSB_PATH` points at it"
                    .to_owned()
            }
            // Captured env bytes cannot change between phases; this hint is for keychain reads.
            microsandbox::HeaderCredentialError::ResolveFailed { .. } => "a configured credential \
                 could not be read at spawn time - the keychain may have been locked, another \
                 agent-vm process may have held the secret inventory lock, or its item \
                 changed, between the pre-boot check and the spawn. Re-run the launch; if it \
                 repeats, check `agent-vm secret ls`"
                .to_owned(),
            microsandbox::HeaderCredentialError::UnsupportedPlatform
            | microsandbox::HeaderCredentialError::UnsupportedBackend => "this platform or \
                 backend does not support origin-scoped header credentials; agent-vm supports \
                 Linux with KVM and Apple Silicon hosts"
                .to_owned(),
            microsandbox::HeaderCredentialError::MissingResolver { .. }
            | microsandbox::HeaderCredentialError::ResolutionMismatch => "an internal agent-vm \
                 error: the runtime refused a credential launch agent-vm had already authorized. \
                 Please report it"
                .to_owned(),
            microsandbox::HeaderCredentialError::RestartRequiresResolver => "a credential-bearing \
                 sandbox cannot be restarted by name; agent-vm always creates a fresh sandbox, so \
                 this indicates an internal error. Please report it"
                .to_owned(),
        })
    });
    match hint {
        Some(hint) => anyhow::anyhow!("{hint}"),
        None => error,
    }
}

/// stderr sink for `launch()`'s `==> …` progress notices.
///
/// Exists because `eprintln` panics from inside `std::io::_eprint`
/// ("failed printing to stderr") when the write fails — a real outcome for
/// `agent-vm … 2>&1 | head` (EPIPE) or a full disk — aborting the launcher
/// with exit 101 and no context instead of reaching the error boundary in
/// `main()` (issue #70). Generic over the sink so the failure path is
/// testable without a broken pipe, following `network.rs`'s
/// `emit_launch_notices_to` precedent.
struct LaunchNotices<W> {
    sink: W,
}

impl LaunchNotices<std::io::Stderr> {
    /// The production sink is the `Stderr` *handle*, not a `.lock()` guard:
    /// `StderrLock<'a>` borrows for `'a` and is `!Send`, so it can neither
    /// be a long-lived field here nor cross into the spawned update-banner
    /// task. (Deadlock is not the concern — std's stderr lock is
    /// reentrant-per-thread.) Each `emit` is a single `write_all`, which
    /// takes the lock once, so nothing is lost by not holding it.
    fn to_stderr() -> Self {
        Self::new(std::io::stderr())
    }
}

impl<W: std::io::Write> LaunchNotices<W> {
    fn new(sink: W) -> Self {
        Self { sink }
    }

    /// Deliver one notice line.
    ///
    /// One `write_all` of the fully rendered line rather than `writeln!`,
    /// which writes once per format-string fragment and could deliver half a
    /// notice before failing. No flush: std's `Stderr` is unbuffered, so
    /// there is nothing to flush and neither `eprintln` nor
    /// `emit_launch_notices_to` does — adding one would change
    /// success-path behavior.
    fn emit(&mut self, message: impl std::fmt::Display) -> Result<()> {
        let mut line = message.to_string();
        line.push('\n');
        self.sink
            .write_all(line.as_bytes())
            .with_context(|| format!("writing the launch notice {:?}", line.trim_end()))
    }
}

/// `==> agent-vm-<hash>-<pid> in /home/dev/proj (state: /…/state/<hash>)`
fn launch_banner(session: &ProjectSession) -> String {
    format!(
        "==> {} in {} (state: {})",
        session.sandbox_name,
        session.project_dir.display(),
        session.state_dir.display(),
    )
}

/// `==> GitHub repo scope (2): a/b, c/d` or
/// `==> GitHub repo scope: <none> (no api.github.com access)`
fn repo_scope_notice(allowed: &[String]) -> String {
    if allowed.is_empty() {
        "==> GitHub repo scope: <none> (no api.github.com access)".to_string()
    } else {
        format!(
            "==> GitHub repo scope ({}): {}",
            allowed.len(),
            allowed.join(", "),
        )
    }
}

/// `==> Agent credentials: claude, codex, gh` /
/// `==> Agent credentials: <none> (no host logins found)`
///
/// Names the providers whose host credential was captured into
/// `<hash>.secrets/` and registered for proxy substitution. Without this
/// the only signal that a capture failed is a `tracing::warn!` buried in
/// the boot output, and the resulting symptom — an in-VM agent that comes
/// up signed out — points nowhere near the host login that fixes it.
/// Order is fixed (not `CredsState` field order) so the line is stable
/// across launches. OpenCode's static provider keys are summarised as a
/// count because there are seven of them.
fn creds_notice(creds: &crate::secrets::CredsState) -> String {
    let mut found: Vec<String> = Vec::new();
    for (present, label) in [
        (creds.anthropic_token_file.is_some(), "claude"),
        (creds.openai_token_file.is_some(), "codex"),
        (
            creds.opencode_openai_access_token_file.is_some(),
            "opencode",
        ),
        (creds.gh_token_file.is_some(), "gh"),
        (creds.copilot_token_file.is_some(), "copilot"),
    ] {
        if present {
            found.push(label.to_string());
        }
    }
    if !creds.opencode_api_token_files.is_empty() {
        found.push(format!(
            "opencode-api x{}",
            creds.opencode_api_token_files.len()
        ));
    }
    if found.is_empty() {
        "==> Agent credentials: <none> (no host logins found)".to_string()
    } else {
        format!("==> Agent credentials: {}", found.join(", "))
    }
}

/// `==> Git author identity: Ada <ada@x> (gh:ada)` /
/// `==> Git author identity: Ada <ada@x>` /
/// `==> Git author identity: <none> (gh not logged in and …)`
fn git_identity_notice(identity: Option<&crate::secrets::HostGitIdentity>) -> String {
    match identity {
        Some(id) => format!(
            "==> Git author identity: {} <{}>{}",
            id.name,
            id.email,
            id.gh_login
                .as_deref()
                .map(|l| format!(" (gh:{l})"))
                .unwrap_or_default(),
        ),
        None => "==> Git author identity: <none> (gh not logged in and no host gitconfig \
                  user.name/email; in-VM `git commit` will refuse until you set one)"
            .to_string(),
    }
}

fn guest_path_is_safe(project: &Path) -> bool {
    let s = match project.to_str() {
        Some(s) => s,
        None => return false,
    };
    !crate::guest_paths::TMPFS_GUEST_PREFIXES
        .iter()
        .any(|p| s == *p || s.starts_with(&format!("{p}/")))
}

/// Whether `s` is safe to place on the guest **kernel command line**.
///
/// libkrun packs the guest workdir (`KRUN_WORKDIR=<path>`) into the kernel
/// command line, which its `Cmdline` builder validates as printable ASCII
/// only (`valid_char` accepts `' '..='~'`) and `.unwrap()`s — a non-ASCII
/// byte panics the VMM (`InvalidAscii`) before boot, and a space is
/// mis-tokenized by the guest kernel (`/proc/cmdline` splits on whitespace).
/// So a path that isn't printable, non-space ASCII (`is_ascii_graphic`,
/// `0x21..=0x7e`) can't be the `KRUN_WORKDIR` value.
///
/// Note the *mount* specs no longer ride the cmdline — they travel via the
/// boot-params side channel (see [`microsandbox`]'s runtime), so the project
/// itself is still mirrored at its real (possibly Cyrillic) path. This
/// predicate only governs the `KRUN_WORKDIR` placeholder: when it fails we
/// hand libkrun `/` and pin the agent's real cwd via the exec request
/// instead (see [`launch`]).
fn guest_path_is_cmdline_safe(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_graphic())
}

/// Whether `s` can be carried into the guest as a mount point at all.
///
/// Mount specs travel via the boot-params side channel, framed as
/// `KEY\tVALUE\n` lines. That transport is byte-transparent for everything
/// except a control character — a TAB or newline in the path would break
/// the framing, and other control bytes have no business in a mount point.
/// Such a path can't be mirrored and falls back to `/workspace`.
pub(crate) fn guest_path_is_mountable(s: &str) -> bool {
    !s.chars().any(|c| c.is_control())
}

/// Decide the in-guest path to mirror the project at, plus a one-line
/// reason when we had to fall back to `/workspace` (for the launch
/// notice). The host bind always targets the real `project_dir`
/// regardless; only the *guest-visible* path changes.
///
/// A non-ASCII or whitespace path is mirrored at its **real** location:
/// the mount spec rides the boot-params side channel (not the cmdline),
/// the mount-point dir is baked byte-for-byte into the rootfs, and the
/// agent's cwd is delivered over the byte-safe exec channel. Only two
/// things still force `/workspace`: a path under a guest tmpfs mount (see
/// [`guest_path_is_safe`]) would be wiped at boot, and a path with control
/// characters (see [`guest_path_is_mountable`]) can't be framed for the
/// side channel.
fn resolve_project_guest_path(
    project_dir: &Path,
    host_path: &str,
) -> (String, Option<&'static str>) {
    if !guest_path_is_safe(project_dir) {
        ("/workspace".to_string(), Some("is under a tmpfs mount"))
    } else if !guest_path_is_mountable(host_path) {
        (
            "/workspace".to_string(),
            Some("contains control characters that can't be carried into the guest"),
        )
    } else {
        (host_path.to_string(), None)
    }
}

/// Absolute directories that must exist inside the guest rootfs before
/// microsandbox can mount the project at its host path. Returns paths from
/// shallowest to deepest, e.g. for `/home/boger/work/foo`:
/// `["/home", "/home/boger", "/home/boger/work", "/home/boger/work/foo"]`.
/// The leaf is included because microsandbox validates `workdir` against the
/// rootfs at create time, *before* the bind mount is materialized — without
/// the empty mount point dir it errors with "workdir does not exist in
/// guest". The bind mount then overlays this empty dir with the host's
/// project contents at boot.
fn mkdir_chain(project: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut acc = PathBuf::new();
    for c in project.components() {
        acc.push(c.as_os_str());
        let s = acc.to_string_lossy().to_string();
        if s != "/" && !s.is_empty() {
            out.push(s);
        }
    }
    out
}

/// The direct runner's fixed usage lines: both spellings, and never rendered
/// argv. Used for `help run` and for every direct usage error (status 2).
pub(crate) const DIRECT_USAGE: &str = "\
agent-vm [launch options] run PROGRAM [ARG]...
       agent-vm [launch options] -- PROGRAM [ARG]...";

/// Footer under `agent-vm help run`. The program is user-supplied argv, so this
/// text names no specific executable.
pub(crate) const DIRECT_AFTER_HELP: &str = "\
Examples:
  agent-vm run make test               run the guest make with these arguments
  agent-vm --memory 4 run bash -c 'echo ok'
  agent-vm -- make test                the top-level `--` spelling is equivalent
  agent-vm run printf '%s\\n' '$HOME'   literal argv: prints $HOME, no expansion
  agent-vm run bash -c 'echo $HOME'    shell syntax needs an explicit shell

Launch options go before `run` or the top-level `--`. Every argument after the
program is literal: no expansion, splitting, globbing, deduplication, tool
default arguments, tool environment or catalog provisioning. The program may be a
bare name resolved on the guest PATH or an explicit path. `--help` and `--` after
it belong to it, and `run` itself takes no options.

Statuses: 127 when the executable is absent from the effective guest PATH, 126
when it is present but not executable (or is a directory named by path), 125 for
an ordinary direct launcher failure, otherwise the program's own status. A bare
name that resolves to a directory counts as not found (127).

Slice 1: no streamed stdin, terminal overrides or signal forwarding yet; see
USAGE.md (issues #399-#401).";

/// Fixed text for a scrubbed parse error on a known-direct route: no supplied
/// value can be among it, and the direct usage line replaces administrative
/// image-import wording.
pub(crate) const DIRECT_SCRUB_ERROR: &str = "\
`agent-vm run` could not parse its arguments. The arguments are not shown, \
because a value among them may be secret. Supported forms:
  agent-vm [launch options] run PROGRAM [ARG]...
  agent-vm [launch options] -- PROGRAM [ARG]...";

/// Fixed text for a scrubbed parse error on a known-direct route that the
/// `secret` predicate selected: value-free like [`DIRECT_SCRUB_ERROR`], but it
/// must not explain the administrative `agent-vm secret …` forms. Those are not
/// what a guest command vector containing the token `secret` could have meant.
pub(crate) const DIRECT_SECRET_SCRUB_ERROR: &str = "\
`agent-vm run` could not parse its arguments. The arguments are not shown, \
because one of them is `secret` and a secret value may have been among them. \
Launch options go before `run` or the top-level `--`, and everything after the \
program is literal guest argv. Supported forms:
  agent-vm [launch options] run PROGRAM [ARG]...
  agent-vm [launch options] -- PROGRAM [ARG]...";

/// Footer under `agent-vm help <tool>`. Shared by every tool verb, so it names no tool.
pub(crate) const LAUNCH_AFTER_HELP: &str = "\
Examples:
  agent-vm <tool>                    launch in the current project
  agent-vm -p 8080:3000 <tool>        publish guest :3000 to host 127.0.0.1:8080
  agent-vm <tool> --some-flag         forward args to the tool

Launch options go before the tool (see `agent-vm --help`). Every argument after
the tool is forwarded to it verbatim, including --help and --.";

/// Full launch-option footer on the top-level command; no catalog-specific names.
pub(crate) const LAUNCH_OPTIONS_LONG_HELP: &str = "\
Examples:
  agent-vm <tool>                                  launch in the current project
  agent-vm <tool> --model opus --resume            forward args to the tool
  agent-vm run make test                           run a guest executable directly
  agent-vm -- make test                            same program, top-level `--` form
  agent-vm shell <command>                         run one command, then exit
  agent-vm --memory 8 --cpus 4 <tool>              a bigger sandbox
  agent-vm --mount ~/ref:ro <tool>                 read-only extra mount
  agent-vm --mount /etc/hosts:/host-hosts:ro <tool>
                                                   read-only single-file bind
  agent-vm --mount ~/skills:ro:follow-links <tool>
                                                   follow symlinks in a skills dir
  agent-vm --mount ~/config:/config:fork:exclude=credentials.json <tool>
                                                   seed an independent writable copy
  agent-vm --repo owner/other-repo <tool>          widen the GitHub allow-list

Fork mounts:
  Writable binds (the project dir included) may not contain ~/.config/agent-vm; launch from a project directory, not $HOME.
  `:fork` copies its source directory once into project-scoped persistent state; later launches
  reuse that copy, so source and fork changes never synchronize in either direction.
  `:fork:follow-links` materializes symlink targets in the copy; without it, symlinks are preserved.
  Repeat `:exclude=REL` to omit paths while seeding a fork; exclusions are fork-only, and a live
  bind cannot hide nested paths. A regular file cannot be forked; bind it read-only with `:ro`
  (a bare or `:rw` file mount is rejected). Forks use disk space for the full initial copy in the
  host-managed project mount store beside `/agent-vm-state`. To reset/reseed, stop users of the
  fork, remove the exact directory printed at launch, then launch the same declaration again.

Networking (deny-by-default; flags compose):
  --publish                host  → guest     open an inbound port to a guest service
  --auto-publish           guest → host      mirror guest listeners onto host loopback
  --allow-internet-egress  guest → internet  public internet + DNS
  --allow-egress           guest → IP/host   reach one IP/CIDR or TLS hostname [proto/port]
  --allow-lan              guest → LAN       reach the whole private range
  --allow-host             guest → host      reach the host's 127.0.0.1 services
  persisted grants: [network] in ~/.config/agent-vm/config.toml
  Flags override persisted booleans and add allowances; launches never save changes.

Environment:
  AGENT_VM_MEMORY_GIB / AGENT_VM_CPUS   same as --memory / --cpus
  AGENT_VM_IMAGE_TAG                    same as --image (outranks configured images)
  AGENT_VM_ROOT                         same as --root (1|true|yes|on)
  AGENT_VM_INSECURE_REGISTRY            allow plain-HTTP registry pulls (1|true|yes|on)
  AGENT_VM_STATE_DIR                    override the per-project state dir
  AGENT_VM_PROFILE                      print per-phase boot timings
  AGENT_VM_DEBUG_CONFIG                 dump the SandboxConfig JSON before boot
  AGENT_VM_NO_CHROME_MCP                disable Chrome MCP auto-configuration for Chrome-capable images
  RUST_LOG                              tracing filter (e.g. agent_vm=debug)";

/// The **launch options**, flattened into the top-level [`crate::cli`] command
/// and written before the tool verb.
#[derive(ClapArgs)]
pub struct Args {
    /// Sandbox memory, in GiB.
    #[arg(
        long,
        env = "AGENT_VM_MEMORY_GIB",
        default_value_t = 2,
        value_name = "GIB",
        help_heading = "Sandbox resources"
    )]
    pub(crate) memory: u32,

    /// vCPU count for the sandbox.
    #[arg(
        long,
        env = "AGENT_VM_CPUS",
        default_value_t = 2,
        value_name = "N",
        help_heading = "Sandbox resources"
    )]
    cpus: u8,

    /// Don't inject host gh/git credentials into the guest.
    ///
    /// With this set, no gh auth flows through the proxy and the guest
    /// agent can't `git push` / `gh pr create` etc. Useful for one-off
    /// throwaway sessions on a repo you don't trust the agent with.
    #[arg(
        long = "no-git",
        default_value_t = false,
        help_heading = "GitHub access"
    )]
    no_git: bool,

    /// Add a repo to the GitHub allow-list (repeatable).
    ///
    /// The cwd's `git remote -v` GitHub entries are always included;
    /// use this to widen the allow-list for cross-repo work.
    #[arg(
        long = "repo",
        value_name = "OWNER/REPO",
        help_heading = "GitHub access"
    )]
    repo: Vec<String>,

    /// Launch even when a requested YAML credential is missing or unreadable.
    ///
    /// Warns and continues for a `credentials = [...]` name that has no
    /// authorization in `~/.config/agent-vm/credentials.yaml`, and for an
    /// authorized `required: true` credential whose value cannot be read. The
    /// guest gets neither the credential nor a fallback, so the in-guest tool may
    /// still fail its own sign-in.
    ///
    /// It does not cover a compiled-in credential provider whose own host
    /// credential is missing - that still refuses the launch (`agent-vm doctor`
    /// lists the providers). Nor does it bypass a malformed or unsupported
    /// `credentials.yaml`, a rejected stored value, a guest-variable conflict, or
    /// any other configuration or security error. There is deliberately no
    /// environment variable: skipping a credential is a per-launch decision the
    /// user makes at the command line.
    #[arg(
        long = "allow-missing-credentials",
        default_value_t = false,
        help_heading = "Credentials"
    )]
    allow_missing_credentials: bool,

    /// Bind an extra host path into the guest, or seed a persistent fork (repeatable).
    ///
    /// Format `HOST[:GUEST][:MODE]...`; `GUEST` defaults to `HOST` (mirror at the same absolute
    /// path). Valid mode tokens are `ro`, `rw`, `fork`, `follow-links`, and `exclude=REL`; conflicting
    /// tokens like `ro`+`rw` or `rw`+`follow-links` are errors. `GUEST`, if given, must be an absolute
    /// path (start with `/`); a trailing token that isn't a path is parsed as a mode keyword, e.g.
    /// `--mount ~/ref:ro`. Directory binds default to writable (`:rw`); a regular file requires an
    /// explicit `:ro` — a bare or `:rw` file mount is rejected, and a file cannot be `:fork`ed.
    ///
    /// `:fork` copies a directory once into project-scoped persistent state. Later launches reuse
    /// that stored copy without synchronizing either direction: source changes do not reach the
    /// fork, and guest changes do not reach the source. Forks consume disk space for the full
    /// initial copy in the host-managed project mount store beside `/agent-vm-state`. To reset or
    /// reseed one, stop its users, remove the exact fork directory printed at launch, then relaunch
    /// the same declaration. `:fork` conflicts with `:ro` and `:rw`.
    ///
    /// Repeat `:exclude=REL` to omit paths while seeding a fork. Exclusions are fork-only: a live
    /// bind cannot hide nested paths, so `:exclude` on any non-fork mount is a parse error. Omitted
    /// paths are absent only from the seed; the guest can create them later. Example: `--mount
    /// ~/config:/config:fork:exclude=credentials.json`.
    ///
    /// For `:fork`, symlinks are preserved by default. `:fork:follow-links` instead materializes
    /// their targets in the project-owned copy, never as a continuing live bind.
    ///
    /// `:follow-links` additionally walks `HOST` on the host side and, for
    /// every symlink it transitively contains that resolves to a directory,
    /// bind-mounts that *real* directory into the guest at its own real
    /// absolute host path. This is what makes symlinks whose target lies
    /// outside `HOST` (e.g. a skills directory full of `foo -> /elsewhere`
    /// links) resolve correctly in the guest — an ordinary bind mount only
    /// exposes the `HOST` subtree, so the guest's `readlink()` would name a
    /// path nothing is mounted at. When a link's raw target text reaches
    /// that directory *through a symlinked parent* (e.g.
    /// `skills/x -> ~/conf/.agents/skills/x` where `.agents/skills` is
    /// itself a link to `../skills`), the guest's `readlink()` names the
    /// pre-resolution path, so the same real directory is bound a second
    /// time at that literal path too. `follow-links` implies `:ro` (bare
    /// `--mount ~/ref:follow-links` behaves as `ro`); combining it with
    /// `:rw` is a parse error. A resolved target outside your `$HOME` is a
    /// hard error; a symlink to a file, or a dangling symlink, is skipped
    /// with a warning. Example: `--mount ~/.agents/skills:ro:follow-links`.
    ///
    /// Each `--mount` (including each auto-discovered follow-links target)
    /// consumes one virtio-fs device shared with rootfs, network, vsock,
    /// console, and `--volume` disks. A `follow-links` symlink can cost two
    /// — the target's own path plus the literal path described above — so
    /// budget up to 2x the symlink count, not 1x. Capacity depends on the
    /// host interrupt model and runtime; do not treat a measurement from
    /// one platform as a portable mount limit.
    #[arg(
        long = "mount",
        value_name = "HOST[:GUEST][:MODE]...",
        help_heading = "Mounts & ports"
    )]
    pub(crate) mount: Vec<String>,

    #[command(flatten)]
    network: crate::network::Args,

    /// The image this session boots. See "Selecting the boot image" in
    /// USAGE.md for the full precedence (flag/env > user config > project
    /// config > default).
    #[command(flatten)]
    pub(crate) image: ImageArgs,

    /// Run the guest as root (uid 0) instead of the default host user.
    ///
    /// Historical behavior: `HOME=/root`, the Chrome MCP runs via `sudo -u
    /// chrome`, and docker-in-VM works (dockerd needs root — non-root has
    /// no way to run it). The default (non-root) mode runs the in-guest
    /// agent as the invoking host user for defense-in-depth on top of the
    /// microVM boundary; matching the host uid is also required to keep
    /// write access to the project/state bind mounts (see CONTEXT.md
    /// "Guest user"). Can also be enabled persistently with a truthy
    /// `AGENT_VM_ROOT` (1|true|yes|on).
    #[arg(long = "root", default_value_t = false, help_heading = "Guest user")]
    pub(crate) root: bool,
}

/// Lower the selected target once, then retain the shared setup and exec path.
pub(crate) async fn launch(
    target: LaunchTarget,
    images: &ConfiguredImages,
    user_network: Option<&crate::user_network::UserNetwork>,
    credential_preflight: CredentialPreflight,
    args: Args,
) -> Result<i32> {
    let (grant, invocation) = target.into_parts();
    // The output policy belongs to the target, not to the sink: a direct launch
    // answers a broken stdout/stderr pipe as its own failure (#398), while a
    // tool/shell launch keeps the legacy best-effort sink so its status cannot
    // change (see `forward_stream_bytes`).
    let output_policy = match invocation.guard() {
        ProgramGuard::Direct => OutputErrorPolicy::DirectChecked,
        ProgramGuard::ImageContract => OutputErrorPolicy::LegacyBestEffort,
    };
    let provisioned = grant.provisioned();
    // The one image selection for this session — a property of the session,
    // not of the launched tool. Resolved first, before any side effect:
    // an invalid override (a typed empty `--image`) or an unreadable
    // configured image must not create state. `args.image.requested()` also
    // applies the empty-`AGENT_VM_IMAGE_TAG`-is-unset rule.
    let boot = boot_image::select(args.image.requested()?, images)?;
    let network_plan = crate::network::Plan::from_args(args.network, user_network)?;
    // The one output policy for this selection: explicit sources render their
    // escaped reference; the default tier renders a fixed label and redacts the
    // reference from every notice, debug dump, progress line and error chain.
    let label = boot.label();
    // `--allow-missing-credentials` moves the *availability* of a YAML
    // credential and nothing else; see `MissingCredentialPolicy`. Derived once
    // here so the flag is read in exactly one place.
    let missing_credential_policy = if args.allow_missing_credentials {
        MissingCredentialPolicy::Warn
    } else {
        MissingCredentialPolicy::Fail
    };
    // The launch's guest-HOME link list: the compiled-in providers plus one
    // link per `persist` path in this launch's provisioning closure. Computed
    // once and threaded to both provisioning sites and the root-mode rootfs
    // patch, so they cannot drift (CONTEXT.md → *Guest HOME*).
    let home_links = crate::guest_home::links(grant.persist());

    // Resolve root vs. non-root guest mode up front — it gates dir
    // provisioning, the rootfs patch block, and the guest env/exec wiring
    // further down, so it has to be known before any of that runs.
    let root_mode = user::should_run_root(args.root, env::var("AGENT_VM_ROOT").ok().as_deref());
    let guest_identity = user::resolve_guest_identity(root_mode)?;
    // The guest HOME those links live under: `/root` in root mode (whose rootfs
    // bakes them in, so nothing real is ever at a link path) and the mirrored
    // host HOME otherwise. Needed *before* mount preparation: it is what turns "a
    // mount at this guest path" into "a mount that shadows a `persist` link",
    // and that collision has to be refused before any fork is published
    // (ADR-0046 / #394 D4).
    let guest_home_path = guest_identity
        .as_ref()
        .map(|identity| PathBuf::from(identity.host_home()))
        .unwrap_or_else(|| PathBuf::from("/root"));
    // Independent of `guest_identity` (which is `None` under `--root`) so
    // the `--mount …:follow-links` $HOME guardrail is still enforced in
    // root mode instead of silently no-op'ing. See `mount::expand_follow_links`.
    //
    // `$HOME` unset does **not** mean the home is unknown: `host_home_dir`
    // falls back to the account record, so a daemon/`env -i`/CI launch still
    // locates the Pi home instead of failing open on the core project bind
    // (ADR-0020). `None` here means neither source named a home, which
    // `ProtectedHostFiles::require_home` refuses on.
    let mount_home = user::host_home_dir();

    let session = ProjectSession::for_cwd()?;
    // AC#6 (agent-vm issue #40): fail closed, before touching the
    // filesystem or booting anything, if this sandbox's real agent/control
    // socket paths would overflow the platform's Unix-domain-socket path
    // limit. See `msb_install::ensure_socket_paths_fit`'s doc comment.
    // Mount preparation is deliberately before every launch-side effect.
    // A rejected topology must not provision session state, reap a sandbox,
    // emit a banner, build tooling, refresh credentials, or configure msb.
    let host_path = session
        .project_dir
        .to_str()
        .context("project path contains non-UTF-8 bytes; not supported")?;
    let (project_guest_path, remap_reason) =
        resolve_project_guest_path(&session.project_dir, host_path);
    let mut core_volumes = user::core_dir_volumes(
        guest_identity
            .as_ref()
            .map(|gi| (gi.host_home(), session.guest_home_dir())),
        &project_guest_path,
        &session.project_dir,
        &session.state_dir,
    );
    let mount_context = launch_mount_context(
        session.mount_store_dir(),
        mount_home.clone(),
        core_volumes
            .iter()
            .map(|volume| PathBuf::from(&volume.guest_path))
            .collect(),
        // Core binds are writable too; the role names the remedy on refusal.
        core_volumes
            .iter()
            .map(|volume| CoreHostSource::new(volume.bind, volume.host_path.clone()))
            .collect(),
        // The same link list both provisioning sites consume, so the pre-fork
        // collision check cannot drift from the links that are actually created.
        crate::guest_home::PersistedHome::new(guest_home_path, &home_links),
    )?;
    // `--mount` is the only declaration source a launch has until verified user
    // `mounts` are selected here (ADR-0046), so the whole list is argv-tagged.
    let mount_requests = mount::MountRequests::from_cli(
        mount::parse_extra_mounts(&args.mount).context("parsing --mount")?,
    );
    let mount_plan = mount::prepare(mount_requests, &mount_context).map_err(|error| {
        // A persisted-HOME collision is not a `--mount` failure — the core
        // project bind alone can cause it — and its own sentence already names
        // the remedy, so it keeps its exact bytes and its own top line.
        if error.is::<crate::guest_home::PersistCollision>() {
            error
        } else {
            error.context("preparing --mount")
        }
    })?;

    // These checks open/create Microsandbox state, so they must remain after
    // the side-effect-free mount rejection boundary.
    crate::msb_install::ensure_msb_home(&crate::msb_install::msb_home_dir()?)?;
    // Fail fast if the private msb.db was forward-migrated by a newer build.
    // See src/msb_preflight.rs and issue #30.
    crate::msb_preflight::ensure_db_not_ahead().await?;
    crate::msb_install::ensure_socket_paths_fit(&session.sandbox_name)?;
    // Pre-#96 projects hold a real `<state>/home/.pi` directory that the new
    // compiled link would refuse to replace. Runs before ensure_dirs so the
    // rename lands on a free name, and in BOTH guest modes. It is
    // descriptor-anchored (every ancestor opened no-follow) and fails closed on
    // a redirected ancestor, so a guest-planted `<state>/home` symlink cannot
    // make it move the host's real `~/.pi`. See #96 and ADR-0021.
    session.migrate_legacy_pi_home()?;
    // Report existing guest-managed Pi state *before* provisioning, and before
    // any later operation that could fail: the migration above has just put
    // real state at its canonical location, and a caller must see unsafe state
    // even when provisioning or image setup later bails. One unconditional
    // scan covers every resolved tool (including custom tools), because the
    // compiled Pi home is unconditional. The banner supplies project/state
    // context; the findings themselves stay field-only. Advisory: this never
    // denies the launch.
    let mut notices = LaunchNotices::to_stderr();
    notices.emit(launch_banner(&session))?;
    // The selected boot image, once, before the session provisions any state
    // (D10). `boot` was resolved before the first side effect above; `label`
    // redacts a default-tier reference.
    notices.emit(format!("==> Boot image: {label}"))?;
    let pi_report = crate::pi_credential_inspection::inspect_project(&session.state_dir);
    if let Some(warning) = pi_report.launch_warning() {
        notices.emit(warning)?;
    }
    session.ensure_dirs(&home_links)?;
    if !root_mode {
        session
            .provision_guest_home(&home_links)
            .context("provisioning non-root guest HOME")?;
    }
    // Core binds carry no follow opt-in, so a symlink in a configured state
    // root (or guest HOME) must not reach the runtime unresolved. Now that
    // provisioning has created the state root and `home`, resolve each core
    // source once. `session.state_root()` deliberately accepts env spelling,
    // and guest HOME's source is `<state_dir>/home`, so both can traverse a
    // symlinked ancestor until this step.
    for volume in &mut core_volumes {
        volume.host_path = volume.host_path.canonicalize().with_context(|| {
            format!(
                "canonicalizing core bind source {} for {}",
                volume.host_path.display(),
                volume.guest_path
            )
        })?;
    }
    // Reap any orphan sandbox dirs left by earlier crashed launchers in
    // this same project before we boot. See
    // `reap_stale_project_sandboxes` for the full rationale.
    reap_stale_project_sandboxes(&session.project_hash).await;

    // The selected boot image's own text, kept as this session's source
    // identity for notices and the guest command line. What the SDK is given is
    // decided by the preparation below. No launch invokes Docker or builds an
    // image; a custom image is selected with
    // `--image`/`AGENT_VM_IMAGE_TAG`/config and booted verbatim
    // (`boot_image::select` above is the sole selection owner).
    let image = boot.reference().as_str().to_string();

    let memory_mib: u32 = args
        .memory
        .checked_mul(1024)
        .context("--memory in GiB overflows u32 MiB")?;
    let cpus = args.cpus;

    // Mount the host project at the *same* absolute path inside the guest so
    // that anything the agent emits (compiler errors, stack traces, git
    // output, file:line references) names a path that's interpretable on the
    // host. The agent-vm-state mount is internal and stays at a fixed path.
    //
    // Exception: paths under tmpfs mount points (typically /tmp, /run,
    // /dev/shm) can't be mirrored, because the guest tmpfs-mounts those at
    // boot — that wipes any mount point our `patch` builder baked into the
    // rootfs. Fall back to /workspace and tell the user once.
    //
    // Per-agent state lives behind a *single* bind mount, with the
    // agent's expected home wired up via symlink (claude, opencode) or
    // an env var (codex). The single-bind layout predates the
    // split-irqchip switch in the runtime — it kept IRQ pressure down
    // back when libkrun only handed out 11 virtio IRQs total. Today
    // it's still the better shape: one virtio-fs server, one rootfs
    // patch entry per agent, and a stable on-host layout. Codex needs
    // the env-var path because its CLI binary lives under its install
    // prefix's .codex/packages (/opt/agent/.codex/packages in the
    // image; /root/.codex/packages under --root), which a symlink
    // would shadow.
    if let Some(reason) = remap_reason {
        notices.emit(format!(
            "==> Project path {host_path} {reason}; mounting at /workspace instead"
        ))?;
    }
    let mut patch_builder_steps = mkdir_chain(Path::new(&project_guest_path));
    // PullPolicy::IfMissing keeps the slow part (pull + materialize) off every
    // launch. There is no launch-time registry probe of any kind: a warm launch
    // must not query a mutable tag, and checking for movement is the explicit
    // `agent-vm image refresh` operation's job.

    // Snapshot host credentials into per-project token files and place
    // placeholder credentials.json files where the in-VM agents will
    // find them. The token files are passed to microsandbox below as
    // SecretSource::File entries; the proxy re-reads them on every
    // connection setup, so a host-side rotation propagates without
    // restarting the sandbox.
    //
    // Passing the in-guest project path lets us pre-approve it in
    // Claude's per-folder trust list (~/.claude.json `projects.<path>.
    // hasTrustDialogAccepted = true`), suppressing the "do you trust
    // this folder?" wizard on first launch in each project.
    // Phase 7 (moved up): parse `--mount HOST[:GUEST]` so the
    // GitHub repo scan below can also walk each mount's remote +
    // submodules — matches main-branch claude-vm.sh behavior.
    //
    // Deliberately scanned here on the *parsed*, pre-expansion list: the
    // GitHub repo scan below (and the volume-building loop further down,
    // via `expand_follow_links`) both need this list, but expansion walks
    // the host filesystem to auto-discover `follow-links` symlink targets
    // (issue #11), and those discovered directories should NOT feed the
    // GitHub allow-list — a `follow-links` mount whose resolved skill dirs
    // happen to contain git checkouts must not silently widen
    // api.github.com access to remotes the user never asked for. Only the
    // explicit `--mount` entries are scanned for repos.
    // Parse and prepare once.  In particular, preparation validates the
    // complete mount plan before it creates fork state, scans repositories,
    // snapshots credentials, or hands anything to the sandbox builder.
    for notice in &mount_plan.notices {
        notices.emit(notice)?;
    }

    // Phase 6: build the per-launch GitHub repo allow-list from the
    // cwd's `git remote -v` + its `.gitmodules` submodules + the
    // same for any `--mount`ed dir, plus any `--repo` overrides.
    // Used both to decide whether to bother capturing host gh auth
    // (no repos → nothing to talk to) and to constrain
    // api.github.com requests server-side via the intercept hook.
    // --no-git suppresses *automatic* cwd-remote detection but does
    // NOT discard explicit --repo arguments (review #11): a user
    // who passes `--no-git --repo X` clearly wants the explicit
    // allow-list. We do warn so they notice if they didn't mean to.
    let mut allowed_repos: Vec<String> = Vec::new();
    if !args.no_git {
        allowed_repos.extend(detect_github_repos(
            &session.project_dir,
            mount_plan.repo_scan_roots.iter(),
        ));
    } else if !args.repo.is_empty() {
        notices.emit(format!(
            "==> --no-git skips cwd remote auto-detection, but --repo overrides are kept ({} entr{})",
            args.repo.len(),
            if args.repo.len() == 1 { "y" } else { "ies" },
        ))?;
    }
    for r in &args.repo {
        let r = r.trim().to_string();
        if !r.is_empty() && !allowed_repos.iter().any(|x| x.eq_ignore_ascii_case(&r)) {
            allowed_repos.push(r);
        }
    }
    let use_github = !allowed_repos.is_empty();
    notices.emit(repo_scope_notice(&allowed_repos))?;

    // #161/#162: resolve this launch's `credentials = [...]` requests against
    // the user's authorization file, before any guest env is published and long
    // before a sandbox record is written.
    //
    // Loading is deferred until a launch actually requests a credential: a
    // launch that requests none behaves exactly as before and does not depend
    // on the file. A launch that *does* request one fails closed if the file
    // cannot be read, rather than quietly booting without the credential it
    // asked for.
    //
    // #162 moved this call *before* `secrets::refresh` because a same-named
    // authorization suppresses that provider's capture; the resolved
    // `replaced` set has to exist before anything is captured. The *notice*
    // emission stays at its historical position below, so the launch's warning
    // order is unchanged. This puts a malformed/unsatisfiable
    // `credentials.yaml` ahead of host credential capture and the
    // `==> host credentials` notice, and nothing else - the tooling-layer build
    // and the session/guest-home provisioning already ran earlier.
    // The file was loaded and env values captured in main before children (#163).
    let (launch_credentials, credential_source) =
        credential_preflight.resolve(missing_credential_policy)?;

    // `provisioned` is the launch catalog's resolved closure (parameter).
    // The requirement set is the tool's own `credentials`, read by the bail
    // loop below; `github_egress` (`use_github`, driven by `--no-git` /
    // detected repos) stays orthogonal to the tool.
    let creds = crate::secrets::refresh(
        &session.state_dir,
        &project_guest_path,
        &crate::secrets::CredentialProvisioning {
            provisioned,
            replaced: launch_credentials.replaced(),
            github_egress: use_github,
        },
    )
    .context("snapshotting host credentials")?;

    // Providers the proxy actually holds a substitution entry for. Derive it
    // once from `CredsState::wired()` so the guest-env gate and the placeholder
    // clearer cannot desynchronise from `token_file`.
    let launch_providers = credential_provider::LaunchProviders {
        provisioned,
        wired: creds.wired(),
    };

    // The built-ins a same-named authorization replaced. Read once here and
    // reused by the requirement bail below and CredentialProvisioning
    // above, so `replaced()` has exactly two readers in this file (this
    // binding and the `CredentialProvisioning` above).
    let replaced = launch_credentials.replaced();

    // When a *required* provider produced no usable credential, fail loudly
    // here rather than letting the guest send an unsubstituted placeholder
    // bearer (the proxy drops it as a violation, or the vendor returns a
    // confusing 401). Only Anthropic and Copilot carry a message; no default
    // tool requires both, so at most one fires. Iteration is in
    // `CredentialProvider::ALL` order, so the error stays deterministic.
    //
    // The requirement set stays the launched tool's own `credentials`: a tool
    // that reaches another through `tools` gets that tool's credential
    // *provisioned* without inheriting its hard bail.
    //
    // Anthropic: a failed capture used to be only a `tracing::warn!` and the
    // launch continued, so the in-VM Claude Code came up signed out. The
    // natural next move — `/login` inside the guest — cannot work either: the
    // guest only ever holds placeholders, and `intercept_hook::oauth_refresh`
    // accepts `grant_type=refresh_token` with the placeholder refresh token
    // *only*, so an authorization-code exchange is rejected and Claude Code
    // surfaces a bare "OAuth error ... status code 400".
    for provider in grant.required().iter() {
        // A replaced provider's requirement is the authorization's `required`,
        // already enforced in phase 1 (spec lines 207-208: "YAML entries use
        // the YAML `required` semantics, rather than inheriting the old
        // built-in requirement solely because their names appear in
        // `credentials`").
        if replaced.contains(provider) {
            continue;
        }
        if creds.token_file(provider).is_none()
            && let Some(message) = credential_provider::missing_credential_error(provider)
        {
            anyhow::bail!("{message}");
        }
    }

    notices.emit(creds_notice(&creds))?;

    // RAII guard so the Phase-5 host-cred mutation check runs on
    // *every* exit path from launch() — including `?` propagation
    // from attach/exec_stream errors (review finding #10). Without
    // this the safety net only fires on the happy path.
    struct SnapshotGuard(Option<crate::secrets::HostCredsSnapshot>);
    impl Drop for SnapshotGuard {
        fn drop(&mut self) {
            if let Some(snap) = self.0.take() {
                crate::secrets::verify_snapshot(&snap);
            }
        }
    }
    let _snap_guard = SnapshotGuard(creds.snapshot.clone());

    // Phase 6/9: always write the guest gitconfig (carries the
    // unconditional `safe.directory = *` so git inside the guest
    // accepts the host-bind-mounted project despite the UID
    // mismatch). The credential-helper / gh hosts.yml stanzas are
    // gated on having actually captured a host gh token.
    //
    // Resolve the host's git author identity (gh api user, then host
    // gitconfig) so in-VM commits land with the user's real
    // name/email rather than the legacy `agent-vm`/`agent-vm@msb.local`
    // placeholder. If neither source yields anything usable, the
    // `[user]` section is omitted and git will refuse to commit
    // until the user sets one — preferable to mis-attribution.
    let host_identity = crate::secrets::discover_host_git_identity();
    notices.emit(git_identity_notice(host_identity.as_ref()))?;
    crate::secrets::write_guest_gh_config(
        &session.state_dir,
        creds.gh_token_file.is_some(),
        host_identity.as_ref(),
    )
    .context("writing guest gh/git config")?;

    // `mount_plan` is closed: launch translates its typed instructions but
    // never reclassifies a source or makes another mount-policy decision.

    // The one image preparation, before the builder and before create. A local
    // rootfs/disk selection passes through with its original text and touches
    // no approval record; an OCI selection is acquired, validated and (on a
    // first pin) committed to this host's approval authority *before* anything
    // is handed to the SDK, so a later create failure cannot leave a launch on
    // unapproved bytes. The returned value holds the shared publication barrier
    // across both create variants.
    let prepared = crate::image_pin::prepare_selected(&boot)
        .await
        .context("preparing the boot image")?;
    let sdk_image = prepared.sdk_reference().to_owned();
    let acquisition_reference = sdk_image.clone();
    let is_local_registry = crate::pull::is_plain_http_registry(&sdk_image);
    // `.workdir()` becomes libkrun's `KRUN_WORKDIR`, which rides the
    // printable-ASCII-only kernel command line. When the real project path
    // isn't cmdline-safe (non-ASCII / whitespace) we hand libkrun `/` and
    // pin the agent's real cwd via the exec request below instead — the
    // exec cwd travels over the byte-safe vsock channel, and the project is
    // still bind-mounted (and the agent still runs) at its true path. The
    // mount spec itself reaches the guest via the boot-params side channel,
    // not the cmdline. (`KRUN_WORKDIR` only sets PID-1's initial chdir,
    // which agentd overrides per-exec, so the placeholder is invisible.)
    let krun_workdir = if guest_path_is_cmdline_safe(&project_guest_path) {
        project_guest_path.clone()
    } else {
        "/".to_string()
    };
    let mut builder = Sandbox::builder(&session.sandbox_name)
        .image(sdk_image.as_str())
        // AC#3 (agent-vm issue #40): explicitly size the writable OCI
        // upper instead of relying on the SDK default. `root_disk()`
        // requires an OCI image to already be set, hence chained right
        // after `.image(...)`; NOT the deprecated `oci_upper_size()`
        // alias, which just forwards to this same call.
        .root_disk(crate::defaults::WRITABLE_UPPER_MIB)
        .registry(|r| if is_local_registry { r.insecure() } else { r })
        .pull_policy(PullPolicy::IfMissing)
        .cpus(cpus)
        .memory(memory_mib)
        .workdir(krun_workdir);
    for volume in core_volumes {
        builder = builder.volume(volume.guest_path, |m| m.bind(volume.host_path));
    }
    // MSB_USER on the *sandbox* builder (independent of the per-exec
    // .user() calls at the attach/exec builders below) drives agentd's
    // InitResolved.default_user, which the host installs as
    // passthroughfs's BindIdentityMap { guest_uid, guest_gid, .. } — this
    // is what makes every bind-mounted file (HOME/project/state) stat
    // with owner bits matching the guest's real uid via passthroughfs's
    // do_access, instead of uid 0. Without it, bind-mounted files would
    // stat as uid 0 to the guest while the exec'd process runs as the
    // real host uid, breaking write access. Neither this nor the
    // per-exec .user() below is a substitute for the other — both are
    // load-bearing (see ADR-0001's Decision section).
    //
    // The identity is derived once and reused verbatim for the sandbox builder
    // and both per-exec `.user()`s, so the bind identity map and the exec'd
    // process always agree. Root mode is explicitly `0:0` even when the image
    // `USER` names an app account (#258).
    let exec_user = guest_identity
        .as_ref()
        .map_or(user::ROOT_USER_SPEC, |gi| gi.user_spec.as_str())
        .to_owned();
    builder = builder.user(exec_user.clone());
    // Prepared mount instructions carry the already-classified node kind;
    // file leaves get only their parents patched so agentd can safely create
    // the target without writing through a readonly parent.
    let mut extra_mount_mkdirs: Vec<String> = Vec::new();
    for volume in &mount_plan.volumes {
        let guest = volume.guest.clone();
        let guest_str = guest
            .to_str()
            .context("--mount guest path must be UTF-8")?
            .to_owned();
        match &volume.source {
            mount::PreparedVolumeSource::WritableBind(host) => {
                notices.emit(format!(
                    "==> Mounting {} -> {}",
                    host.display(),
                    guest.display()
                ))?;
                let host = host.clone();
                builder =
                    builder.volume(guest_str, move |m| m.bind(host).follow_root_symlinks(true));
            }
            mount::PreparedVolumeSource::ReadOnlyBind(host) => {
                notices.emit(format!(
                    "==> Mounting {} -> {} (read-only)",
                    host.display(),
                    guest.display()
                ))?;
                let host = host.clone();
                builder = builder.volume(guest_str, move |m| {
                    m.bind(host).follow_root_symlinks(true).readonly()
                });
            }
        }
        match volume.node_kind {
            mount::PreparedNodeKind::Directory => extra_mount_mkdirs.extend(mkdir_chain(&guest)),
            mount::PreparedNodeKind::File => {
                if let Some(parent) = guest.parent() {
                    extra_mount_mkdirs.extend(mkdir_chain(parent));
                }
            }
        }
    }
    builder = builder.patch(|mut patch| {
        for parent in extra_mount_mkdirs.drain(..) {
            patch = patch.mkdir(parent, None);
        }
        patch
    });
    let mut builder = builder.patch(|mut p| {
        for parent in patch_builder_steps.drain(..) {
            p = p.mkdir(parent, None);
        }
        if root_mode {
            // Root mode: the dotfile symlinks live at un-shadowed
            // rootfs paths (/root/...), so baking them via `.patch()`
            // is correct — nothing mounts over /root at runtime. The
            // ancestor chain (`.local`, `.local/share`, `.config`, plus a
            // declared path's own ancestors) is parents-first by construction,
            // which is what the builder's sequential mkdir needs.
            for dir in crate::guest_home::link_parent_dirs(&home_links) {
                p = p.mkdir(format!("/root/{}", dir.display()), None);
            }
            for link in &home_links {
                p = p.symlink(
                    link.guest_target(),
                    format!("/root/{}", link.home_relative.display()),
                    true,
                );
            }
            p
        } else {
            // Non-root mode: the HOME dir + its dotfile symlinks are
            // instead provisioned host-side (ProjectSession::
            // provision_guest_home, called above) because
            // /agent-vm-state is a *runtime* bind mount that shadows
            // whatever a `.patch()` bakes at that path. /etc/passwd and
            // /etc/group are real rootfs, unaffected by that bind, so
            // appending the guest's identity here is correct.
            let gi = guest_identity
                .as_ref()
                .expect("non-root mode always resolves a guest identity");
            p = p.append("/etc/passwd", user::passwd_append_line(gi));
            // See `group_append_line`'s doc comment (user.rs) for why
            // gids in the system-reserved range are skipped.
            if let Some(line) = user::group_append_line(gi.gid) {
                p = p.append("/etc/group", line);
            }
            p
        }
    });

    // #161/#162: emit the resolution's notes and withheld-credential warnings
    // here, at their historical position, so the notice order stays
    // byte-identical (`repo_scope_notice` → `creds_notice` → these). The
    // *resolution* itself now runs before `secrets::refresh` above.
    for note in launch_credentials.notes() {
        notices.emit(format!("warning: {note}"))?;
    }
    for withheld in launch_credentials.withheld() {
        notices.emit(format!("warning: {}", withheld.notice()))?;
    }
    // AC2: an authorized credential owns its guest variable, so a tool-declared
    // `env` key for that name is refused and every other writer of the name is
    // suppressed. That decision is made once, in `assemble_guest_env` below,
    // rather than at each emission site; see `credential_resolver`.

    network_plan
        .emit_launch_notices()
        .context("writing launch networking notices")?;
    // Compare declarations to the authority just printed, before applying it.
    if let Some(declared) = grant.requests() {
        for line in network_plan
            .request_report(&declared.requests, declared.tier)
            .lines()
        {
            notices.emit(line)?;
        }
    }

    let executable =
        std::env::current_exe().context("resolving agent-vm executable for credential hook")?;
    let credential_plan = crate::credential_injection::Plan::new(
        executable,
        crate::credential_injection::Inputs {
            creds: &creds,
            state_dir: &session.state_dir,
            allowed_repos: &allowed_repos,
            provisioned,
            launch: &launch_credentials,
        },
    )?;

    builder = network_plan.apply_to(builder);
    builder = credential_plan.apply_to(builder)?;

    // The guest `PATH` is owned by the booted image, and it is deliberately not
    // resolved here (#258). Any pre-create cache read would miss the OCI config
    // on a cold first acquisition and pin the launcher's fallback literal,
    // silently overriding a nonstandard image prefix. `path: None` below leaves
    // the sandbox env's OCI default in place; after create the effective value
    // is read back from the created sandbox (`resolved_exec_path`) and applied
    // as the per-exec override on both exec paths.

    // #161: a `sentinelEnv: false` variable must end up *unset*, but the SDK
    // builder cannot remove an `ENV` the image itself ships - guest env is
    // last-wins, so agent-vm publishing nothing leaves the image's value in
    // place. Such a collision is therefore refused rather than silently
    // ignored. The metadata read must fail **closed**: logging is not handling
    // an error (CODING_STANDARDS), and a cold cache is exactly when an
    // image-defined value for an owned name would otherwise survive.
    // The shared publication barrier covers every image-cache read this launch
    // makes through both SDK create variants. Shared, so unrelated warm
    // launches proceed concurrently; exclusive archive publication cannot move
    // an alias under the cache consumption below.
    //
    // The image preparation above already validated the content this create
    // consumes, under that barrier: a present entry is complete,
    // identity-consistent and host-platform, and an approved selection is
    // reacquired by its approved digest rather than re-resolved from a tag. A
    // local rootfs/disk launch has no OCI cache participation at all and takes
    // no barrier.
    if launch_credentials.needs_image_env_check() {
        // The preparation validated exactly the content this create consumes, so
        // its environment is the answer — including on a cold first acquisition,
        // which is what makes the check real rather than a best-effort cache
        // read. Only a local path (no OCI config at all) keeps the historical
        // metadata read, which still fails closed.
        let image_env = match prepared.image_env() {
            Some(image_env) => Some(image_env.to_vec()),
            None => image_config_env(&sdk_image).await,
        };
        match image_env {
            Some(image_env) => {
                let image_env: BTreeSet<String> = image_env.into_iter().collect();
                if let Some(name) = launch_credentials
                    .unset_names_in_image_env(&image_env)
                    .into_iter()
                    .next()
                {
                    anyhow::bail!(
                        "the boot image defines the environment variable `{name}`, which an \
                         authorized credential declares `sentinelEnv: false` (it must be unset in \
                         the guest). An image `ENV` cannot be removed through the sandbox builder; \
                         rename the variable in credentials.yaml"
                    );
                }
            }
            None => {
                // Only a local rootfs/disk selection reaches this: an OCI
                // selection's environment always comes from the preparation, so
                // there is nothing to cache and no `image refresh` to suggest —
                // that command acquires OCI references and always refuses the
                // user's own image.
                anyhow::bail!(
                    "the boot image's environment could not be read, so agent-vm cannot verify that a \
                     `sentinelEnv: false` variable is unset in the guest for `{image}`. Use an OCI \
                     image so agent-vm can read its environment. Alternatively declare \
                     `sentinelEnv: true` in credentials.yaml"
                )
            }
        }
    }

    // Non-root mode mirrors the host's own $HOME and username into the guest
    // (ADR-0002); root mode pins the literal root identity (HOME=/root,
    // USER/LOGNAME=root) so an image's `ENV HOME`/`USER` cannot leak in (#258).
    // Built here as data so the single ownership-aware assembly below is what
    // actually publishes it.
    let identity: Vec<(&'static str, String)> = match &guest_identity {
        Some(gi) => user::guest_identity_env(gi).into_iter().collect(),
        None => user::root_identity_env().into_iter().collect(),
    };
    let provider_env = credential_provider::provider_guest_env(launch_providers);

    // Guest env, the one emission point (#161, AC2). Every writer's
    // contribution — the tool's own `env`, PATH, the guest
    // identity, the launcher constants and provider variables — is filtered or
    // rejected in `assemble_guest_env`, so no writer can bypass ownership by
    // not consulting it, and an owned name's sentinel is published last of all.
    //
    // The tool's own `env` is published *first* (inside the assembly) for the
    // same reason as before: a project config cannot accidentally redirect
    // PATH, IS_SANDBOX, LANG or a provider's variable, because the launcher's
    // own later emission wins. This is defence in depth, not a trust boundary
    // (a config that can declare `env` can already declare `command`; ADR-0015).
    // HOME/USER/LOGNAME are published by the launcher in both modes (the
    // non-root account triple, or the root triple), so `config::check_env_key`
    // rejects those three keys outright at config time (ADR-0016).
    let assembled = launch_credentials
        .assemble_guest_env(crate::credential_resolver::GuestEnvSources {
            tool_env: grant.guest_env(),
            path: None,
            identity: &identity,
            always: GUEST_ALWAYS_ENV,
            provider: &provider_env,
        })
        .context("assembling the credential-owned guest environment")?;
    for (key, value) in &assembled {
        builder = builder.env(key, value);
    }

    let profile = env::var("AGENT_VM_PROFILE").is_ok();
    notices.emit(format!(
        "==> Booting sandbox from {} ({memory_mib} MiB, {cpus} vCPU; first run pulls layers, otherwise ~3s)",
        label.text()
    ))?;
    let t_create = Instant::now();
    // Keep command debug output adjacent to the config dump. The invocation
    // travels over exec only after boot, so SandboxConfig does not contain it.
    // Arguments have the dump's exposure class behind the same opt-in flag.
    let inner_cmd = invocation.program();
    let command_display = invocation.display();
    let inner_argv = invocation.argv();
    let config = builder.build().await.context("preparing sandbox config")?;
    if let Some(dump) = crate::debug_config::sandbox_config(&config, label.is_redacted())? {
        notices.emit(dump)?;
        // No trailing space when the argv is empty (codex/opencode), so the
        // line is exactly the guest command line an integration test asserts.
        let guest_command = if inner_argv.is_empty() {
            inner_cmd.to_string()
        } else {
            format!("{inner_cmd} {}", inner_argv.join(" "))
        };
        notices.emit(format!("[debug] guest command: {guest_command}"))?;
    }
    // The resolver variant is used exactly when this launch has a ready,
    // authorized credential. The `render`/`await_render` dance below is
    // unchanged: the two create entry points share the same
    // `(PullProgressHandle, JoinHandle)` shape.
    crate::image_acquire::gate_before_sdk_consume().context("preparing sandbox creation")?;
    let (progress, task) = match credential_source {
        Some(source) if !launch_credentials.ready().is_empty() => {
            Sandbox::create_with_pull_progress_and_resolver(
                config,
                launch_credentials.resolver(source),
            )
        }
        _ => Sandbox::create_with_pull_progress(config),
    };
    let reference_label = label.is_redacted().then(|| label.text().to_string());
    let render_task = tokio::spawn(crate::pull_progress::render(progress, reference_label));
    // See pull.rs: await render before propagating errors so finish()
    // clears the bars, and use the logging helper so render-task panics
    // are visible instead of silently swallowed.
    let result = task
        .await
        .context("create-with-pull-progress join")
        .and_then(|inner| inner.context("creating sandbox"));
    crate::pull_progress::await_render(render_task).await;
    // The SDK has finished consuming the image cache. Release the barrier
    // before guest hooks, commands and the session: a long-running guest must
    // never hold image publication.
    crate::image_acquire::gate_create_returned().context("creating sandbox")?;
    drop(prepared);
    let sandbox = match result {
        Ok(sandbox) => sandbox,
        // A redacted (default-tier) failure must not chain the registry URL
        // that embeds the reference; the fixed reason still names the stage. An
        // explicit source keeps its error unchanged.
        Err(error) => {
            let error = crate::image_miss::attach(
                translate_create_error(error),
                &acquisition_reference,
                &label,
            );
            return Err(label.redact_error("booting a sandbox from", error));
        }
    };
    if profile {
        notices.emit(format!("[profile] create: {:?}", t_create.elapsed()))?;
    }
    // When the project path isn't cmdline-safe we handed libkrun the `/`
    // workdir placeholder, so create-time validation only confirmed that
    // `/` exists — not that the real (non-ASCII) mount point materialized.
    // agentd's per-exec `chdir` ignores failure (it would silently drop the
    // agent into `/`), so verify the real path is present now over the
    // byte-safe fs channel and fail loudly otherwise. ASCII paths were
    // already validated at create time (workdir == the real path).
    if !guest_path_is_cmdline_safe(&project_guest_path)
        && !sandbox
            .fs()
            .exists(&project_guest_path)
            .await
            .unwrap_or(false)
    {
        let _ = sandbox.stop().await;
        anyhow::bail!(
            "project path {project_guest_path} did not appear inside the guest \
             (the bind mount failed to materialize); full logs: {}",
            sandbox_log_dir(&session.sandbox_name).display()
        );
    }

    // The effective exec `PATH` now comes from the created sandbox's resolved
    // config: the SDK merges the acquired image's OCI config before create
    // returns, including on a cold first acquisition, so this is the image's
    // real PATH rather than a cache-miss fallback (#258).
    let exec_path = resolved_exec_path(sandbox.config());

    // Optional capability resolution: an image that carries the Chrome
    // DevTools marker, or supplies the wrapper, gets the launcher-owned MCP
    // entry; anything else boots normally with the entry removed. There is no
    // image-version gate — compatibility is the documented boot-image contract
    // (USAGE.md#boot-image-contract), not an integer (#258).
    let chrome_mcp_enabled = crate::image_capabilities::chrome_mcp_enabled(
        &sandbox,
        label.text(),
        env::var_os("AGENT_VM_NO_CHROME_MCP").is_some(),
    )
    .await;
    crate::secrets::sync_chrome_mcp(&session.state_dir, chrome_mcp_enabled)
        .context("synchronizing Chrome MCP configuration")?;

    network_plan
        .start_event_reporting(&sandbox)
        .context("starting auto-publish event reporting")?;

    // Wrap the agent invocation in a tiny bash prelude that:
    //
    // 1. Strips IPv6 nameservers from /etc/resolv.conf before exec'ing
    //    the agent. microsandbox's agentd writes both v4 and v6 gateway
    //    DNS into the guest's /etc/resolv.conf at boot. The v6 entry was
    //    observed unresponsive in at least one nested-libkrun setup
    //    (gateway times out on v6 DNS queries), and codex's Rust async
    //    resolver returns EAI_AGAIN ("Try again") in that case instead
    //    of falling through to the working v4 resolver the way glibc's
    //    getaddrinfo does. Result: codex hangs at startup with "failed
    //    to lookup address information" for chatgpt.com, even though
    //    `getent hosts chatgpt.com` returns immediately. Stripping the
    //    v6 nameserver line makes the resolver single-stack, which is
    //    fine for outbound traffic to public APIs. The regex matches
    //    lines whose nameserver value contains a colon — IPv4 addresses
    //    never do, IPv6 addresses always do.
    //
    // 2. Redirects stdin to /dev/null when not on a TTY. exec_with's
    //    default `StdinMode::Null` was observed *not* to satisfy codex
    //    0.133's `exec` subcommand: codex blocks indefinitely on what it
    //    thinks is unbounded interactive input. Backgrounding codex (`&`)
    //    fixed it (bash auto-redirects stdin to /dev/null for background
    //    jobs) but we can't background the user's agent. An explicit
    //    `exec < /dev/null` gives codex a real /dev/null fd and it
    //    proceeds. `[ -t 0 ]` keeps interactive TTY launches unaffected.
    // Phase 9 adds a project-runtime hook (`.agent-vm.runtime.sh`):
    // if the file exists at the project root inside the guest, source
    // it before exec'ing the agent. Project owners use this for
    // setup that has to happen *inside* the sandbox (npm install,
    // docker compose up, env-var exports). Runs once per launch with
    // PWD set to the project dir; non-zero exit aborts the launch
    // with the same exit code.
    // Importing the microsandbox MITM CA into the `chrome` user's NSS
    // DB (chromium on Linux ignores the system CA bundle and honours only
    // its per-user NSS DB, so the chrome-devtools MCP would otherwise fail
    // every HTTPS page with ERR_CERT_AUTHORITY_INVALID) lives in the in-image
    // `agent-vm-chrome-mcp` wrapper: it runs once when the chrome MCP starts,
    // off the launch path, and is skipped when chrome is unused. The CA is
    // per-install (not bakeable into the shared image); see the opt-in Chrome
    // DevTools layer wrapper. The wrapper owns that work off the launch path.
    //
    // Assemble the in-guest `bash -c` line via [`AgentShellLine`], which is
    // unit-tested directly. The IPv6-nameserver strip is the
    // `STRIP_IPV6_NAMESERVERS` const (see its doc comment / PLAN.md B3).
    let shell_line = AgentShellLine {
        guard: invocation.guard(),
        project_guest_path: &project_guest_path,
        image: &image,
        command: inner_cmd,
        args: inner_argv,
    }
    .render();
    let cmd = image_contract::LAUNCH_SHELL;
    let shell_argv: Vec<String> = vec!["-c".into(), shell_line];

    let t_run = Instant::now();
    let exit = if std::io::stdin().is_terminal() {
        notices.emit(format!("==> Attaching to {command_display}"))?;
        // Pin the agent's cwd to the real project path via the exec request
        // (vsock, byte-safe), NOT libkrun's `KRUN_WORKDIR` — which may be the
        // ASCII `/` placeholder for a non-ASCII project. `attach()` alone
        // leaves cwd unset, falling back to that placeholder; `attach_with`
        // lets us set it, matching the streaming path below.
        //
        // PID 1 (agentd) must stay root to `setuid` per exec, so this per-exec
        // `.user(...)` governs the exec'd process's actual uid. It's independent
        // of the sandbox-builder `.user()` set above (MSB_USER →
        // InitResolved.default_user → passthroughfs's BindIdentityMap, for
        // bind-mounted file owner bits) — both calls are load-bearing, for
        // different reasons; neither is a substitute for the other. The PATH
        // override is the acquired image's resolved config value (#258).
        match sandbox
            .attach_with(cmd, |a| {
                a.args(shell_argv)
                    .cwd(project_guest_path.clone())
                    .user(exec_user.clone())
                    .env("PATH", exec_path.clone())
            })
            .await
        {
            Ok(code) => code,
            Err(error) => {
                let error = anyhow::Error::new(error);
                let primary = exec_failure_primary(
                    contract_spawn_diagnostic(&image, &error),
                    error.context(format!("attaching to {command_display}")),
                );
                return Err(finish_failed_exec(
                    &sandbox,
                    primary,
                    &sandbox_log_dir(&session.sandbox_name).display().to_string(),
                )
                .await);
            }
        }
    } else {
        // No host TTY (piped, redirected, smoke-tested under `sg`/`sudo` etc.).
        // attach() needs a real /dev/tty for raw-mode stdin, so use the
        // streaming exec API instead: write stdout/stderr to ours as they
        // arrive. That keeps progress visible on long-running agent
        // commands (codex exec can take >30s for a single response) and
        // lets us inspect partial output when the user Ctrl-Cs or the
        // shell times out.
        notices.emit(format!(
            "==> Running {command_display} in sandbox (no TTY; streaming output)"
        ))?;
        let handle = match sandbox
            .exec_stream_with(cmd, |e| {
                e.args(shell_argv)
                    .cwd(project_guest_path.clone())
                    .user(exec_user.clone())
                    .env("PATH", exec_path.clone())
            })
            .await
        {
            Ok(handle) => handle,
            Err(error) => {
                let error = anyhow::Error::new(error);
                let primary = exec_failure_primary(
                    contract_spawn_diagnostic(&image, &error),
                    error.context(format!("running {command_display} in sandbox")),
                );
                return Err(finish_failed_exec(
                    &sandbox,
                    primary,
                    &sandbox_log_dir(&session.sandbox_name).display().to_string(),
                )
                .await);
            }
        };
        let mut stdout = tokio::io::stdout();
        let mut stderr = tokio::io::stderr();
        // Race the exec event stream against the sandbox's own runtime exit
        // (issue #41): if the msb VMM child dies mid-session, the relay socket
        // closing should already end the event stream (`recv()` -> `None`), but
        // that relies on the SDK's reader loop observing the socket EOF promptly.
        // `sandbox.wait()` resolving first means the exec await can never hang on
        // a VMM that's already gone, no matter how the event stream behaves.
        let runtime_exit: RuntimeExit = Box::pin(sandbox.wait());
        stream_exec_with_cleanup(
            &sandbox,
            handle,
            runtime_exit,
            &mut stdout,
            &mut stderr,
            output_policy,
            ExecContext {
                image: &image,
                log_dir: &sandbox_log_dir(&session.sandbox_name).display().to_string(),
            },
        )
        .await?
    };

    if profile {
        notices.emit(format!("[profile] run:    {:?}", t_run.elapsed()))?;
    }

    notices.emit("==> Stopping sandbox")?;
    let t_stop = Instant::now();
    let cleanup = cleanup_exec_sandbox(&sandbox).await;
    if profile {
        notices.emit(format!("[profile] stop+remove: {:?}", t_stop.elapsed()))?;
    }
    cleanup_after_exit(inner_cmd, exit, cleanup)?;

    // Phase 5 safety net (host-cred mutation check) runs via the
    // SnapshotGuard above, which drops at end of scope including
    // any `?`-propagated error path.

    Ok(exit)
}

/// Who owns a guest stream sink failure.
///
/// The legacy sink deliberately swallows `write_all`/`flush` errors: a tool or
/// shell launch whose output pipe dies keeps reporting the guest's own status,
/// and this ticket must not change that. A direct launch checks both, because a
/// lost stdout is a launcher failure (125) there — the one deliberate,
/// local, regression-tested exception (#398).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutputErrorPolicy {
    LegacyBestEffort,
    DirectChecked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GuestStream {
    Stdout,
    Stderr,
}

impl GuestStream {
    fn name(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

/// Write then flush one event's bytes, in exactly the legacy order (both are
/// attempted even when the write fails). Never includes payload bytes in an
/// error: the guest decides what the stream contains.
async fn forward_stream_bytes(
    sink: &mut (impl tokio::io::AsyncWrite + Unpin),
    bytes: &[u8],
    stream: GuestStream,
    policy: OutputErrorPolicy,
) -> Result<()> {
    use tokio::io::AsyncWriteExt as _;
    let written = sink.write_all(bytes).await;
    let flushed = sink.flush().await;
    if policy == OutputErrorPolicy::LegacyBestEffort {
        return Ok(());
    }
    written.map_err(|error| anyhow::anyhow!("writing guest {} failed: {error}", stream.name()))?;
    flushed.map_err(|error| anyhow::anyhow!("flushing guest {} failed: {error}", stream.name()))?;
    Ok(())
}

/// The named launch context the exec lifecycle diagnostics are built from.
struct ExecContext<'a> {
    image: &'a str,
    log_dir: &'a str,
}

/// The exec lifecycle for a streamed (non-TTY) launch.
///
/// It **owns** the event handle and the pinned runtime wait future, borrows the
/// sinks, and returns the guest status or the primary failure. Both handles are
/// dropped unconditionally before teardown: the wait future may hold the
/// child-handle mutex, so a teardown that ran first would deadlock (#258).
async fn stream_exec_with_cleanup<T: ExecTeardown>(
    teardown: &T,
    mut handle: impl ExecEventSource,
    mut runtime_exit: RuntimeExit<'_>,
    stdout: &mut (impl tokio::io::AsyncWrite + Unpin),
    stderr: &mut (impl tokio::io::AsyncWrite + Unpin),
    policy: OutputErrorPolicy,
    context: ExecContext<'_>,
) -> Result<i32> {
    use microsandbox::sandbox::exec::ExecEvent;
    let stream_result: Result<i32> = loop {
        match next_exec_step(
            &mut handle,
            &mut runtime_exit,
            STREAM_END_RUNTIME_EXIT_GRACE,
        )
        .await
        {
            ExecStep::Event(ExecEvent::Stdout(bytes)) => {
                // Break through the loop result, never `?` out: the wait future
                // and handle must be dropped by this function before teardown.
                if let Err(primary) =
                    forward_stream_bytes(stdout, &bytes, GuestStream::Stdout, policy).await
                {
                    break Err(primary);
                }
            }
            ExecStep::Event(ExecEvent::Stderr(bytes)) => {
                // Break through the loop result, never `?` out: the wait future
                // and handle must be dropped by this function before teardown.
                if let Err(primary) =
                    forward_stream_bytes(stderr, &bytes, GuestStream::Stderr, policy).await
                {
                    break Err(primary);
                }
            }
            ExecStep::Event(ExecEvent::Exited { code }) => break Ok(code),
            ExecStep::Event(ExecEvent::Failed(payload)) => {
                // A contract breach (missing/unrunnable `bash`) becomes the
                // image diagnostic; anything else keeps an escaped message
                // rather than the Rust `Debug` dump of the payload (#258).
                break Err(exec_failure_primary(
                    image_contract::launch_shell_spawn_diagnostic(context.image, &payload),
                    anyhow::anyhow!(
                        "exec session failed: {}",
                        config::escape_str(&payload.message)
                    ),
                ));
            }
            ExecStep::Event(ExecEvent::Started { .. } | ExecEvent::StdinError(_)) => {}
            ExecStep::StreamEnded => {
                break Err(anyhow::anyhow!(
                    "exec session event stream ended without Exited (agentd disconnect or \
                     microsandbox bug; partial output above; full logs: {})",
                    context.log_dir
                ));
            }
            ExecStep::RuntimeExited(detail) => {
                break Err(anyhow::anyhow!(
                    "sandbox process exited unexpectedly while the exec stream was still \
                     open ({detail}); partial output above; see msb-exit.log under {} for \
                     the VMM's post-mortem record",
                    context.log_dir
                ));
            }
        }
    };
    // Cancels futures that may hold the child-handle mutex. Unconditional, and
    // before every streaming teardown path.
    drop(runtime_exit);
    drop(handle);
    match stream_result {
        Ok(code) => Ok(code),
        Err(primary) => Err(finish_failed_exec(teardown, primary, context.log_dir).await),
    }
}

/// The teardown operations the exec lifecycle performs.
///
/// A seam, not a new lifecycle: [`Sandbox`]'s adapter delegates to the current
/// SDK calls and keeps their error display, so a test can drive the *production*
/// failure schedule (stop/kill/reap/remove errors and timeouts) without a booted
/// VM or a fake `msb`. Bounded timeouts stay in
/// [`cleanup_exec_sandbox_failures`], the one owner of the order.
trait ExecTeardown: Sync {
    async fn stop_and_wait(&self) -> Result<()>;
    async fn kill_with_timeout(&self, timeout: Duration) -> Result<()>;
    async fn wait(&self) -> Result<()>;
    async fn remove(&self) -> Result<()>;
}

impl ExecTeardown for Sandbox {
    async fn stop_and_wait(&self) -> Result<()> {
        Sandbox::stop_and_wait(self)
            .await
            .map(|_| ())
            .map_err(anyhow::Error::new)
    }
    async fn kill_with_timeout(&self, timeout: Duration) -> Result<()> {
        Sandbox::kill_with_timeout(self, timeout)
            .await
            .map_err(anyhow::Error::new)
    }
    async fn wait(&self) -> Result<()> {
        Sandbox::wait(self)
            .await
            .map(|_| ())
            .map_err(anyhow::Error::new)
    }
    async fn remove(&self) -> Result<()> {
        Sandbox::remove(self.name())
            .await
            .map_err(anyhow::Error::new)
    }
}

/// Bounded teardown deadlines for the exec lifecycle. Named and local: a wedged
/// VMM must not hang the launcher, and a failed graceful stop must still reap
/// and remove rather than leaking a hidden VM (#258).
const EXEC_STOP_TIMEOUT: Duration = Duration::from_secs(10);
const EXEC_KILL_TIMEOUT: Duration = Duration::from_secs(5);
const EXEC_REAP_TIMEOUT: Duration = Duration::from_secs(5);
const EXEC_REMOVE_TIMEOUT: Duration = Duration::from_secs(5);

/// The image-contract diagnostic for an SDK exec error whose cause is a failed
/// spawn of the launch shell, or `None` when the failure is not the image's and
/// the caller's contextual error applies (#258).
fn contract_spawn_diagnostic(image: &str, error: &anyhow::Error) -> Option<String> {
    error.chain().find_map(|cause| {
        let microsandbox::MicrosandboxError::ExecFailed(failure) = cause.downcast_ref()? else {
            return None;
        };
        image_contract::launch_shell_spawn_diagnostic(image, failure)
    })
}

/// The primary failure for a launch whose exec setup or event stream failed:
/// the image-contract diagnostic when a failed spawn of the launch shell caused
/// it, otherwise the caller's contextual error. [`finish_failed_exec`] is the
/// single owner of the `(full logs: …)` suffix, so none is added here (#258).
fn exec_failure_primary(contract: Option<String>, fallback: anyhow::Error) -> anyhow::Error {
    match contract {
        Some(diagnostic) => anyhow::anyhow!("{diagnostic}"),
        None => fallback,
    }
}

/// Attempt every teardown step, collecting failures instead of swallowing them
/// (CODING_STANDARDS: errors are returned, not logged and ignored). The
/// graceful stop is tried first; only its failure escalates to a bounded
/// kill+reap. The sandbox is removed either way, so a failed launch never
/// leaves a hidden VM behind (#258).
async fn cleanup_exec_sandbox_failures(teardown: &impl ExecTeardown) -> Vec<String> {
    let mut failures: Vec<String> = Vec::new();
    let stopped = match tokio::time::timeout(EXEC_STOP_TIMEOUT, teardown.stop_and_wait()).await {
        Ok(Ok(_)) => true,
        Ok(Err(error)) => {
            failures.push(format!("stop: {error}"));
            false
        }
        Err(_) => {
            failures.push(format!("stop: timed out after {EXEC_STOP_TIMEOUT:?}"));
            false
        }
    };
    if !stopped {
        // Cancelling the timed-out stop future released the child-handle lock
        // before this kill/reap runs: the outer timeout on `kill_with_timeout`
        // bounds the dispatch itself, not just the kill it performs.
        match tokio::time::timeout(
            EXEC_KILL_TIMEOUT,
            teardown.kill_with_timeout(EXEC_KILL_TIMEOUT),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => failures.push(format!("kill: {error}")),
            Err(_) => failures.push(format!("kill: timed out after {EXEC_KILL_TIMEOUT:?}")),
        }
        // Reap even if the kill failed, so no wedged process is left owned.
        match tokio::time::timeout(EXEC_REAP_TIMEOUT, teardown.wait()).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => failures.push(format!("reap: {error}")),
            Err(_) => failures.push(format!("reap: timed out after {EXEC_REAP_TIMEOUT:?}")),
        }
    }
    match tokio::time::timeout(EXEC_REMOVE_TIMEOUT, teardown.remove()).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => failures.push(format!("remove: {error}")),
        Err(_) => failures.push(format!("remove: timed out after {EXEC_REMOVE_TIMEOUT:?}")),
    }
    failures
}

/// [`cleanup_exec_sandbox_failures`] as a `Result`: `Ok` only when every
/// teardown step succeeded, otherwise one error listing the failures in
/// operation order. A successful forced cleanup never hides a failed graceful
/// stop.
async fn cleanup_exec_sandbox(teardown: &impl ExecTeardown) -> anyhow::Result<()> {
    let failures = cleanup_exec_sandbox_failures(teardown).await;
    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("{}", failures.join("; ")))
    }
}

/// Apply the shared cleanup path after a **known** guest status: a teardown
/// failure is still an error (never a silent success), and it names the command
/// and the status the guest had already produced. Extracted so the cleanup
/// after a known exit is driven by the same code in tests as in a launch.
fn cleanup_after_exit(command: &str, exit: i32, cleanup: anyhow::Result<()>) -> anyhow::Result<()> {
    cleanup.map_err(|error| {
        error.context(format!(
            "guest command `{}` exited {exit}, but the sandbox could not be cleaned up",
            config::escape_str(command)
        ))
    })
}

/// Render a failed launch's teardown outcome. The primary contract diagnostic
/// stays first, teardown failures follow in operation order, and the log
/// directory is always named. Pure, so ordering and visibility are unit-tested
/// without a sandbox.
fn failed_exec_message(primary: &str, cleanup_failures: &[String], log_dir: &str) -> String {
    if cleanup_failures.is_empty() {
        format!("{primary} (full logs: {log_dir})")
    } else {
        format!(
            "{primary}; cleanup failed: {} (full logs: {log_dir})",
            cleanup_failures.join("; ")
        )
    }
}

/// Finish a failed exec by tearing the sandbox down and returning the primary
/// failure with any teardown failures **appended**: the contract breach stays
/// visible even when cleanup also fails (#258).
async fn finish_failed_exec(
    teardown: &impl ExecTeardown,
    primary: anyhow::Error,
    log_dir: &str,
) -> anyhow::Error {
    let failures = cleanup_exec_sandbox_failures(teardown).await;
    anyhow::anyhow!(
        "{}",
        failed_exec_message(&format!("{primary:#}"), &failures, log_dir)
    )
}

/// A pending [`Sandbox::wait`] call, boxed so `launch`'s streaming-exec
/// branch can hold it alongside an `ExecHandle` without threading a generic
/// parameter through the whole function. Borrows the `Sandbox` for `'a`
/// rather than requiring `'static`, since `sandbox.wait()` only borrows
/// `&self`.
type RuntimeExit<'a> = std::pin::Pin<
    Box<
        dyn std::future::Future<Output = microsandbox::MicrosandboxResult<std::process::ExitStatus>>
            + Send
            + 'a,
    >,
>;

/// One step of racing an exec event stream against the sandbox's own
/// runtime exit — see [`next_exec_step`].
#[derive(Debug)]
enum ExecStep {
    /// The event stream produced an event.
    Event(microsandbox::sandbox::exec::ExecEvent),
    /// The event stream ended (channel closed) without an `Exited` event.
    StreamEnded,
    /// The sandbox process exited while the event stream was still open.
    /// Carries a short diagnostic detail (exit status or wait error) for
    /// the caller to fold into its own error message.
    RuntimeExited(String),
}

/// Minimal seam over "the next exec event" so [`next_exec_step`] is
/// testable against a stub source instead of a real `ExecHandle` (which
/// requires a booted sandbox). Implemented for `ExecHandle` by delegating
/// to its inherent `recv` — the trait method is named the same so callers
/// don't need to think about which one they're using.
trait ExecEventSource {
    async fn recv(&mut self) -> Option<microsandbox::sandbox::exec::ExecEvent>;
}

impl ExecEventSource for microsandbox::sandbox::exec::ExecHandle {
    async fn recv(&mut self) -> Option<microsandbox::sandbox::exec::ExecEvent> {
        microsandbox::sandbox::exec::ExecHandle::recv(self).await
    }
}

/// How long [`next_exec_step`] waits for the in-flight `runtime_exit`
/// future to complete after it has already observed the exec stream close,
/// before giving up and reporting a plain [`ExecStep::StreamEnded`].
///
/// On a real VMM kill the relay socket EOFs essentially instantly, so the
/// stream close is observed first almost every time — `sandbox.wait()`
/// (which classifies the exit and writes `msb-exit.log`) needs a moment
/// longer to actually reap the child. `child_reaping.rs`'s
/// `killed_vmm_child_is_reaped_and_reported_not_blocked` confirmed this
/// resolves "promptly" against a real sandbox; this budget is comfortably
/// above that observed latency while staying well short of anything a
/// human at a CLI would call a hang. If the stream closed for some other
/// reason and the sandbox process is genuinely still alive, this bound is
/// what keeps `next_exec_step` from hanging on it.
const STREAM_END_RUNTIME_EXIT_GRACE: std::time::Duration = std::time::Duration::from_secs(3);

/// Format a resolved `runtime_exit` result into the short diagnostic detail
/// carried by [`ExecStep::RuntimeExited`].
fn describe_runtime_exit(
    result: microsandbox::MicrosandboxResult<std::process::ExitStatus>,
) -> String {
    match result {
        Ok(status) => format!("exit status: {status:?}"),
        Err(err) => format!("wait() failed: {err}"),
    }
}

/// Await the next exec event, racing it against `runtime_exit`.
///
/// This is the testable seam for issue #41's "never block forever on an
/// exited VMM" requirement: if the sandbox process dies while the exec
/// stream is still open (rather than the stream itself observing the
/// closed relay socket and ending on its own), this future resolves with
/// [`ExecStep::RuntimeExited`] instead of leaving the caller's `recv()`
/// pending indefinitely. `runtime_exit` must be pinned once by the caller
/// (via [`RuntimeExit`]) and reused across calls, mirroring the standard
/// `tokio::pin!`-a-long-lived-future-then-race-it-in-a-loop idiom — each
/// call here re-polls the *same* future rather than starting a fresh wait.
///
/// Follow-up fix: a plain `tokio::select!` between `events.recv()` and
/// `runtime_exit` has a real-world ordering bug. On an actual VMM kill, the
/// relay socket's EOF is observed by `events.recv() -> None` before
/// `sandbox.wait()` (backing `runtime_exit`) gets to complete — which means
/// `sandbox.wait()`'s exit classification, and the `msb-exit.log`
/// post-mortem write it performs, would never happen if we reported
/// `StreamEnded` right there (the still-in-flight `runtime_exit` future
/// would just be dropped by the caller). So when `events.recv()` resolves
/// to `None`, this function does *not* immediately report `StreamEnded`:
/// it first gives the already-in-flight `runtime_exit` future a bounded
/// ([`STREAM_END_RUNTIME_EXIT_GRACE`]) chance to finish, so the caller
/// reliably sees the classified [`ExecStep::RuntimeExited`] (and the log
/// write has reliably happened) instead of racing ahead of it. Only if
/// `runtime_exit` doesn't resolve within the grace window — i.e. the
/// stream closed for some reason other than the VMM dying — does this fall
/// back to `StreamEnded`, so a non-crash stream closure still can't hang.
async fn next_exec_step(
    events: &mut impl ExecEventSource,
    runtime_exit: &mut RuntimeExit<'_>,
    stream_end_grace: std::time::Duration,
) -> ExecStep {
    tokio::select! {
        event = events.recv() => match event {
            Some(event) => ExecStep::Event(event),
            None => match tokio::time::timeout(stream_end_grace, &mut *runtime_exit).await {
                Ok(result) => ExecStep::RuntimeExited(describe_runtime_exit(result)),
                Err(_) => ExecStep::StreamEnded,
            },
        },
        result = &mut *runtime_exit => ExecStep::RuntimeExited(describe_runtime_exit(result)),
    }
}

/// Best-effort hint at where msb writes a sandbox's per-launch
/// logs. The directory contains three files worth checking on a
/// failed launch:
///
/// - `runtime.log` — msb tracing + Rust panic from the sandbox
///   subprocess (vendor `vm.rs::setup_log_capture` redirects its
///   stderr here).
/// - `kernel.log` — kernel printk / early-init panic (vendor
///   `vm.rs::setup_kernel_log`).
/// - `boot-error.json` — structured cause when the VM fails to come
///   up far enough to write into the two above (vendor
///   `boot_error.rs` is the canonical source of "couldn't boot
///   because X").
///
/// Returning a *directory* rather than a single file lets the user
/// `ls` it and pick whichever is non-empty, instead of following a
/// `runtime.log` hint that's zero bytes on early-boot failures.
///
/// Resolution mostly matches upstream's
/// `microsandbox_utils::resolve_home()` (`$MSB_HOME` →
/// `$HOME/.microsandbox` → `./.microsandbox`), with one deliberate
/// difference: when both `MSB_HOME` and `HOME` are unset (cron,
/// systemd-unit-without-Environment=HOME, `env -i`) we canonicalize
/// the relative fallback against the current working directory so
/// the hint string is absolute. Upstream does the same lookup
/// inside the msb subprocess where CWD is more controlled; on the
/// launcher side, embedding `./.microsandbox` in a user-facing
/// error message rendered far from where the launcher ran is
/// confusing.
fn sandbox_log_dir(sandbox_name: &str) -> PathBuf {
    microsandbox_sandboxes_root()
        .join(sandbox_name)
        .join("logs")
}

/// `$MSB_HOME/sandboxes` (resolved through the same ladder as
/// [`sandbox_log_dir`]). Holds one subdirectory per sandbox that
/// microsandbox materialized — including the `upper.ext4` overlay,
/// `logs/`, and other on-disk state.
fn microsandbox_sandboxes_root() -> PathBuf {
    let home = env::var_os("MSB_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|h| PathBuf::from(h).join(".microsandbox")))
        .unwrap_or_else(|| {
            env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(".microsandbox")
        });
    home.join("sandboxes")
}

/// Best-effort GC of orphan sandbox dirs from earlier crashed launches
/// in this same project (matching name prefix `agent-vm-<hash>-`).
///
/// The Sandbox name now carries the launcher's PID (see
/// [`crate::session::ProjectSession`]) so two concurrent invocations
/// don't collide — but the previous deterministic name doubled as
/// implicit garbage collection: the next launch's `.replace()` would
/// stop+kill any leftover same-name sandbox and unlink its on-disk
/// state. With per-launch names that GC never fires; if a launcher
/// crashes between `Sandbox::create` and the cleanup `Sandbox::remove`
/// at the end of [`launch`], its `~/.microsandbox/sandboxes/agent-vm-
/// <hash>-<pid>/` (overlay + logs + DB row) leaks forever. We reap
/// those here.
///
/// Safety: we only remove entries whose PID is *not currently alive*
/// (checked via `/proc/<pid>`), so a peer launcher running right now —
/// the very case this PR enables — is never touched. The reap also
/// proactively clears any stale entry whose PID we're about to reuse
/// ourselves: otherwise `Sandbox::create` would fail with "already
/// exists" because we dropped `.replace()`. PID reuse for our own
/// `process::id()` is rare but not impossible after enough crashed
/// launches accumulate.
async fn reap_stale_project_sandboxes(project_hash: &str) {
    let root = microsandbox_sandboxes_root();
    let entries = match std::fs::read_dir(&root) {
        Ok(e) => e,
        Err(_) => return, // no microsandbox home yet — nothing to reap
    };
    let prefix = format!("agent-vm-{project_hash}-");
    for entry in entries.flatten() {
        let name_os = entry.file_name();
        let name = match name_os.to_str() {
            Some(s) => s,
            None => continue,
        };
        let pid_str = match name.strip_prefix(&prefix) {
            Some(s) => s,
            None => continue,
        };
        let pid: u32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        if pid_alive(pid) {
            // Either a peer launcher running right now, or — if it's
            // our own PID — we're about to claim the same name and
            // `Sandbox::remove` would destroy what we're booting.
            continue;
        }
        // Best-effort. `Sandbox::remove` handles "doesn't exist in DB
        // but dir present" by still removing the dir; conversely if
        // it's gone from disk but a DB row lingers it cleans that too.
        // Either way, errors here are not fatal: worst case the user
        // sees the dir again next launch.
        let _ = microsandbox::Sandbox::remove(name).await;
    }
}

fn pid_alive(pid: u32) -> bool {
    // /proc/<pid> exists iff a process with that PID is currently
    // alive. We don't try to disambiguate "alive but a different
    // program reusing this PID" — if /proc/<pid> exists we conservatively
    // skip the reap. The cost of leaving one stale dir until the
    // process exits is small compared to the cost of nuking an
    // unrelated process's sandbox.
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

/// Build the GitHub repo allow-list by scanning `project_dir` and
/// each `extra_mount_dir` for:
///   * every `git remote -v` URL that points at github.com,
///   * every github.com URL listed in that dir's `.gitmodules`.
///
/// Matches main-branch claude-vm.sh:1463-1514 — without this,
/// `git push` from inside a submodule (or a mounted sibling repo)
/// would hit api.github.com anonymous and 401.
///
/// Failure modes (not a repo, no `.gitmodules`, non-github remote)
/// just contribute nothing — caller passes `--repo` to widen.
fn detect_github_repos<'a>(
    project_dir: &Path,
    extra_mount_roots: impl IntoIterator<Item = &'a mount::RepoScanRoot>,
) -> Vec<String> {
    let mut slugs: Vec<String> = Vec::new();
    scan_dir_for_github_slugs(project_dir, &mut slugs);
    let project_canon = project_dir.canonicalize().ok();
    for root in extra_mount_roots {
        if let (Some(project), Ok(mounted)) = (project_canon.as_ref(), root.host.canonicalize())
            && &mounted == project
        {
            continue;
        }
        scan_dir_for_github_slugs(&root.host, &mut slugs);
    }
    slugs
}

/// Scan one directory: top-level remotes + one level of submodule
/// URLs in `.gitmodules`. Submodule scanning is shallow (matches
/// claude-vm.sh; recursing into each submodule's `.gitmodules`
/// would balloon scope and add little value in practice). Fork seed
/// omissions are physical content removal, so an excluded `.git` or
/// `.gitmodules` is simply absent from the committed `data` and cannot
/// contribute metadata; nothing here needs a logical exclusion filter.
fn scan_dir_for_github_slugs(dir: &Path, out: &mut Vec<String>) {
    for slug in parse_dir_remote_github_slugs(dir) {
        push_slug_unique(out, slug);
    }
    for slug in parse_gitmodules_github_slugs(dir) {
        push_slug_unique(out, slug);
    }
}

fn push_slug_unique(out: &mut Vec<String>, slug: String) {
    if !out.iter().any(|x| x.eq_ignore_ascii_case(&slug)) {
        out.push(slug);
    }
}

/// `git -C <dir> remote -v` → github slugs. Hardened against a
/// hostile cwd that might define core.fsmonitor / aliases (review
/// #6): the user may have just cloned a project they don't fully
/// trust; running git in that repo before we've even built the
/// sandbox would otherwise honour repo-local hooks — host RCE
/// pre-sandbox. Disable the dangerous knobs and force
/// safe.directory so we don't fail closed on a foreign-UID
/// checkout. (Note: `-c include.path=` isn't valid git syntax;
/// includeIf/include are only honored from files git already
/// decides to read, which `-c` flags can't suppress in 2.x, so we
/// rely on disabling the per-repo *execution* hooks below.)
fn parse_dir_remote_github_slugs(dir: &Path) -> Vec<String> {
    let out = std::process::Command::new("git")
        .args(safe_git_config_flags())
        .args(["-C"])
        .arg(dir)
        .args(["remote", "-v"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        // Refuse host-level git config so a $GIT_CONFIG_GLOBAL
        // override (env injected by the user shell) can't sneak past
        // the `-c` overrides above. The empty values turn into a
        // non-existent path lookup, which git treats as missing.
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output();
    let out = match out {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut slugs: Vec<String> = Vec::new();
    for line in text.lines() {
        // line format: "<name>\t<url> (<fetch|push>)"
        let url = match line.split_ascii_whitespace().nth(1) {
            Some(u) => u,
            None => continue,
        };
        if let Some(slug) = parse_github_slug(url)
            && !slugs.iter().any(|s| s.eq_ignore_ascii_case(&slug))
        {
            slugs.push(slug);
        }
    }
    slugs
}

/// Parse `.gitmodules` (INI-style) via `git config -f` — using git
/// itself avoids reinventing an INI parser AND inherits the same
/// safe.directory / fsmonitor neutralization. `-f <path>` reads
/// ONLY that file (no chdir into the repo), so repo-local hooks
/// can't fire.
fn parse_gitmodules_github_slugs(dir: &Path) -> Vec<String> {
    let gitmodules = dir.join(".gitmodules");
    // `symlink_metadata` (vs `is_file`/`metadata`) deliberately does
    // NOT follow symlinks. A hostile checkout containing
    // `.gitmodules -> ~/.config/git/config` (or any out-of-tree path)
    // would otherwise route the parse at an unrelated host file —
    // and any stale `submodule.*.url` entries leaking out of it
    // would silently widen this launch's GitHub scope. The
    // legitimate `.gitmodules` is always a regular file.
    match std::fs::symlink_metadata(&gitmodules) {
        Ok(m) if m.is_file() => {}
        _ => return Vec::new(),
    }
    let out = std::process::Command::new("git")
        .args(safe_git_config_flags())
        .args(["config", "-f"])
        .arg(&gitmodules)
        .args(["--get-regexp", r"^submodule\..*\.url$"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output();
    let out = match out {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut slugs: Vec<String> = Vec::new();
    for line in text.lines() {
        // line format: "submodule.<name>.url <url>"
        let url = match line.split_ascii_whitespace().nth(1) {
            Some(u) => u,
            None => continue,
        };
        if let Some(slug) = parse_github_slug(url) {
            slugs.push(slug);
        }
    }
    slugs
}

/// `-c` flags reused by every git invocation we make on
/// possibly-untrusted host paths. Keeps the hardening identical
/// across remote/submodule scans.
fn safe_git_config_flags() -> [&'static str; 12] {
    [
        // Disable repo-local config that runs binaries:
        "-c",
        "core.fsmonitor=",
        "-c",
        "core.fsmonitorHookVersion=",
        // Editor/pager fall back to cat — nothing we run here
        // needs them but a repo `core.pager = !bad-script` would
        // otherwise fire on output paging.
        "-c",
        "core.pager=cat",
        "-c",
        "core.editor=:",
        // Trust the dir even if owned by another UID (we only read).
        "-c",
        "safe.directory=*",
        // Don't fetch anything across this invocation.
        "-c",
        "protocol.allow=never",
    ]
}

/// Pull `owner/repo` from a GitHub remote URL. Returns `None` for
/// non-GitHub URLs. Strips a trailing `.git`. Handles both:
/// - `https://github.com/owner/repo[.git]`
/// - `git@github.com:owner/repo[.git]`
/// - `ssh://git@github.com/owner/repo[.git]`
fn parse_github_slug(url: &str) -> Option<String> {
    let rest = if let Some(r) = url.strip_prefix("https://github.com/") {
        r
    } else if let Some(r) = url.strip_prefix("http://github.com/") {
        r
    } else if let Some(r) = url.strip_prefix("git@github.com:") {
        r
    } else if let Some(r) = url.strip_prefix("ssh://git@github.com/") {
        r
    } else {
        let r = url.strip_prefix("ssh://git@github.com:")?;
        // some hosts include a port-style colon; strip until next /
        r.split_once('/').map(|(_, p)| p)?
    };
    let trimmed = rest.trim_end_matches('/');
    let mut parts = trimmed.split('/');
    let owner = parts.next()?;
    let repo_raw = parts.next()?;
    if owner.is_empty() || repo_raw.is_empty() {
        return None;
    }
    // Strip exactly ONE trailing `.git` (the git URL convention).
    // `trim_end_matches` here would be greedy — `repo.git.git`
    // would round-trip as `repo` and miss the actual repo name.
    let repo = repo_raw.strip_suffix(".git").unwrap_or(repo_raw);
    if repo.is_empty() {
        return None;
    }
    // Reject path-traversal-shaped segments. A URL like
    // `https://github.com/../attacker/repo` would otherwise yield
    // the bogus slug `"../attacker"`, which the intercept hook's
    // path-traversal guard already drops — but it still pollutes
    // the `==> GitHub repo scope` summary and the `--allowed-repo`
    // argv with junk that masks malicious .gitmodules entries.
    if matches!(owner, "." | "..") || matches!(repo, "." | "..") {
        return None;
    }
    Some(format!("{owner}/{repo}"))
}

/// Bash snippet (one logical line) that removes **only** IPv6 `nameserver`
/// entries from the guest's `/etc/resolv.conf`.
///
/// microsandbox's agentd writes both an IPv4 and an IPv6 gateway-DNS
/// `nameserver` line at boot. The IPv6 entry is unresponsive in at least
/// one nested-libkrun config (the gateway times out on v6 DNS queries —
/// PLAN.md item B3 / upstream microsandbox issue #5). glibc's
/// `getaddrinfo` quietly falls through to the working v4 server, but a
/// strict async resolver (codex's hickory) returns `EAI_AGAIN`
/// ("Try again") and hangs at startup with "failed to lookup address
/// information", even though `getent hosts <host>` resolves instantly.
///
/// The sed address `/^nameserver .*:/` deletes a line iff it starts with
/// `nameserver ` *and* its value contains a colon. Every IPv6 literal
/// contains a colon; no IPv4 dotted-quad does — so v4 `nameserver` lines,
/// `# comments` (the `^nameserver` anchor won't match a leading `#`),
/// `search` and `options` lines are all left intact. `2>/dev/null
/// || true` keeps a read-only or absent resolv.conf from aborting the
/// prelude.
///
/// This is the cheaper of the two B3 options: a microsandbox-side
/// `network.dns(disable_ipv6)` knob would mean a submodule change to
/// agentd's resolv.conf writer; stripping one line in the launcher
/// prelude is self-contained and has no upstream-merge dependency.
const STRIP_IPV6_NAMESERVERS: &str =
    "sed -i '/^nameserver .*:/d' /etc/resolv.conf 2>/dev/null || true";

/// Run the image's seed entry points. A tool layer that bakes state which the
/// guest's runtime persistence symlinks would shadow (the claude LSP plugin tree
/// under `~/.claude`, whose symlink into the state dir hides it) drops an
/// executable under `/opt/agent-vm/seed.d/`; the claude tool layer installs
/// `10-claude-plugins` there. Tool-agnostic by design: the launcher names no
/// tool (epic #78), and an image that supplies neither entry point runs nothing.
///
/// Both clauses are optional image content, not lineage or migration promises:
/// the `seed.d/*` loop and the named `/opt/agent-vm/seed-claude-plugins.sh`
/// script run on **every** launch (the latter executes after the loop, so an
/// image may supply either or both). Each hook must therefore be idempotent —
/// it is re-run on every boot — and both are inert when absent.
const RUN_IMAGE_SEED_HOOKS: &str = concat!(
    "for _h in /opt/agent-vm/seed.d/*; do [ -x \"$_h\" ] && \"$_h\"; done\n",
    "[ -x /opt/agent-vm/seed-claude-plugins.sh ] && /opt/agent-vm/seed-claude-plugins.sh",
    "; true",
);

/// The guest command line: the tool's default argv (minus any flag the user
/// already passed), then the tool arguments — or, for an interactive shell, a
/// single `-c` with those args joined and escaped.
///
/// Pure and string-only so the seven default tools' guest command lines are
/// unit-tested without booting, mirroring [`AgentShellLine`] below.
/// This is the *only* oracle for "identical to `main`": the guest command
/// line travels over the exec request after boot and never appears in the
/// `SandboxConfig` an integration test can observe (see the
/// `[debug] guest command:` line in `launch`).
///
/// The `argv` values' "why" lives beside them in `default-tools.toml`; the
/// filter here is the one rule that belongs to the launch path rather than the
/// catalogue: a default flag the user already passed is not duplicated.
pub(crate) fn inner_argv(tool: &Tool, tool_args: Vec<String>) -> Vec<String> {
    let mut inner_args: Vec<String> = tool
        .argv()
        .iter()
        .filter(|default| !tool_args.iter().any(|user| user == *default))
        .map(|argument| argument.to_string())
        .collect();
    if tool.is_interactive_shell() && !tool_args.is_empty() {
        // `agent-vm shell foo bar` runs `foo bar` as a command. Without `-c`,
        // bash treats the first non-option positional as a script filename and
        // PATH-searches for it, so `agent-vm shell ls` lands on `/usr/bin/ls`
        // and prints "cannot execute binary file" the moment bash hits the ELF
        // magic. Joining the user's args into a single `-c` command line (each
        // arg shell-escaped so quoting is preserved across the boundary) is
        // the standard fix.
        let cmd = tool_args
            .iter()
            .map(|a| shell_escape(a))
            .collect::<Vec<_>>()
            .join(" ");
        inner_args.push("-c".into());
        inner_args.push(cmd);
    } else {
        inner_args.extend(tool_args);
    }
    inner_args
}

/// The in-guest `bash -c` line: the prelude (IPv6-nameserver strip, seed
/// entry points, stdin redirect, project runtime hook), then the selected
/// program's presence guard, then `exec` of that program with its args. Pure
/// and string-only so it can be unit-tested without booting a sandbox — the
/// launch path renders exactly this, so the tested behavior and the live
/// behavior cannot drift.
///
/// Fields are named because all four are strings: a positional call would be
/// easy to transpose invisibly (#258).
struct AgentShellLine<'a> {
    project_guest_path: &'a str,
    image: &'a str,
    command: &'a str,
    args: &'a [String],
    guard: ProgramGuard,
}

impl AgentShellLine<'_> {
    /// Prelude, guard, then `exec` with the configured argv.
    fn render(&self) -> String {
        let path = shell_escape(self.project_guest_path);
        let prelude = format!(
            "{STRIP_IPV6_NAMESERVERS}\n\
             {RUN_IMAGE_SEED_HOOKS}\n\
             [ -t 0 ] || exec < /dev/null\n\
             _hook={path}/.agent-vm.runtime.sh\n\
             if [ -f \"$_hook\" ]; then\n\
             \techo \"==> sourcing $_hook\" >&2\n\
             \tcd {path} && . \"$_hook\" || {{ rc=$?; echo \"==> .agent-vm.runtime.sh failed (exit $rc)\" >&2; exit $rc; }}\n\
             fi",
        );
        let mut shell_line = prelude;
        shell_line.push('\n');
        shell_line.push_str(&self.program_guard());
        shell_line.push_str(&self.exec_line());
        shell_line
    }

    /// The final `exec` of the configured command and argv. Split from
    /// [`Self::render`] so tests can run the guard and this `exec` against a
    /// real `/bin/bash` without the prelude editing the host's
    /// `/etc/resolv.conf` (#258).
    fn exec_line(&self) -> String {
        let mut out = String::from("; exec -- ");
        out.push_str(&shell_escape(self.command));
        for a in self.args {
            out.push(' ');
            out.push_str(&shell_escape(a));
        }
        out
    }

    /// The external-program presence guard, placed **after** the project
    /// runtime hook so a hook's `PATH` export counts, and immediately before
    /// `exec`. `builtin type -P` searches the external `PATH` only — never a
    /// function, alias or builtin — and the slash branch covers an
    /// absolute/relative configured pathname (including spaces). A program that
    /// is missing, not a regular file, or not executable by this guest user
    /// exits through the normal teardown with the contract message and
    /// [`image_contract::MISSING_PROGRAM_EXIT`] (#258).
    fn program_guard(&self) -> String {
        match self.guard {
            ProgramGuard::ImageContract => self.image_contract_guard(),
            ProgramGuard::Direct => self.direct_guard(),
        }
    }

    /// Direct-launch guard: a real `PATH` search after the hook, keeping the
    /// looked-up pathname bytes intact, then 127 (not found) versus 126 (found
    /// but not executable).
    ///
    /// Clearing the hash is the first line deliberately. `type -P` answers from
    /// the hash table without consulting `PATH`, and the seed/project hooks run
    /// before this guard, so a hook that hashed a pathname and then moved,
    /// removed or `hash -p`-overrode it would otherwise look missing (127) or
    /// directory-replaced (126) although the effective `PATH` has the program.
    /// No second clear is needed: `type -P` does not populate the table and only
    /// builtins run before `exec`, which repeats the same search. `|| builtin :`
    /// discards `hash -r`'s one failure mode — a hook's `set +h`, where the table
    /// is ignored anyway — because a hook's `set -e` would otherwise abort with a
    /// bare status 1 and no direct diagnostic.
    fn direct_guard(&self) -> String {
        let command = shell_escape(self.command);
        let not_found = shell_escape(&format!(
            "agent-vm: executable not found: {}",
            config::escape_str(self.command)
        ));
        let not_executable = shell_escape(&format!(
            "agent-vm: not executable: {}",
            config::escape_str(self.command)
        ));
        format!(
            "builtin hash -r 2>/dev/null || builtin :\n\
             _avm_command={command}\n\
             _avm_external=\n\
             _avm_lookup_status=0\n\
             case \"$_avm_command\" in\n\
             \t*/*) _avm_external=$_avm_command ;;\n\
             \t*)\n\
             \t\tif _avm_external=$(\n\
             \t\t\tbuiltin type -P -- \"$_avm_command\"\n\
             \t\t\t_avm_status=$?\n\
             \t\t\tbuiltin printf '.'\n\
             \t\t\texit \"$_avm_status\"\n\
             \t\t); then _avm_lookup_status=0; else _avm_lookup_status=$?; fi\n\
             \t\t_avm_external=${{_avm_external%.}}\n\
             \t\t_avm_external=${{_avm_external%$'\\n'}}\n\
             \t\t;;\n\
             esac\n\
             if [ \"$_avm_lookup_status\" -ne 0 ] || [ -z \"$_avm_external\" ] || [ ! -e \"$_avm_external\" ]; then\n\
             \tbuiltin printf '%s\\n' {not_found} >&2\n\
             \texit {missing}\n\
             fi\n\
             if [ -d \"$_avm_external\" ] || [ ! -x \"$_avm_external\" ]; then\n\
             \tbuiltin printf '%s\\n' {not_executable} >&2\n\
             \texit {unrunnable}\n\
             fi\n\
             unset _avm_command _avm_external _avm_lookup_status",
            missing = crate::launch_target::DIRECT_NOT_FOUND_EXIT,
            unrunnable = crate::launch_target::DIRECT_NOT_EXECUTABLE_EXIT,
        )
    }

    fn image_contract_guard(&self) -> String {
        let command = shell_escape(self.command);
        let message = shell_escape(&image_contract::missing_program_message(
            self.image,
            self.command,
        ));
        format!(
            "_avm_command={command}\n\
             _avm_external=\n\
             case \"$_avm_command\" in\n\
             \t*/*) _avm_external=$_avm_command ;;\n\
             \t*) _avm_external=$(builtin type -P -- \"$_avm_command\") || _avm_external= ;;\n\
             esac\n\
             if [ -z \"$_avm_external\" ] || [ ! -f \"$_avm_external\" ] || [ ! -x \"$_avm_external\" ]; then\n\
             \tprintf '%s\\n' {message} >&2\n\
             \texit {exit}\n\
             fi\n\
             builtin hash -r\n\
             unset _avm_command _avm_external",
            exit = image_contract::MISSING_PROGRAM_EXIT,
        )
    }
}

/// Single-quote `s` for use as a single argv element in a `bash -c`
/// line. Embedded single quotes are split out with the standard
/// `'\''` trick. Adequate for forwarding arbitrary user-supplied agent
/// args through the resolv.conf prelude wrapper.
fn shell_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

// Keep home selection in the same constructor exercised by the subprocess test:
// root mode must not discard raw HOME merely because Pi requires UTF-8.
fn launch_mount_context(
    mount_store: PathBuf,
    host_home: Option<PathBuf>,
    core_guest_mounts: Vec<PathBuf>,
    core_host_sources: Vec<CoreHostSource>,
    persisted_home: crate::guest_home::PersistedHome,
) -> Result<mount::MountContext> {
    let authority_home = config::host_home_dir().context("locating the authority home")?;
    Ok(mount::MountContext {
        mount_store,
        host_home,
        authority_home,
        account_home: user::account_home_dir(),
        core_guest_mounts,
        core_host_sources,
        persisted_home,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::write_executable;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[test]
    fn raw_authority_home_selected() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        let raw = PathBuf::from(OsString::from_vec(b"/agent-vm-m11a-home-\xff".to_vec()));
        assert!(raw.to_str().is_none());
        let mut child = Command::new(std::env::current_exe().unwrap())
            .env_clear()
            .env("HOME", raw.as_os_str())
            .env("AGENT_VM_M11A_CHILD", "1")
            .args([
                "--exact",
                "run::tests::authority_home_selection_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // The child emits only a bounded test report, below pipe capacity.
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("M11a child timed out");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "{:?}", out);
        assert!(String::from_utf8_lossy(&out.stdout).contains("M11A_RAW_AUTHORITY_HOME_OK"));
    }

    #[test]
    fn authority_home_selection_child() {
        use std::os::unix::ffi::OsStrExt;
        if std::env::var_os("AGENT_VM_M11A_CHILD").as_deref() != Some(std::ffi::OsStr::new("1")) {
            return;
        }
        assert!(user::resolve_guest_identity(true).unwrap().is_none());
        let context = launch_mount_context(
            PathBuf::from("/agent-vm-m11a-unused-store"),
            user::host_home_dir(),
            Vec::new(),
            Vec::new(),
            crate::guest_home::PersistedHome::none(),
        )
        .unwrap();
        let selected = context.authority_home.as_ref().expect("raw authority HOME");
        assert!(selected.to_str().is_none());
        assert_eq!(selected.as_os_str().as_bytes(), b"/agent-vm-m11a-home-\xff");
        assert_ne!(context.host_home.as_ref(), Some(selected));
        assert_ne!(context.account_home.as_ref(), Some(selected));
        println!("M11A_RAW_AUTHORITY_HOME_OK");
    }

    /// A real, empty `$HOME` shared by every test in this binary: `prepare`
    /// fails closed on a declared mount when `$HOME` is unset, and this is not
    /// what these tests exercise. With no `~/.pi` it yields
    /// `Severity::Advise` and no exposure for a source outside the home.
    fn test_home() -> PathBuf {
        static HOME: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
        HOME.get_or_init(|| tempfile::tempdir().unwrap())
            .path()
            .to_path_buf()
    }

    /// The seven compiled-in `default-tools.toml` tools, for the argv tests
    /// below. Parsed via the same validated path as user input.
    fn default_catalog() -> crate::config::LaunchCatalog {
        let dir = tempfile::tempdir().unwrap();
        crate::config::load(&crate::config::ConfigPaths {
            user: Some(dir.path().join("no-user-config.toml")),
            project: dir.path().join("no-project-config.toml"),
            home: None,
        })
        .expect("the embedded default catalog parses")
        .into_launch_catalog()
        .expect("the default catalog resolves")
    }

    fn tool<'a>(catalog: &'a crate::config::LaunchCatalog, name: &str) -> &'a Tool {
        catalog
            .as_slice()
            .iter()
            .find(|entry| entry.tool().name() == name)
            .unwrap()
            .tool()
    }

    /// **T2.** Differential characterization of [`inner_argv`] against the
    /// pre-#82 `run::launch` behaviour (`matches!(agent, Agent::Shell)` plus
    /// the "filter a default the user already passed" rule), transcribed by
    /// hand from `bb299d1` and covering both sides of the interactive-shell
    /// boundary. This is the unit-level oracle for "identical to `main`".
    #[test]
    fn inner_argv_matches_the_legacy_launch_behaviour() {
        let catalog = default_catalog();
        let args = |argv: &[&str]| argv.iter().map(|s| s.to_string()).collect::<Vec<_>>();

        // No user args: exactly command + default argv.
        for (name, expected) in [
            ("pi", vec![]),
            ("codex", vec![]),
            ("opencode", vec![]),
            ("claude", vec!["--dangerously-skip-permissions"]),
            ("copilot", vec!["--allow-all-tools"]),
            ("shell", vec!["-O", "histappend"]),
        ] {
            assert_eq!(
                inner_argv(tool(&catalog, name), vec![]),
                args(&expected),
                "{name}: no user args"
            );
        }

        // A non-shell tool appends the user's args verbatim.
        assert_eq!(
            inner_argv(tool(&catalog, "claude"), args(&["--model", "opus"])),
            args(&["--dangerously-skip-permissions", "--model", "opus"]),
        );

        // The asymmetric pair: the same user args on either side of the
        // `is_interactive_shell` boundary. Each shell arg is single-quoted, so
        // the joined `-c` line is `'ls' '-l'` (the pre-#82 behaviour).
        assert_eq!(
            inner_argv(tool(&catalog, "shell"), args(&["ls", "-l"])),
            args(&["-O", "histappend", "-c", "'ls' '-l'"]),
        );
        assert_eq!(
            inner_argv(tool(&catalog, "copilot"), args(&["ls", "-l"])),
            args(&["--allow-all-tools", "ls", "-l"]),
        );

        // A default flag the user already passed appears once, not twice.
        assert_eq!(
            inner_argv(
                tool(&catalog, "claude"),
                args(&["--dangerously-skip-permissions"]),
            ),
            args(&["--dangerously-skip-permissions"]),
        );

        // A shell with no user args does NOT join a `-c`.
        assert_eq!(
            inner_argv(tool(&catalog, "shell"), vec![]),
            args(&["-O", "histappend"]),
        );
    }

    /// V7 (#96): `pi` declares neither default `args` nor `credentials`, so a
    /// user subcommand stays at argv[1] and the launch cannot hard-bail on a
    /// missing credential. Adding `args = ["--approve"]` here would displace
    /// `list` and run an agent turn instead (ADR-0012, ADR-0021); this test
    /// exists so that regression cannot slip back in.
    #[test]
    fn pi_declares_no_args_and_no_credentials() {
        let catalog = default_catalog();
        let pi = tool(&catalog, "pi");
        assert!(pi.argv().is_empty(), "pi must declare no default args");
        assert!(
            pi.credentials().is_empty(),
            "pi must declare no credentials"
        );
        assert_eq!(
            pi.credential_providers(),
            crate::credential_provider::ProviderSet::new(std::iter::empty())
        );
        assert_eq!(
            inner_argv(pi, vec!["list".into()]),
            vec!["list".to_string()]
        );
    }

    /// The interactive-shell `-c` join shell-escapes each argument, so a
    /// quoted user command survives the boundary (the pre-#82 behaviour).
    #[test]
    fn inner_argv_shell_join_escapes_each_argument() {
        let catalog = default_catalog();
        let argv: Vec<String> = vec!["echo".into(), "a b".into(), "it's".into()];
        assert_eq!(
            inner_argv(tool(&catalog, "shell"), argv),
            vec![
                "-O".to_string(),
                "histappend".to_string(),
                "-c".to_string(),
                "'echo' 'a b' 'it'\\''s'".to_string(),
            ]
        );
    }

    // Test doubles for `LaunchNotices`' output seam (issue #70). One ordered
    // event log so "these bytes were delivered, in this step order" is asserted
    // directly rather than inferred from side effects. Test-local duplication of
    // the spirit of `network.rs`'s `SharedWriter`/`FailingWriter` — deliberate,
    // per CODING_STANDARDS' DRY note (wait for a third instance).
    #[derive(Debug, PartialEq, Eq)]
    enum NoticeIo {
        Wrote(String),
    }

    /// Collapses consecutive `Wrote` entries in `log`, concatenating their
    /// payloads, so a test can assert "these bytes were delivered, in this
    /// step order" without pinning how many `write()` calls the sink saw.
    /// The production sink (`write_all` on std's `Stderr`) makes one call,
    /// but `LaunchNotices`' `impl Write` bound makes no such promise for a
    /// future sink — asserting exact-call-count would couple the test to an
    /// implementation detail the acceptance criteria don't care about.
    fn folded_notice_log(log: &[NoticeIo]) -> Vec<NoticeIo> {
        let mut folded: Vec<NoticeIo> = Vec::new();
        for event in log {
            match (folded.last_mut(), event) {
                (Some(NoticeIo::Wrote(acc)), NoticeIo::Wrote(next)) => acc.push_str(next),
                (_, NoticeIo::Wrote(s)) => folded.push(NoticeIo::Wrote(s.clone())),
            }
        }
        folded
    }

    /// Which io step, if any, fails. `None` is the success path.
    #[derive(Clone, Copy)]
    enum Fault {
        None,
        Write,
    }

    struct ScriptedOutput {
        log: Rc<RefCell<Vec<NoticeIo>>>,
        fault: Fault,
    }

    impl std::io::Write for ScriptedOutput {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if matches!(self.fault, Fault::Write) {
                return Err(std::io::Error::other("broken output"));
            }
            self.log
                .borrow_mut()
                .push(NoticeIo::Wrote(String::from_utf8_lossy(bytes).into_owned()));
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    // Tests for `LaunchNotices::emit` (issue #70), reusing the output test
    // doubles above (D8: no new test-support module for a second consumer in
    // the same file).

    #[test]
    fn notice_is_delivered_as_one_write_without_a_flush() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let output = ScriptedOutput {
            log: log.clone(),
            fault: Fault::None,
        };
        let mut notices = LaunchNotices::new(output);
        notices.emit("==> hello").expect("scripted success");
        assert_eq!(
            folded_notice_log(&log.borrow()),
            vec![NoticeIo::Wrote("==> hello\n".to_string())],
            "one atomic write, no flush"
        );
    }

    #[test]
    fn notice_write_failure_is_propagated_with_the_line_in_context() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let output = ScriptedOutput {
            log: log.clone(),
            fault: Fault::Write,
        };
        let mut notices = LaunchNotices::new(output);
        let error = notices
            .emit("==> hello")
            .expect_err("write failure must propagate");
        let chain = format!("{error:#}");
        assert!(
            chain.contains("writing the launch notice \"==> hello\""),
            "chain: {chain}"
        );
        assert!(chain.contains("broken output"), "chain: {chain}");
    }

    #[test]
    fn notice_write_failure_propagates_a_multi_line_pi_warning() {
        // The launch warning is a multi-line string carried by one `emit`.
        // Its write failure must be the same contextual `Result`, not a panic
        // (the EPIPE/`head` case behind issue #70).
        let log = Rc::new(RefCell::new(Vec::new()));
        let output = ScriptedOutput {
            log: log.clone(),
            fault: Fault::Write,
        };
        let mut notices = LaunchNotices::new(output);
        let error = notices
            .emit("==> WARNING: potentially sensitive\n    auth.json: provider=anthropic")
            .expect_err("write failure must propagate");
        let chain = format!("{error:#}");
        assert!(
            chain.contains("writing the launch notice"),
            "chain: {chain}"
        );
        assert!(chain.contains("broken output"), "chain: {chain}");
    }

    #[test]
    fn notice_launch_banner_names_sandbox_project_and_state_dir() {
        let session = ProjectSession {
            project_dir: PathBuf::from("/home/dev/proj"),
            project_hash: "abc".to_string(),
            state_dir: PathBuf::from("/state/abc"),
            sandbox_name: "agent-vm-abc-42".to_string(),
        };
        assert_eq!(
            launch_banner(&session),
            "==> agent-vm-abc-42 in /home/dev/proj (state: /state/abc)"
        );
    }

    #[test]
    fn notice_repo_scope_lists_allowed_repos_or_reports_none() {
        assert_eq!(
            repo_scope_notice(&[]),
            "==> GitHub repo scope: <none> (no api.github.com access)"
        );
        assert_eq!(
            repo_scope_notice(&["a/b".to_string(), "c/d".to_string()]),
            "==> GitHub repo scope (2): a/b, c/d"
        );
    }

    #[test]
    fn notice_git_identity_renders_login_suffix_or_none() {
        assert_eq!(
            git_identity_notice(Some(&crate::secrets::HostGitIdentity {
                name: "Ada".to_string(),
                email: "ada@x".to_string(),
                gh_login: Some("ada".to_string()),
            })),
            "==> Git author identity: Ada <ada@x> (gh:ada)"
        );
        assert_eq!(
            git_identity_notice(Some(&crate::secrets::HostGitIdentity {
                name: "Ada".to_string(),
                email: "ada@x".to_string(),
                gh_login: None,
            })),
            "==> Git author identity: Ada <ada@x>"
        );
        assert_eq!(
            git_identity_notice(None),
            "==> Git author identity: <none> (gh not logged in and no host gitconfig \
             user.name/email; in-VM `git commit` will refuse until you set one)"
        );
    }

    #[test]
    fn notice_creds_lists_captured_providers_or_reports_none() {
        use crate::secrets::CredsState;
        use std::path::PathBuf;

        assert_eq!(
            creds_notice(&CredsState::default()),
            "==> Agent credentials: <none> (no host logins found)"
        );
        // Order is the fixed display order, not the order the fields were
        // populated in, so the line reads the same launch to launch.
        assert_eq!(
            creds_notice(&CredsState {
                gh_token_file: Some(PathBuf::from("/s/gh")),
                anthropic_token_file: Some(PathBuf::from("/s/anthropic")),
                ..CredsState::default()
            }),
            "==> Agent credentials: claude, gh"
        );
    }

    /// Head+tail source guard (D10): the launch path must contain no
    /// panicking `eprintln!`/`eprint!`/`println!`/`print!` call. `mod tests`
    /// opens at `#[cfg(test)]` and closes with the only column-0 `}` inside
    /// it (everything nested is indented), so locating that span isolates
    /// the test module from the production code that follows it in this
    /// file (see issue #70's plan D10; a prefix-only scan would miss these).
    /// Unlike an earlier version of this test, the scan below walks
    /// `src.lines().enumerate()` once directly — real 1-based line numbers
    /// throughout — and skips lines inside the test module's span, rather
    /// than concatenating head+tail into a separate buffer and reporting
    /// `line_no + 1` against *that* buffer's line numbers (which put every
    /// tail hit ~1245 lines too low, landing inside `mod tests`; issue #70
    /// code review finding F1).
    ///
    /// This split point is positional, not structural: if a future test
    /// literal inside `mod tests` ever introduces its own column-0 `}`, the
    /// `\n}\n` search below would match that line instead, shrinking the
    /// test module's computed span and leaving an in-test `eprintln!` in
    /// the scanned "production" text. That fails *loudly* (the guard then
    /// trips on the in-test call), not silently, so this fragility is safe
    /// to leave undefended.
    #[test]
    fn notice_production_launch_path_uses_no_panicking_print_macros() {
        let src = include_str!("run.rs");
        let cfg_test_offset = src.find("#[cfg(test)]").expect("run.rs has a test module");
        let after_cfg_test = &src[cfg_test_offset..];
        let close_offset_in_after = after_cfg_test.find("\n}\n").expect("test module is closed");
        // Byte offset of the `}` that closes `mod tests` (skip the leading
        // '\n' of the "\n}\n" match).
        let test_module_close_brace_offset = cfg_test_offset + close_offset_in_after + 1;
        let tail_start_offset = cfg_test_offset + close_offset_in_after + "\n}\n".len();
        let tail = &src[tail_start_offset..];
        assert!(
            !tail.contains("#[cfg(test)]"),
            "this guard assumes a single test module in run.rs"
        );

        fn line_number_at(src: &str, byte_offset: usize) -> usize {
            src[..byte_offset].matches('\n').count() + 1
        }
        // The test module's span, in real 1-based line numbers: from
        // `#[cfg(test)]` through the `}` that closes `mod tests`, inclusive.
        let test_module_start_line = line_number_at(src, cfg_test_offset);
        let test_module_end_line = line_number_at(src, test_module_close_brace_offset);

        // "eprintln!(" contains "println!(" and "eprint!(" contains
        // "print!(" (but "eprintln!(" does not contain "print!("), so all
        // four needles are checked, with "eprint" reported first when a
        // line matches more than one.
        for (idx, line) in src.lines().enumerate() {
            let line_no = idx + 1;
            if line_no >= test_module_start_line && line_no <= test_module_end_line {
                continue;
            }
            let hit = if line.contains("eprintln!(") {
                Some("eprintln!(")
            } else if line.contains("eprint!(") {
                Some("eprint!(")
            } else if line.contains("println!(") {
                Some("println!(")
            } else if line.contains("print!(") {
                Some("print!(")
            } else {
                None
            };
            assert!(
                hit.is_none(),
                "production run.rs:{} uses {} — route it through LaunchNotices \
                 instead (issue #70). line: {line:?}",
                line_no,
                hit.unwrap_or_default(),
            );
        }
    }

    /// Stub [`ExecEventSource`] backed by an mpsc channel: `send` pushes an
    /// event, holding the paired `Sender` alive keeps `recv()` pending
    /// (simulates an exec stream that's still open), and dropping it makes
    /// `recv()` return `None` (simulates the stream ending).
    struct StubEvents(tokio::sync::mpsc::Receiver<microsandbox::sandbox::exec::ExecEvent>);

    impl ExecEventSource for StubEvents {
        async fn recv(&mut self) -> Option<microsandbox::sandbox::exec::ExecEvent> {
            self.0.recv().await
        }
    }

    /// A `RuntimeExit` future that never resolves — models a sandbox process
    /// that is still running.
    fn runtime_never_exits<'a>() -> RuntimeExit<'a> {
        Box::pin(std::future::pending())
    }

    /// A `RuntimeExit` future that resolves immediately with a real
    /// `ExitStatus` — models the VMM child having already exited. Spawns a
    /// trivial OS process rather than fabricating an `ExitStatus`, since the
    /// type has no public constructor.
    fn runtime_exited_now<'a>(code: i32) -> RuntimeExit<'a> {
        Box::pin(async move {
            let status = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!("exit {code}"))
                .status()
                .expect("spawn stub exit process");
            Ok(status)
        })
    }

    #[tokio::test]
    async fn next_exec_step_returns_the_event_when_the_stream_has_one_and_runtime_is_still_alive() {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tx.send(microsandbox::sandbox::exec::ExecEvent::Exited { code: 0 })
            .await
            .unwrap();
        let mut events = StubEvents(rx);
        let mut runtime_exit = runtime_never_exits();

        let step = next_exec_step(
            &mut events,
            &mut runtime_exit,
            std::time::Duration::from_millis(50),
        )
        .await;

        assert!(matches!(
            step,
            ExecStep::Event(microsandbox::sandbox::exec::ExecEvent::Exited { code: 0 })
        ));
    }

    /// The stream closes and the sandbox process is (per `runtime_never_exits`)
    /// genuinely still alive — i.e. not the issue #41 VMM-kill shape. This
    /// must still fall back to `StreamEnded` once the bounded grace window
    /// elapses, rather than hanging on a `runtime_exit` that will never
    /// resolve.
    #[tokio::test]
    async fn next_exec_step_reports_stream_ended_when_the_channel_closes() {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        drop(tx);
        let mut events = StubEvents(rx);
        let mut runtime_exit = runtime_never_exits();

        let step = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            next_exec_step(
                &mut events,
                &mut runtime_exit,
                std::time::Duration::from_millis(50),
            ),
        )
        .await
        .expect(
            "next_exec_step hung instead of falling back to StreamEnded after the grace window",
        );

        assert!(matches!(step, ExecStep::StreamEnded));
    }

    /// Regression test for the follow-up fix to issue #41: on a real VMM
    /// kill, the exec stream's EOF (relay socket closing) is observed
    /// *before* `sandbox.wait()` gets a chance to complete and classify the
    /// exit — confirmed live against a real sandbox (verifications.md item
    /// 3: `events.recv() -> None` won this race 2/2 times against an actual
    /// `kill -KILL` of the VMM). `next_exec_step` must not report
    /// `StreamEnded` in that shape: it must give the already-in-flight
    /// `runtime_exit` future a bounded chance to finish so `sandbox.wait()`'s
    /// classification (and its `msb-exit.log` write) still happens, and
    /// report `RuntimeExited` instead.
    #[tokio::test]
    async fn next_exec_step_awaits_runtime_exit_when_stream_closes_first() {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        // The stream is already closed by the time next_exec_step is
        // called — models the relay EOF having already been observed.
        drop(tx);
        let mut events = StubEvents(rx);
        // `runtime_exit` is still in flight and resolves a little *after*
        // the stream close is observed — models `sandbox.wait()` completing
        // its reap/classification slightly behind the relay EOF, which is
        // exactly the ordering that was silently dropped before this fix.
        let mut runtime_exit: RuntimeExit = Box::pin(async {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            let status = std::process::Command::new("sh")
                .arg("-c")
                .arg("exit 1")
                .status()
                .expect("spawn stub exit process");
            Ok(status)
        });

        let step = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            next_exec_step(
                &mut events,
                &mut runtime_exit,
                std::time::Duration::from_millis(500),
            ),
        )
        .await
        .expect("next_exec_step hung waiting on the racing runtime exit");

        match step {
            ExecStep::RuntimeExited(detail) => {
                assert!(
                    detail.contains("exit status"),
                    "detail should name the exit status: {detail}"
                );
            }
            other => panic!(
                "expected RuntimeExited (runtime_exit should win once given its bounded grace \
                 window past the stream close), got {other:?} instead"
            ),
        }
    }

    /// The AC this seam exists for (issue #41): if the sandbox process exits
    /// while the exec stream is still open and never produces another
    /// event, `next_exec_step` must resolve with a diagnostic —  not hang
    /// forever waiting on `recv()`, and not silently report a `0` exit.
    #[tokio::test]
    async fn next_exec_step_surfaces_runtime_exit_instead_of_hanging_on_a_silent_stream() {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let mut events = StubEvents(rx);
        let mut runtime_exit = runtime_exited_now(17);

        let step = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            next_exec_step(
                &mut events,
                &mut runtime_exit,
                std::time::Duration::from_millis(500),
            ),
        )
        .await
        .expect("next_exec_step hung instead of observing the runtime exit");

        match step {
            ExecStep::RuntimeExited(detail) => {
                assert!(
                    detail.contains("exit status"),
                    "detail should name the exit status: {detail}"
                );
            }
            other => panic!("expected RuntimeExited, got a stream event/close instead: {other:?}"),
        }
        // Keep the sender alive for the whole test so a hang would show up
        // as a real timeout rather than an incidental `StreamEnded`.
        drop(tx);
    }

    /// Dropping the pending `runtime_exit` releases the child-handle lock it
    /// took on its first poll. The streaming branch relies on this ordering
    /// (drop before stop/wait) for **every** exit, including a `Failed` event —
    /// the old inner-`bail!` shape left the future alive and deadlocked teardown.
    /// Synthetic: it illustrates ownership, not SDK teardown.
    #[tokio::test]
    async fn dropping_the_pending_runtime_exit_releases_the_child_handle_lock() {
        use microsandbox::protocol::exec::{ExecFailed, ExecFailureKind};
        use microsandbox::sandbox::exec::ExecEvent;

        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let mut events = StubEvents(rx);

        let handle_lock = std::sync::Arc::new(tokio::sync::Mutex::new(()));
        let lock_for_future = handle_lock.clone();
        let mut runtime_exit: RuntimeExit = Box::pin(async move {
            // The first poll takes the lock, exactly as `sandbox.wait()` takes
            // the child-handle mutex once polled.
            let _guard = lock_for_future.lock().await;
            std::future::pending().await
        });

        // Force the first poll with no event available, so the lock is really
        // held (the select would otherwise be free to return the event without
        // ever polling the runtime future).
        let waited = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            next_exec_step(
                &mut events,
                &mut runtime_exit,
                std::time::Duration::from_millis(10),
            ),
        )
        .await;
        assert!(waited.is_err(), "nothing is ready, so the step must wait");

        tx.send(ExecEvent::Failed(ExecFailed {
            kind: ExecFailureKind::NotFound,
            errno: None,
            errno_name: None,
            message: "no bash".to_string(),
            stage: None,
        }))
        .await
        .unwrap();
        let step = next_exec_step(
            &mut events,
            &mut runtime_exit,
            std::time::Duration::from_millis(50),
        )
        .await;
        assert!(matches!(step, ExecStep::Event(ExecEvent::Failed(_))));

        // Drop unconditionally, as the launch branch does before teardown.
        drop(runtime_exit);
        let _released = tokio::time::timeout(std::time::Duration::from_secs(1), handle_lock.lock())
            .await
            .expect("the child-handle lock must be released once runtime_exit is dropped");
    }

    fn sandbox_config_with_env(env: Vec<(&str, &str)>) -> microsandbox::sandbox::SandboxConfig {
        let mut config = microsandbox::sandbox::SandboxConfig::default();
        config.spec.env = env
            .into_iter()
            .map(|(key, value)| microsandbox_types::EnvVar::new(key, value))
            .collect();
        config
    }

    /// The exec PATH is the acquired image's own value, including a nonstandard
    /// prefix and an explicitly empty value; only *absence* uses the fallback
    /// (#258).
    #[test]
    fn resolved_exec_path_prefers_the_image_value_and_falls_back_only_when_absent() {
        assert_eq!(
            resolved_exec_path(&sandbox_config_with_env(vec![(
                "PATH",
                "/opt/e2e-258/bin:/usr/bin:/bin"
            )])),
            "/opt/e2e-258/bin:/usr/bin:/bin"
        );
        assert_eq!(
            resolved_exec_path(&sandbox_config_with_env(vec![])),
            FALLBACK_GUEST_PATH
        );
        assert_eq!(
            resolved_exec_path(&sandbox_config_with_env(vec![("PATH", "")])),
            "",
            "an image that truly sets an empty PATH means it"
        );
        // Last wins, matching guest env's last-wins semantics.
        assert_eq!(
            resolved_exec_path(&sandbox_config_with_env(vec![
                ("PATH", "/first"),
                ("OTHER", "x"),
                ("PATH", "/last"),
            ])),
            "/last"
        );
    }

    #[test]
    fn root_flag_parses_via_clap() {
        let mut env = crate::test_env::guard();
        for name in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(name);
        }
        #[derive(clap::Parser)]
        struct TestCli {
            #[command(flatten)]
            args: Args,
        }
        use clap::Parser as _;

        let cli = TestCli::try_parse_from(["agent-vm"]).expect("parses with no flags");
        assert!(!cli.args.root);

        let cli = TestCli::try_parse_from(["agent-vm", "--root"]).expect("parses --root");
        assert!(cli.args.root);
    }

    /// Doc/help lockstep: the `Environment:` block's value-parsing rows
    /// must render the same set `env_flag::TRUTHY` actually accepts, or a
    /// future change to one and not the other would silently document a
    /// truthy set the binary doesn't implement (or vice versa).
    #[test]
    fn environment_help_block_lists_the_shared_truthy_set() {
        let rendered = format!("({})", crate::env_flag::TRUTHY.join("|"));
        let long_help = LAUNCH_OPTIONS_LONG_HELP;
        for var in ["AGENT_VM_ROOT", "AGENT_VM_INSECURE_REGISTRY"] {
            let line = long_help
                .lines()
                .find(|line| line.contains(var))
                .unwrap_or_else(|| panic!("{var} missing from launch_after_long_help"));
            assert!(
                line.contains(&rendered),
                "{var}'s help line {line:?} does not list env_flag::TRUTHY ({rendered})"
            );
        }
    }

    #[test]
    fn launch_applies_base_network_then_credential_network_before_boot() {
        // `launch` has boot-heavy dependencies, so keep this caller-level
        // characterization at the orchestration boundary. The Plan tests own
        // behavior; this prevents a future reorder from dropping the
        // credential overlay or applying it before the base network plan.
        // Limit the source characterization to production code. Searching the
        // complete `include_str!` would let these test literals satisfy their
        // own assertions if a lifecycle call were removed from `launch`.
        let production = include_str!("run.rs")
            .split_once("#[cfg(test)]")
            .expect("run.rs has a test module")
            .0;
        let position = |needle| production.find(needle).expect("launch step is present");
        let plan = position(
            "let network_plan = crate::network::Plan::from_args(args.network, user_network)?;",
        );
        let notices = position(".emit_launch_notices()");
        let base_network = position("builder = network_plan.apply_to(builder);");
        let credential_network = position("builder = credential_plan.apply_to(builder)?;");
        let build = position("let config = builder.build().await");
        let create = position("Sandbox::create_with_pull_progress(config)");
        assert!(plan < position("mount::prepare("));
        assert!(plan < position("ensure_msb_home("));
        assert!(plan < notices);
        let report = position("network_plan\n            .request_report(");
        assert!(notices < report && report < base_network);
        assert!(base_network < credential_network);
        assert!(credential_network < build);
        assert!(build < create);
    }

    #[test]
    fn flattened_network_args_preserve_values_and_defaults() {
        let mut env = crate::test_env::guard();
        for name in ["AGENT_VM_MEMORY_GIB", "AGENT_VM_CPUS", "AGENT_VM_IMAGE_TAG"] {
            env.remove_var(name);
        }
        #[derive(clap::Parser)]
        struct TestCli {
            #[command(flatten)]
            args: Args,
        }
        use clap::Parser as _;

        let defaults = TestCli::try_parse_from(["agent-vm"]).expect("default launch args parse");
        assert!(defaults.args.network.publish.is_empty());
        assert!(!defaults.args.network.auto_publish);
        assert!(defaults.args.network.allow_egress.is_empty());
        assert_eq!(defaults.args.network.allow_internet_egress, None);
        assert_eq!(defaults.args.network.allow_lan, None);
        assert_eq!(defaults.args.network.allow_host, None);

        let parsed = TestCli::try_parse_from([
            "agent-vm",
            "-p",
            "8080:3000",
            "--publish",
            "8081:3001",
            "--auto-publish",
            "--allow-egress",
            "10.0.0.5",
            "--allow-egress",
            "fd00::1",
            "--allow-lan",
            "--allow-host",
        ])
        .expect("all network launch options parse");
        assert_eq!(parsed.args.network.publish, ["8080:3000", "8081:3001"]);
        assert!(parsed.args.network.auto_publish);
        assert_eq!(parsed.args.network.allow_egress, ["10.0.0.5", "fd00::1"]);
        assert_eq!(parsed.args.network.allow_lan, Some(true));
        assert_eq!(parsed.args.network.allow_host, Some(true));
        let explicit = TestCli::try_parse_from([
            "agent-vm",
            "--allow-internet-egress",
            "--allow-lan=false",
            "--allow-host=true",
            "--allow-egress",
            "tcp://[10.0.0.0/24]:22",
        ])
        .unwrap();
        assert_eq!(explicit.args.network.allow_internet_egress, Some(true));
        assert_eq!(explicit.args.network.allow_lan, Some(false));
        assert_eq!(explicit.args.network.allow_host, Some(true));
        assert_eq!(
            explicit.args.network.allow_egress,
            ["tcp://[10.0.0.0/24]:22"]
        );
        assert!(TestCli::try_parse_from(["agent-vm", "--allow-lan", "false"]).is_err());
        assert!(TestCli::try_parse_from(["agent-vm", "--allow-lan=maybe"]).is_err());
        assert_eq!(
            TestCli::try_parse_from(["agent-vm", "--allow-lan", "--allow-lan=false"])
                .err()
                .unwrap()
                .kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
    }

    #[test]
    fn non_interactive_tool_appends_tool_arguments_verbatim() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("config.toml");
        std::fs::write(
            &project,
            include_str!("../../../script/test/fixtures/egress-config.toml"),
        )
        .unwrap();
        let catalog = crate::config::load(&crate::config::ConfigPaths {
            user: None,
            project,

            home: None,
        })
        .unwrap()
        .into_launch_catalog()
        .unwrap();
        assert_eq!(
            inner_argv(
                tool(&catalog, "egressprobe"),
                vec!["D1".into(), "id-1".into()]
            ),
            ["./egress-probe.sh", "D1", "id-1"]
        );
    }

    #[test]
    fn interactive_shell_turns_dash_c_into_a_literal_command_word() {
        let catalog = default_catalog();
        assert_eq!(
            inner_argv(tool(&catalog, "shell"), vec!["-c".into(), "echo hi".into()]),
            ["-O", "histappend", "-c", "'-c' 'echo hi'"]
        );
    }

    #[test]
    fn shell_escape_handles_simple_and_quoted() {
        assert_eq!(shell_escape("foo"), "'foo'");
        assert_eq!(
            shell_escape("--flag=value with spaces"),
            "'--flag=value with spaces'"
        );
        assert_eq!(shell_escape("don't"), "'don'\\''t'");
        assert_eq!(shell_escape(""), "''");
    }

    // ── IPv6 resolv.conf strip (PLAN.md B3 / upstream issue #5) ───

    fn direct_args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    /// One execution of the composed production direct tail: which shell, which
    /// program and argv, the prefix script that stands in for the hook, and the
    /// `PATH` it runs under. Named fields, because every one of them is a string
    /// that must not be swapped with its neighbour.
    struct DirectTail<'a> {
        bash: &'a str,
        program: &'a str,
        args: &'a [String],
        before: &'a str,
        path: &'a str,
    }

    // Execute precisely the composed production tail, never the host-mutating prelude.
    fn direct_tail(tail: DirectTail<'_>) -> std::process::Output {
        let DirectTail {
            bash,
            program,
            args,
            before,
            path,
        } = tail;
        let line = AgentShellLine {
            guard: ProgramGuard::Direct,
            project_guest_path: "/work",
            image: "unused",
            command: program,
            args,
        };
        std::process::Command::new(bash)
            .args([
                "-c",
                &format!("{before}\n{}{}", line.program_guard(), line.exec_line()),
            ])
            .env("PATH", path)
            .output()
            .unwrap()
    }

    fn host_bashes() -> Vec<&'static str> {
        let mut bashes = vec!["/bin/bash"];
        if Path::new("/opt/homebrew/bin/bash").is_file() {
            bashes.push("/opt/homebrew/bin/bash");
        }
        bashes
    }

    #[test]
    fn direct_guard_preserves_literal_argv_and_guest_status() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let probe = temp.path().join("probe");
        std::fs::write(&probe, "#!/bin/sh\nprintf '%s\\0' \"$@\"\nexit 23\n").unwrap();
        std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o755)).unwrap();
        let vector = direct_args(&[
            "",
            "a b",
            "'\"",
            "日本語",
            "$HOME",
            "*",
            ";",
            "|",
            "--",
            "--help",
            "x",
            "x",
            "a\nb",
            "end\n\n",
        ]);
        let expected: Vec<u8> = vector
            .iter()
            .flat_map(|s| s.as_bytes().iter().copied().chain([0]))
            .collect();
        for bash in host_bashes() {
            let output = direct_tail(DirectTail {
                bash,
                program: probe.to_str().unwrap(),
                args: &vector,
                before: "",
                path: "/usr/bin:/bin",
            });
            assert_eq!(output.status.code(), Some(23), "{bash}: {output:?}");
            assert_eq!(output.stdout, expected);
            assert!(output.stderr.is_empty());
            let output = direct_tail(DirectTail {
                bash,
                program: "printf",
                args: &direct_args(&["%s\\n", "$HOME"]),
                before: "",
                path: "/usr/bin:/bin",
            });
            assert!(output.status.success());
            assert_eq!(output.stdout, b"$HOME\n");
        }
    }

    #[test]
    fn direct_guard_lookup_preserves_pathname_bytes_and_distinguishes_statuses() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        for directory in ["bin", "bin\n"] {
            let bin = temp.path().join(directory);
            std::fs::create_dir(&bin).unwrap();
            for name in ["probe", "probe\n", "probe\n\n", "日本'語\t"] {
                let file = bin.join(name);
                std::fs::write(&file, "#!/bin/sh\nprintf 'executed\\n'\nexit 23\n").unwrap();
                std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
                for bash in host_bashes() {
                    for program in [name, file.to_str().unwrap()] {
                        let output = direct_tail(DirectTail {
                            bash,
                            program,
                            args: &[],
                            before: "set -e",
                            path: bin.to_str().unwrap(),
                        });
                        assert_eq!(
                            output.status.code(),
                            Some(23),
                            "{bash}, {program:?}: {output:?}"
                        );
                        assert_eq!(output.stdout, b"executed\n");
                        assert!(output.stderr.is_empty());
                    }
                }
            }
            let nonexec = bin.join("nonexec");
            std::fs::write(&nonexec, "not executable").unwrap();
            std::fs::set_permissions(&nonexec, std::fs::Permissions::from_mode(0o644)).unwrap();
            let directory = bin.join("directory");
            std::fs::create_dir(&directory).unwrap();
            std::os::unix::fs::symlink(bin.join("absent"), bin.join("broken")).unwrap();
            for bash in host_bashes() {
                for (program, status) in [
                    ("missing", 127),
                    (bin.join("missing").to_str().unwrap(), 127),
                    ("nonexec", 126),
                    (nonexec.to_str().unwrap(), 126),
                    ("directory", 127),
                    (directory.to_str().unwrap(), 126),
                    ("broken", 127),
                ] {
                    let output = direct_tail(DirectTail {
                        bash,
                        program,
                        args: &[],
                        before: "set -e",
                        path: bin.to_str().unwrap(),
                    });
                    assert_eq!(
                        output.status.code(),
                        Some(status),
                        "{bash}, {program:?}: {output:?}"
                    );
                    assert!(output.stdout.is_empty());
                    assert!(
                        String::from_utf8(output.stderr)
                            .unwrap()
                            .starts_with("agent-vm: ")
                    );
                }
            }
        }
    }

    #[test]
    fn direct_guard_uses_post_hook_path_not_functions_aliases_or_stale_hash() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let bin = temp.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let bin = bin.to_str().unwrap();
        let file = Path::new(bin).join("probe");
        std::fs::write(&file, "#!/bin/sh\nprintf external\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
        for bash in host_bashes() {
            // The hash entry is created after the prefix's last PATH assignment:
            // assigning PATH empties the table itself, so an earlier `hash -p`
            // would prove nothing about the guard.
            let before = format!(
                "export PATH={}\n\
                 hash -p /missing/probe probe\n\
                 builtin type -P -- probe >&2\n\
                 probe() {{ exit 99; }}\n\
                 alias probe='exit 98'",
                shell_escape(bin)
            );
            let output = direct_tail(DirectTail {
                bash,
                program: "probe",
                args: &[],
                before: &before,
                path: "/usr/bin:/bin",
            });
            assert!(output.status.success(), "{bash}: {output:?}");
            assert_eq!(output.stdout, b"external");
            // The negative control proves the stale pathname reaches the guard:
            // the external program running can only follow the guard's own clear.
            assert_eq!(
                String::from_utf8(output.stderr).unwrap(),
                "/missing/probe\n",
                "{bash}"
            );
            let output = direct_tail(DirectTail {
                bash,
                program: "absent",
                args: &[],
                before: "absent() { exit 99; }; alias absent='exit 98'",
                path: bin,
            });
            assert_eq!(output.status.code(), Some(127), "{bash}: {output:?}");
            assert!(output.stdout.is_empty());
        }
    }

    #[test]
    fn direct_guard_ignores_a_hook_left_stale_hash_after_a_move_or_replacement() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let mut case = 0;
        for bash in host_bashes() {
            for later in [Some("later"), None] {
                for replaced_by_directory in [false, true] {
                    case += 1;
                    let root = temp.path().join(format!("case{case}"));
                    let earlier = root.join("earlier");
                    let later_bin = root.join("later");
                    std::fs::create_dir_all(&earlier).unwrap();
                    std::fs::create_dir_all(&later_bin).unwrap();
                    let earlier_probe = earlier.join("probe");
                    std::fs::write(&earlier_probe, "#!/bin/sh\nprintf earlier\n").unwrap();
                    std::fs::set_permissions(
                        &earlier_probe,
                        std::fs::Permissions::from_mode(0o755),
                    )
                    .unwrap();
                    if let Some(body) = later {
                        let file = later_bin.join("probe");
                        std::fs::write(&file, format!("#!/bin/sh\nprintf {body}\n")).unwrap();
                        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755))
                            .unwrap();
                    }
                    // Hook shape: run a PATH program (hashing it), then remove or
                    // directory-replace it with no further PATH assignment.
                    let earlier_probe = shell_escape(earlier_probe.to_str().unwrap());
                    let mutation = if replaced_by_directory {
                        format!("rm {earlier_probe}\nmkdir {earlier_probe}")
                    } else {
                        format!("rm {earlier_probe}")
                    };
                    let before = format!(
                        "export PATH={}:/usr/bin:/bin\nprobe >/dev/null\n{mutation}",
                        shell_escape(&format!("{}:{}", earlier.display(), later_bin.display()))
                    );
                    let context =
                        format!("{bash}, later={later:?}, directory={replaced_by_directory}");
                    let output = direct_tail(DirectTail {
                        bash,
                        program: "probe",
                        args: &[],
                        before: &before,
                        path: "/usr/bin:/bin",
                    });
                    match later {
                        Some(body) => {
                            assert!(output.status.success(), "{context}: {output:?}");
                            assert_eq!(output.stdout, body.as_bytes(), "{context}");
                        }
                        None => {
                            assert_eq!(output.status.code(), Some(127), "{context}: {output:?}");
                            assert!(output.stdout.is_empty(), "{context}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn direct_guard_tolerates_a_hook_disabling_hashing_under_errexit() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let bin = temp.path().to_str().unwrap();
        let file = temp.path().join("probe");
        std::fs::write(&file, "#!/bin/sh\nprintf external\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
        let nonexec = temp.path().join("nonexec");
        std::fs::write(&nonexec, "not executable").unwrap();
        std::fs::set_permissions(&nonexec, std::fs::Permissions::from_mode(0o644)).unwrap();
        for bash in host_bashes() {
            let output = direct_tail(DirectTail {
                bash,
                program: "probe",
                args: &[],
                before: "set -e\nset +h",
                path: bin,
            });
            assert!(output.status.success(), "{bash}: {output:?}");
            assert_eq!(output.stdout, b"external");
            assert_eq!(output.stderr, b"", "{bash}");
            for (program, status) in [("missing", 127), ("nonexec", 126)] {
                let output = direct_tail(DirectTail {
                    bash,
                    program,
                    args: &[],
                    before: "set -e\nset +h",
                    path: bin,
                });
                assert_eq!(
                    output.status.code(),
                    Some(status),
                    "{bash}, {program}: {output:?}"
                );
                assert!(output.stdout.is_empty());
                let stderr = String::from_utf8(output.stderr).unwrap();
                assert!(!stderr.contains("hashing disabled"), "{bash}: {stderr}");
                assert!(stderr.starts_with("agent-vm: "), "{bash}: {stderr}");
            }
        }
    }

    #[test]
    fn direct_guard_clears_the_hash_once_before_the_lookup() {
        let guard = AgentShellLine {
            guard: ProgramGuard::Direct,
            project_guest_path: "/work",
            image: "unused",
            command: "probe --help",
            args: &[],
        }
        .program_guard();
        assert_eq!(guard.matches("hash -r").count(), 1, "{guard}");
        let clear = guard.find("hash -r").unwrap();
        assert!(
            clear < guard.find("case \"$_avm_command\"").unwrap(),
            "{guard}"
        );
        assert!(clear < guard.find("builtin type -P").unwrap(), "{guard}");
        let checks = guard.find("if [ \"$_avm_lookup_status\"").unwrap();
        assert!(!guard[checks..].contains("hash -r"), "{guard}");
        assert!(
            guard.starts_with("builtin hash -r 2>/dev/null || builtin :\n"),
            "{guard}"
        );
    }

    #[test]
    fn direct_guard_follows_hook_and_hook_failure_prevents_exec() {
        let line = AgentShellLine {
            guard: ProgramGuard::Direct,
            project_guest_path: "/work",
            image: "unused",
            command: "printf",
            args: &[],
        }
        .render();
        assert!(
            line.find(STRIP_IPV6_NAMESERVERS).unwrap() < line.find(RUN_IMAGE_SEED_HOOKS).unwrap()
        );
        assert!(line.find("[ -t 0 ] || exec < /dev/null").unwrap() < line.find("_hook=").unwrap());
        assert!(line.find(". \"$_hook\"").unwrap() < line.find("_avm_command=").unwrap());
        assert!(line.find("_avm_command=").unwrap() < line.find("; exec --").unwrap());
        let temp = tempfile::tempdir().unwrap();
        let hook = temp.path().join(".agent-vm.runtime.sh");
        for body in ["return 9", "exit 9"] {
            std::fs::write(&hook, body).unwrap();
            let line = AgentShellLine {
                guard: ProgramGuard::Direct,
                project_guest_path: temp.path().to_str().unwrap(),
                image: "unused",
                command: "printf",
                args: &["EXECUTED".into()],
            }
            .render();
            let safe_tail = &line[line.find("_hook=").unwrap()..];
            for bash in host_bashes() {
                let output = std::process::Command::new(bash)
                    .args(["-c", safe_tail])
                    .output()
                    .unwrap();
                assert_eq!(output.status.code(), Some(9));
                assert!(output.stdout.is_empty());
                if body == "return 9" {
                    assert!(String::from_utf8_lossy(&output.stderr).contains("failed (exit 9)"));
                }
            }
        }
    }
    fn shell_line(project: &str, image: &str, command: &str, args: &[String]) -> String {
        AgentShellLine {
            guard: ProgramGuard::ImageContract,
            project_guest_path: project,
            image,
            command,
            args,
        }
        .render()
    }

    #[test]
    fn agent_shell_line_starts_with_v6_strip_and_execs() {
        let line = shell_line("/work/proj", "alpine:3.22", "claude", &[]);
        // The prelude opens with the IPv6-nameserver strip, sourced from
        // the single `STRIP_IPV6_NAMESERVERS` const so the live launch
        // path and this test can't drift.
        assert!(line.starts_with(STRIP_IPV6_NAMESERVERS), "got: {line}");
        assert!(line.starts_with("sed -i '/^nameserver .*:/d' /etc/resolv.conf"));
        assert!(line.contains("exec -- 'claude'"), "got: {line}");
    }

    #[test]
    fn agent_shell_line_forwards_args() {
        let line = shell_line(
            "/p",
            "alpine:3.22",
            "codex",
            &["exec".into(), "don't".into()],
        );
        assert!(
            line.contains("exec -- 'codex' 'exec' 'don'\\''t'"),
            "got: {line}"
        );
    }

    #[test]
    fn agent_shell_line_runs_seed_entry_points_then_hook_then_guard_then_exec() {
        // Ordering is load-bearing: the seed entry points and the project
        // runtime hook run first (a hook's `PATH` export must count for the
        // guard), then the external-program guard, then `exec`.
        let line = shell_line("/work/proj", "alpine:3.22", "claude", &[]);
        let seed = line
            .find(RUN_IMAGE_SEED_HOOKS)
            .expect("seed-entry-point step present");
        let hook = line
            .find(".agent-vm.runtime.sh")
            .expect("project runtime hook present");
        let guard = line.find("_avm_command=").expect("program guard present");
        let exec = line.find("exec -- 'claude'").expect("exec present");
        assert!(
            seed < hook,
            "seed entry points must precede the hook; got: {line}"
        );
        assert!(
            hook < guard,
            "the runtime hook must precede the guard; got: {line}"
        );
        assert!(guard < exec, "the guard must precede exec; got: {line}");
        assert!(
            line.contains("for _h in /opt/agent-vm/seed.d/*"),
            "the generic seed.d loop must be emitted; got: {line}"
        );
        assert!(
            line.contains("/opt/agent-vm/seed-claude-plugins.sh"),
            "the named seed entry point must be emitted; got: {line}"
        );
    }

    // ── external-program guard: the rendered guard + the ACTUAL exec (#258) ───

    /// Run the exact guard + final `exec` [`AgentShellLine::render`] appends, in
    /// a real `/bin/bash`. Never the full prelude: that would rewrite the host's
    /// `/etc/resolv.conf`.
    fn run_guard_tail(
        command: &str,
        args: &[String],
        path: Option<&str>,
        prefix: &str,
        extra_env: &[(&str, &str)],
    ) -> std::process::Output {
        let line = AgentShellLine {
            guard: ProgramGuard::ImageContract,
            project_guest_path: "/work/proj",
            image: "e2e-258/img with spaces",
            command,
            args,
        };
        // Mirror `render` exactly: the guard and the `exec` line are concatenated
        // with no separator (`exec_line` opens with `; `), so a newline here would
        // put `;` at the start of a line and make bash reject the script.
        let tail = format!("{prefix}\n{}{}", line.program_guard(), line.exec_line());
        let mut process = std::process::Command::new("/bin/bash");
        process.arg("-c").arg(tail);
        match path {
            Some(value) => {
                process.env("PATH", value);
            }
            None => {
                process.env_remove("PATH");
            }
        }
        for (key, value) in extra_env {
            process.env(key, value);
        }
        process.output().expect("/bin/bash runs")
    }

    /// The guard must actually `exec` the selected program: a sentinel, the
    /// forwarded argv and the program's own exit status are the oracle, not the
    /// guard's lookup alone.
    #[test]
    fn guard_execs_the_real_program_with_argv_and_status() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        write_executable(
            &bin.join("hello-258"),
            "#!/bin/sh\nprintf 'sentinel=%s\\n' \"$TEST_SENTINEL\"\nprintf 'arg1=[%s] arg2=[%s]\\n' \"$1\" \"$2\"\nexit 23\n",
        );
        let out = run_guard_tail(
            "hello-258",
            &["a b".to_string(), "c'd".to_string()],
            Some(bin.to_str().unwrap()),
            "",
            &[("TEST_SENTINEL", "ok")],
        );
        assert_eq!(
            out.status.code(),
            Some(23),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "sentinel=ok\narg1=[a b] arg2=[c'd]\n"
        );
    }

    #[test]
    fn guard_refuses_a_missing_program() {
        let dir = tempfile::tempdir().unwrap();
        let out = run_guard_tail(
            "not-installed-258",
            &[],
            Some(dir.path().to_str().unwrap()),
            "",
            &[],
        );
        assert_eq!(out.status.code(), Some(127));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("has no runnable external program"),
            "got: {stderr}"
        );
        assert!(stderr.contains("not-installed-258"), "got: {stderr}");
        assert!(
            stderr.contains("e2e-258/img with spaces"),
            "image must be named; got: {stderr}"
        );
    }

    #[test]
    fn guard_refuses_builtin_only_and_function_or_alias_shadows() {
        let dir = tempfile::tempdir().unwrap();
        // `printf` is a builtin with no external binary on this PATH.
        let out = run_guard_tail("printf", &[], Some(""), "", &[]);
        assert_eq!(out.status.code(), Some(127));
        assert!(String::from_utf8_lossy(&out.stderr).contains("has no runnable external program"));

        let prefix = "no-real-258() { echo function; }\nalias no-real-258='echo alias'\n";
        let out = run_guard_tail(
            "no-real-258",
            &[],
            Some(dir.path().to_str().unwrap()),
            prefix,
            &[],
        );
        assert_eq!(
            out.status.code(),
            Some(127),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!String::from_utf8_lossy(&out.stdout).contains("function"));
    }

    #[test]
    fn guard_execs_a_real_program_even_when_a_function_shadows_the_name() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        write_executable(&bin.join("hello-258"), "#!/bin/sh\necho REAL\nexit 23\n");
        let prefix = "hello-258() { echo FUNCTION; }\nalias hello-258='echo ALIAS'\n";
        let out = run_guard_tail("hello-258", &[], Some(bin.to_str().unwrap()), prefix, &[]);
        assert_eq!(out.status.code(), Some(23));
        assert_eq!(String::from_utf8_lossy(&out.stdout), "REAL\n");
    }

    #[test]
    fn guard_handles_quoted_names_and_pathnames_with_spaces() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        write_executable(&bin.join("we'ird"), "#!/bin/sh\necho QUOTED\nexit 23\n");
        let out = run_guard_tail("we'ird", &[], Some(bin.to_str().unwrap()), "", &[]);
        assert_eq!(
            out.status.code(),
            Some(23),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&out.stdout), "QUOTED\n");

        let spaced = dir.path().join("bin dir").join("my prog");
        std::fs::create_dir_all(spaced.parent().unwrap()).unwrap();
        write_executable(&spaced, "#!/bin/sh\necho SPACED\nexit 23\n");
        let out = run_guard_tail(spaced.to_str().unwrap(), &[], Some(""), "", &[]);
        assert_eq!(
            out.status.code(),
            Some(23),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&out.stdout), "SPACED\n");
    }

    #[test]
    fn guard_refuses_non_executable_files_and_directories() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("not-executable-258");
        std::fs::write(&plain, "data").unwrap();
        let out = run_guard_tail(plain.to_str().unwrap(), &[], Some(""), "", &[]);
        assert_eq!(out.status.code(), Some(127));
        assert!(String::from_utf8_lossy(&out.stderr).contains("has no runnable external program"));

        let directory = dir.path().join("a-directory-258");
        std::fs::create_dir_all(&directory).unwrap();
        let out = run_guard_tail(directory.to_str().unwrap(), &[], Some(""), "", &[]);
        assert_eq!(out.status.code(), Some(127));
    }

    #[test]
    fn guard_honours_a_hook_exported_path_and_ignores_a_stale_hash() {
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join("old");
        let new = dir.path().join("new");
        std::fs::create_dir_all(&old).unwrap();
        std::fs::create_dir_all(&new).unwrap();
        write_executable(&old.join("moved-258"), "#!/bin/sh\necho OLD\nexit 1\n");
        write_executable(&new.join("moved-258"), "#!/bin/sh\necho NEW\nexit 23\n");

        // A hook-shaped script exports a PATH the launcher never set; the guard
        // must see it because it runs after the hook.
        let out = run_guard_tail(
            "moved-258",
            &[],
            Some(""),
            "export PATH=\"$HOOK_BIN\"\n",
            &[("HOOK_BIN", new.to_str().unwrap())],
        );
        assert_eq!(
            out.status.code(),
            Some(23),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&out.stdout), "NEW\n");

        // An old hashed location must not win over the final PATH: run the old
        // binary (hashing it), then change PATH before the guard + exec.
        let prefix = format!(
            "PATH=\"{old}\"\nmoved-258 >/dev/null 2>&1 || true\nexport PATH=\"{new}\"\n",
            old = old.display(),
            new = new.display()
        );
        let out = run_guard_tail("moved-258", &[], Some(old.to_str().unwrap()), &prefix, &[]);
        assert_eq!(
            out.status.code(),
            Some(23),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&out.stdout), "NEW\n");
    }

    /// The teardown combination rule: the primary contract diagnostic survives,
    /// stays first, keeps operation order, and always names the log directory.
    #[test]
    fn failed_exec_message_keeps_the_primary_diagnostic_first() {
        let primary = "boot image `img` has no runnable `bash` on its guest PATH";
        let clean = failed_exec_message(primary, &[], "/logs");
        assert_eq!(clean, format!("{primary} (full logs: /logs)"));

        let failures = vec![
            "stop: timed out".to_string(),
            "kill: hung".to_string(),
            "remove: database locked".to_string(),
        ];
        let combined = failed_exec_message(primary, &failures, "/logs");
        assert!(combined.starts_with(primary), "got: {combined}");
        let stop = combined.find("stop: timed out").unwrap();
        let kill = combined.find("kill: hung").unwrap();
        let remove = combined.find("remove: database locked").unwrap();
        assert!(
            stop < kill && kill < remove,
            "operation order must survive; got: {combined}"
        );
        assert!(combined.contains("/logs"));
    }

    /// #258: the three exec-failure call sites build the primary through
    /// [`exec_failure_primary`] without a log path, so the single owner
    /// ([`failed_exec_message`]) names the directory exactly once — a primary
    /// that already carried the suffix used to duplicate it on every path.
    #[test]
    fn the_call_site_primary_names_the_log_directory_exactly_once() {
        use microsandbox::protocol::exec::{ExecFailed, ExecFailureKind};

        let diagnostic = image_contract::launch_shell_spawn_diagnostic(
            "alpine:3.22",
            &ExecFailed {
                kind: ExecFailureKind::NotFound,
                errno: None,
                errno_name: None,
                message: "no such file".to_string(),
                stage: None,
            },
        )
        .expect("NotFound maps to a contract diagnostic");
        for primary in [
            exec_failure_primary(Some(diagnostic), anyhow::anyhow!("unused fallback")),
            exec_failure_primary(
                None,
                anyhow::anyhow!("attaching to hello-258").context("outer"),
            ),
        ] {
            let rendered = failed_exec_message(&format!("{primary:#}"), &[], "/logs/session");
            assert_eq!(
                rendered.matches("(full logs:").count(),
                1,
                "the log directory must be named once: {rendered}"
            );
            assert!(
                rendered.ends_with("(full logs: /logs/session)"),
                "got: {rendered}"
            );
        }
    }

    /// Guard the hand-maintained tie to the base Dockerfile's `ENV PATH`.
    /// After #84 the fallback must name no `/opt/agent` tool prefix — the tool
    /// layers append their own prefixes to the composed image, and the base
    /// carries none.
    #[test]
    fn fallback_guest_path_names_no_tool_prefix() {
        assert!(
            !FALLBACK_GUEST_PATH.contains("/opt/agent"),
            "the fallback PATH must name no tool prefix; got {FALLBACK_GUEST_PATH}"
        );
        assert_eq!(
            FALLBACK_GUEST_PATH,
            "/usr/local/bin:/usr/bin:/usr/sbin:/bin"
        );
    }

    /// Guard the exact `sed` program in `STRIP_IPV6_NAMESERVERS`. The
    /// regex is load-bearing (see the const's doc comment): an accidental
    /// edit that dropped the `^` anchor or the `:` class would silently
    /// start eating IPv4 nameservers or comment lines, leaving the guest
    /// with no DNS at all.
    #[test]
    fn strip_ipv6_nameservers_snippet_is_the_expected_sed() {
        assert_eq!(
            STRIP_IPV6_NAMESERVERS,
            "sed -i '/^nameserver .*:/d' /etc/resolv.conf 2>/dev/null || true",
        );
    }

    /// Reimplement the `sed '/^nameserver .*:/d'` predicate in Rust and
    /// assert it removes **only** IPv6 `nameserver` lines: IPv4
    /// nameservers, comments, `search` and `options` must survive. This
    /// exercises the regex *intent* without needing a live VM (the real
    /// strip runs inside the guest, which we can't boot here).
    #[test]
    fn sed_predicate_removes_only_ipv6_nameservers() {
        // Mirror `sed` address `/^nameserver .*:/`: delete iff the line
        // begins exactly with "nameserver " (so a leading '#' comment is
        // NOT matched — the `^` anchors before `nameserver`) AND a colon
        // appears somewhere after that prefix (i.e. in the value).
        fn deleted_by_sed(line: &str) -> bool {
            match line.strip_prefix("nameserver ") {
                Some(value) => value.contains(':'),
                None => false,
            }
        }

        let resolv = "\
# generated by agentd
nameserver 10.0.2.3
nameserver 192.168.1.1
nameserver fec0::3
nameserver fe80::1%eth0
nameserver 2001:4860:4860::8888
# nameserver 2001:db8::1
search lan example.com
options ndots:2 timeout:1";

        let kept: Vec<&str> = resolv.lines().filter(|l| !deleted_by_sed(l)).collect();

        // IPv4 nameservers survive.
        assert!(kept.contains(&"nameserver 10.0.2.3"));
        assert!(kept.contains(&"nameserver 192.168.1.1"));
        // Comments survive, including a commented-out IPv6 nameserver.
        assert!(kept.contains(&"# generated by agentd"));
        assert!(kept.contains(&"# nameserver 2001:db8::1"));
        // `search` / `options` survive even though `options` contains a
        // colon (the `^nameserver` anchor protects them).
        assert!(kept.contains(&"search lan example.com"));
        assert!(kept.contains(&"options ndots:2 timeout:1"));

        // Every IPv6 nameserver line is gone (global, link-local with a
        // zone id, and ULA forms all carry a colon).
        assert!(!kept.iter().any(|l| l.starts_with("nameserver fec0::3")));
        assert!(!kept.iter().any(|l| l.starts_with("nameserver fe80::1")));
        assert!(!kept.iter().any(|l| l.starts_with("nameserver 2001:")));

        // No surviving line is an (uncommented) IPv6 nameserver.
        assert!(!kept.iter().any(|l| deleted_by_sed(l)));
    }

    // ── parse_github_slug ────────────────────────────────────────

    #[test]
    fn parse_github_slug_https_with_and_without_dot_git() {
        assert_eq!(
            parse_github_slug("https://github.com/wirenboard/agent-vm.git"),
            Some("wirenboard/agent-vm".into())
        );
        assert_eq!(
            parse_github_slug("https://github.com/wirenboard/agent-vm"),
            Some("wirenboard/agent-vm".into())
        );
        // Extra path components beyond the repo are ignored.
        assert_eq!(
            parse_github_slug("https://github.com/wirenboard/agent-vm/tree/main"),
            Some("wirenboard/agent-vm".into())
        );
        // http also works.
        assert_eq!(
            parse_github_slug("http://github.com/o/r.git"),
            Some("o/r".into())
        );
    }

    #[test]
    fn parse_github_slug_scp_and_ssh_url_forms() {
        // scp-like: git@github.com:owner/repo[.git]
        assert_eq!(
            parse_github_slug("git@github.com:wirenboard/agent-vm.git"),
            Some("wirenboard/agent-vm".into())
        );
        assert_eq!(
            parse_github_slug("git@github.com:wirenboard/agent-vm"),
            Some("wirenboard/agent-vm".into())
        );
        // URL form with /
        assert_eq!(
            parse_github_slug("ssh://git@github.com/wirenboard/agent-vm.git"),
            Some("wirenboard/agent-vm".into())
        );
        // URL form with port: ssh://git@github.com:22/owner/repo
        assert_eq!(
            parse_github_slug("ssh://git@github.com:22/wirenboard/agent-vm"),
            Some("wirenboard/agent-vm".into())
        );
    }

    #[test]
    fn parse_github_slug_rejects_non_github_urls() {
        assert_eq!(parse_github_slug("https://gitlab.com/o/r"), None);
        assert_eq!(
            parse_github_slug("https://example.com/github.com/o/r"),
            None
        );
        assert_eq!(parse_github_slug(""), None);
        assert_eq!(parse_github_slug("not a url"), None);
    }

    #[test]
    fn parse_github_slug_handles_dot_git_only_once() {
        // Regression: `trim_end_matches(".git")` (greedy) would strip
        // both, yielding `o/repo` instead of `o/repo.git`. With
        // `strip_suffix` we strip exactly one.
        assert_eq!(
            parse_github_slug("https://github.com/o/repo.git.git"),
            Some("o/repo.git".into())
        );
    }

    #[test]
    fn parse_github_slug_rejects_empty_owner_or_repo() {
        assert_eq!(parse_github_slug("https://github.com/"), None);
        assert_eq!(parse_github_slug("https://github.com/owner"), None);
        assert_eq!(parse_github_slug("https://github.com/owner/"), None);
        assert_eq!(parse_github_slug("https://github.com//repo"), None);
        // Only `.git` after the owner means an empty repo segment.
        assert_eq!(parse_github_slug("https://github.com/owner/.git"), None);
    }

    #[test]
    fn parse_github_slug_rejects_dot_and_dotdot_segments() {
        // A submodule URL like `https://github.com/../attacker/repo`
        // is shaped like a path-traversal — must not yield a slug.
        assert_eq!(parse_github_slug("https://github.com/../attacker"), None);
        assert_eq!(parse_github_slug("https://github.com/owner/.."), None);
        assert_eq!(parse_github_slug("https://github.com/./repo"), None);
        assert_eq!(parse_github_slug("https://github.com/owner/."), None);
        assert_eq!(parse_github_slug("git@github.com:../attacker.git"), None);
    }

    // ── guest-path predicates / resolve_project_guest_path ───────

    #[test]
    fn guest_path_is_cmdline_safe_accepts_plain_ascii_only() {
        // This predicate now governs only the KRUN_WORKDIR placeholder
        // (the one path that still rides the cmdline). Plain ASCII passes.
        assert!(guest_path_is_cmdline_safe("/home/boger/work/agent-vm"));
        assert!(guest_path_is_cmdline_safe("/workspace"));
        // '=' is safe in a path (the kernel splits a KEY=value token only
        // on its first '='); only whitespace and non-ASCII are unsafe.
        assert!(guest_path_is_cmdline_safe("/home/a=b/c-d.e_f+g"));
        // Cyrillic/emoji (non-ASCII), space, tab, DEL are all NOT
        // cmdline-safe → the workdir falls back to the "/" placeholder.
        assert!(!guest_path_is_cmdline_safe("/home/boger/проект-тест"));
        assert!(!guest_path_is_cmdline_safe("/home/boger/😀proj"));
        assert!(!guest_path_is_cmdline_safe("/home/My Project"));
        assert!(!guest_path_is_cmdline_safe("/home/x\ty"));
        assert!(!guest_path_is_cmdline_safe("/home/x\u{7f}y"));
    }

    #[test]
    fn guest_path_is_mountable_allows_non_ascii_and_space_not_control() {
        // Mount points travel via the byte-transparent boot-params side
        // channel, so non-ASCII and spaces are mountable.
        assert!(guest_path_is_mountable("/home/boger/проект-тест"));
        assert!(guest_path_is_mountable("/home/boger/😀proj"));
        assert!(guest_path_is_mountable("/home/My Project"));
        assert!(guest_path_is_mountable("/home/boger/work"));
        // Control characters (TAB/newline/DEL) break the KEY\tVALUE\n
        // framing and are rejected.
        assert!(!guest_path_is_mountable("/home/x\ty"));
        assert!(!guest_path_is_mountable("/home/x\ny"));
        assert!(!guest_path_is_mountable("/home/x\u{7f}y"));
    }

    #[test]
    fn guest_always_env_pins_utf8_locale_and_sandbox_flag() {
        let map: std::collections::HashMap<&str, &str> = GUEST_ALWAYS_ENV.iter().copied().collect();
        // Claude Code's root-guard bypass must stay set.
        assert_eq!(map.get("IS_SANDBOX"), Some(&"1"));
        // A UTF-8 locale must be pinned: without it the guest is C/POSIX,
        // which renders a Cyrillic cwd as `M-P…` escapes and makes the
        // agents' filesystem encoding ASCII (mishandling non-ASCII paths).
        // Removing or non-UTF-8-ing this regresses Cyrillic-path support.
        let lang = map
            .get("LANG")
            .expect("guest LANG must be pinned to a UTF-8 locale");
        assert!(
            lang.to_ascii_lowercase().replace('-', "").contains("utf8"),
            "guest LANG must be a UTF-8 locale, got {lang:?}"
        );
    }

    #[test]
    fn every_launcher_published_name_is_refused_for_a_credential() {
        // AC2 fail-closed: the launcher-owned names an authorization may not
        // own are exactly the ones the launcher itself publishes. Pinning the
        // enumeration here means a new `GUEST_ALWAYS_ENV` entry that forgets
        // `LAUNCHER_OWNED_ENV_NAMES` fails a test instead of silently emitting
        // a value AC2 promised to leave unset. (It does not, by itself, notice
        // a new launcher env *writer*; PATH and the identity triple are pinned
        // separately below, and every other writer goes through
        // `assemble_guest_env`.)
        use crate::credential_yaml::{GuestEnvName, LAUNCHER_OWNED_ENV_NAMES};
        for (name, _) in GUEST_ALWAYS_ENV {
            assert!(
                LAUNCHER_OWNED_ENV_NAMES.contains(name),
                "{name} is launcher-published but not owned"
            );
            assert!(GuestEnvName::parse(name).is_err(), "{name}");
        }
        // PATH is published from the booted image's OCI config.
        assert!(LAUNCHER_OWNED_ENV_NAMES.contains(&"PATH"));
        assert!(GuestEnvName::parse("PATH").is_err());
        // The guest-identity triple is refused as well.
        for name in ["HOME", "USER", "LOGNAME"] {
            assert!(GuestEnvName::parse(name).is_err(), "{name}");
        }
    }

    #[test]
    fn resolve_project_guest_path_mirrors_real_path_and_only_remaps_unmountable() {
        // Plain ASCII path is mirrored 1:1 with no remap notice.
        let (guest, reason) =
            resolve_project_guest_path(Path::new("/home/boger/proj"), "/home/boger/proj");
        assert_eq!(guest, "/home/boger/proj");
        assert!(reason.is_none());

        // Cyrillic, emoji, and space are now mirrored at their REAL path —
        // the mount spec rides the side channel and the cwd the exec
        // channel, so there's no /workspace fallback and no remap notice.
        for p in ["/home/boger/проект", "/home/boger/😀p", "/home/My Project"] {
            let (guest, reason) = resolve_project_guest_path(Path::new(p), p);
            assert_eq!(guest, p, "{p:?} should be mirrored at its real path");
            assert!(reason.is_none(), "{p:?} should not report a remap reason");
        }

        // A path under a guest tmpfs mount still remaps (would be wiped at
        // boot), regardless of being otherwise ASCII-clean.
        let (guest, reason) = resolve_project_guest_path(Path::new("/tmp/proj"), "/tmp/proj");
        assert_eq!(guest, "/workspace");
        assert!(reason.is_some_and(|r| r.contains("tmpfs")));

        // A control character in the path can't be framed for the side
        // channel → defensive /workspace fallback.
        let (guest, reason) = resolve_project_guest_path(Path::new("/home/a\tb"), "/home/a\tb");
        assert_eq!(guest, "/workspace");
        assert!(reason.is_some_and(|r| r.contains("control characters")));
    }

    // ── mkdir_chain ──────────────────────────────────────────────

    #[test]
    fn mkdir_chain_yields_path_prefixes() {
        let chain = mkdir_chain(std::path::Path::new("/home/user/proj"));
        assert_eq!(chain, vec!["/home", "/home/user", "/home/user/proj"]);
    }

    #[test]
    fn mkdir_chain_root_is_empty() {
        let chain = mkdir_chain(std::path::Path::new("/"));
        assert_eq!(chain, Vec::<String>::new());
    }

    #[test]
    fn mkdir_chain_single_segment() {
        let chain = mkdir_chain(std::path::Path::new("/workspace"));
        assert_eq!(chain, vec!["/workspace"]);
    }

    // ── guest_path_is_safe ───────────────────────────────────────

    #[test]
    fn guest_path_safe_for_normal_paths() {
        assert!(guest_path_is_safe(std::path::Path::new("/home/u/proj")));
        assert!(guest_path_is_safe(std::path::Path::new("/workspace")));
        assert!(guest_path_is_safe(std::path::Path::new("/opt/foo")));
    }

    #[test]
    fn guest_path_unsafe_under_tmpfs_prefixes() {
        // The guest tmpfs-mounts these at boot, wiping any bake-time
        // mount point — so we can't mirror them.
        assert!(!guest_path_is_safe(std::path::Path::new("/tmp")));
        assert!(!guest_path_is_safe(std::path::Path::new("/tmp/anything")));
        assert!(!guest_path_is_safe(std::path::Path::new("/run")));
        assert!(!guest_path_is_safe(std::path::Path::new("/run/user/1000")));
        assert!(!guest_path_is_safe(std::path::Path::new("/dev/shm")));
        assert!(!guest_path_is_safe(std::path::Path::new("/var/run/foo")));
    }

    #[test]
    fn guest_path_safe_for_lookalikes_outside_tmpfs() {
        // /tmpfoo is NOT under /tmp/ — must remain safe.
        assert!(guest_path_is_safe(std::path::Path::new("/tmpfoo")));
        assert!(guest_path_is_safe(std::path::Path::new("/run-extra")));
    }

    // ── detect_github_repos against the live worktree ─────────────
    //
    // Exercises the real `git` invocation on the worktree this test
    // is built in. Skips itself cleanly if the workspace doesn't
    // have a github origin (e.g. distro packagers building from a
    // tarball), so it stays useful in the dev tree without being
    // load-bearing for releases.

    fn workspace_root() -> std::path::PathBuf {
        // crates/agent-vm/ → workspace root is two levels up.
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("CARGO_MANIFEST_DIR has two parents")
            .to_path_buf()
    }

    #[test]
    fn detect_github_repos_includes_submodules() {
        let root = workspace_root();
        if !root.join(".gitmodules").is_file() {
            eprintln!("skipping: no .gitmodules at {root:?}");
            return;
        }
        let slugs = detect_github_repos(&root, std::iter::empty());
        // The rewrite worktree vendors microsandbox as a submodule.
        // If origin happens to be non-github (rare), we still expect
        // the submodule slug.
        assert!(
            slugs
                .iter()
                .any(|s| s.eq_ignore_ascii_case("gregwebs/microsandbox")),
            "expected gregwebs/microsandbox in scope, got {slugs:?}"
        );
    }

    #[test]
    fn github_scan_reads_prepared_fork_data_not_exclusions() {
        // A fork's committed `data` is what detection scans. Seed omissions
        // are physical content removal, so an omitted `.git`/`.gitmodules`
        // simply cannot contribute slugs; nothing is logically filtered.
        let source = tempfile::tempdir().unwrap();
        std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(source.path())
            .status()
            .unwrap();
        std::process::Command::new("git")
            .args([
                "remote",
                "add",
                "origin",
                "https://github.com/example/visible.git",
            ])
            .current_dir(source.path())
            .status()
            .unwrap();
        std::fs::write(
            source.path().join(".gitmodules"),
            "[submodule \"sub\"]\n path = sub\n url = https://github.com/example/submodule.git\n",
        )
        .unwrap();
        let project = tempfile::tempdir().unwrap();

        for (exclusions, expect_origin, expect_submodule) in [
            (vec![], true, true),
            (vec![".git"], false, true),
            (vec![".git/config"], false, true),
            (vec![".gitmodules"], true, false),
        ] {
            let store = tempfile::tempdir().unwrap();
            let mut raw = format!("{}:/guest:fork", source.path().display());
            for exclusion in &exclusions {
                raw.push_str(&format!(":exclude={exclusion}"));
            }
            let plan = mount::prepare(
                mount::parse_extra_mounts(&[raw]).unwrap(),
                &mount::MountContext {
                    mount_store: store.path().to_path_buf(),
                    authority_home: Some(test_home()),
                    account_home: None,
                    host_home: Some(test_home()),
                    core_guest_mounts: Vec::new(),
                    core_host_sources: Vec::new(),
                    persisted_home: crate::guest_home::PersistedHome::none(),
                },
            )
            .unwrap();
            let slugs = detect_github_repos(project.path(), plan.repo_scan_roots.iter());
            assert_eq!(
                slugs.iter().any(|slug| slug == "example/visible"),
                expect_origin,
                "origin slug (exclusions={exclusions:?}): {slugs:?}"
            );
            assert_eq!(
                slugs.iter().any(|slug| slug == "example/submodule"),
                expect_submodule,
                "submodule slug (exclusions={exclusions:?}): {slugs:?}"
            );
        }
    }

    #[test]
    fn github_scan_reuses_committed_data_after_source_mutation() {
        let source = tempfile::tempdir().unwrap();
        std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(source.path())
            .status()
            .unwrap();
        std::process::Command::new("git")
            .args([
                "remote",
                "add",
                "origin",
                "https://github.com/example/visible.git",
            ])
            .current_dir(source.path())
            .status()
            .unwrap();
        let project = tempfile::tempdir().unwrap();
        let store = tempfile::tempdir().unwrap();
        let raw = format!("{}:/guest:fork", source.path().display());
        let context = mount::MountContext {
            mount_store: store.path().to_path_buf(),
            authority_home: Some(test_home()),
            account_home: None,
            host_home: Some(test_home()),
            core_guest_mounts: Vec::new(),
            core_host_sources: Vec::new(),
            persisted_home: crate::guest_home::PersistedHome::none(),
        };
        let first = mount::prepare(
            mount::parse_extra_mounts(std::slice::from_ref(&raw)).unwrap(),
            &context,
        )
        .unwrap();
        assert!(
            detect_github_repos(project.path(), first.repo_scan_roots.iter())
                .iter()
                .any(|slug| slug == "example/visible")
        );

        // Remove the source and re-prepare: READY reuse still scans `data`.
        std::fs::remove_dir_all(source.path()).unwrap();
        let reused = mount::prepare(mount::parse_extra_mounts(&[raw]).unwrap(), &context).unwrap();
        let slugs = detect_github_repos(project.path(), reused.repo_scan_roots.iter());
        assert!(
            slugs.iter().any(|slug| slug == "example/visible"),
            "README reuse must still scan committed data: {slugs:?}"
        );

        // Mounting the project itself must not duplicate a slug.
        std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(project.path())
            .status()
            .unwrap();
        std::process::Command::new("git")
            .args([
                "remote",
                "add",
                "origin",
                "https://github.com/example/visible.git",
            ])
            .current_dir(project.path())
            .status()
            .unwrap();
        let self_store = tempfile::tempdir().unwrap();
        let self_plan = mount::prepare(
            mount::parse_extra_mounts(&[format!("{}:/proj:fork", project.path().display())])
                .unwrap(),
            &mount::MountContext {
                mount_store: self_store.path().to_path_buf(),
                authority_home: Some(test_home()),
                account_home: None,
                host_home: Some(test_home()),
                core_guest_mounts: Vec::new(),
                core_host_sources: Vec::new(),
                persisted_home: crate::guest_home::PersistedHome::none(),
            },
        )
        .unwrap();
        let slugs = detect_github_repos(project.path(), self_plan.repo_scan_roots.iter());
        assert_eq!(
            slugs
                .iter()
                .filter(|slug| *slug == "example/visible")
                .count(),
            1,
            "mounting the project itself must not duplicate: {slugs:?}"
        );
    }

    #[test]
    fn parse_gitmodules_returns_empty_when_file_missing() {
        let tmp =
            std::env::temp_dir().join(format!("agent-vm-gitmodules-test-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let slugs = parse_gitmodules_github_slugs(&tmp);
        std::fs::remove_dir_all(&tmp).ok();
        assert!(slugs.is_empty(), "no .gitmodules → no slugs, got {slugs:?}");
    }

    // ── The production stream/failed-exec lifecycle, with injected failures ──

    /// Exec events plus a drop receipt: teardown must not run while this is
    /// alive, because dropping it releases the child-handle mutex.
    struct TrackingEvents {
        events: tokio::sync::mpsc::Receiver<microsandbox::sandbox::exec::ExecEvent>,
        dropped: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl ExecEventSource for TrackingEvents {
        async fn recv(&mut self) -> Option<microsandbox::sandbox::exec::ExecEvent> {
            self.events.recv().await
        }
    }

    impl Drop for TrackingEvents {
        fn drop(&mut self) {
            self.dropped
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// A sink whose write and flush can each fail, with a per-poll **write
    /// schedule**: `Ok(n)` accepts one short write (a real partial write, which
    /// `write_all` retries) and `Err(kind)` is a later poll failing. An empty
    /// schedule accepts everything.
    #[derive(Default)]
    struct StubSink {
        accepted: Vec<u8>,
        flushes: usize,
        write_steps: Vec<Result<usize, std::io::ErrorKind>>,
        flush_error: Option<std::io::ErrorKind>,
    }

    impl StubSink {
        /// The schedule a real `write_all` partial-write-then-error produces:
        /// the first poll accepts `bytes` and a later poll fails.
        fn partial_then_error(bytes: usize, kind: std::io::ErrorKind) -> Self {
            Self {
                write_steps: vec![Ok(bytes), Err(kind)],
                ..Self::default()
            }
        }
    }

    impl tokio::io::AsyncWrite for StubSink {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
            buffer: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let step = if self.write_steps.is_empty() {
                Ok(buffer.len())
            } else {
                self.write_steps.remove(0)
            };
            match step {
                Ok(written) => {
                    let written = written.min(buffer.len());
                    self.accepted.extend_from_slice(&buffer[..written]);
                    std::task::Poll::Ready(Ok(written))
                }
                Err(kind) => std::task::Poll::Ready(Err(std::io::Error::new(kind, "stub write"))),
            }
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if let Some(kind) = self.flush_error {
                return std::task::Poll::Ready(Err(std::io::Error::new(kind, "stub flush")));
            }
            self.flushes += 1;
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// A teardown that records its operations, injects one failure per stage and
    /// can hold a stage pending so the cleanup deadline (not an immediate error)
    /// cancels it.
    struct StubTeardown {
        log: std::sync::Mutex<Vec<String>>,
        failures: Vec<(&'static str, &'static str)>,
        pending: Vec<&'static str>,
        handle_dropped: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
        runtime_dropped: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    }

    impl StubTeardown {
        fn new() -> Self {
            Self {
                log: std::sync::Mutex::new(Vec::new()),
                failures: Vec::new(),
                pending: Vec::new(),
                handle_dropped: None,
                runtime_dropped: None,
            }
        }

        /// Hold `stage` pending until its outer deadline cancels it.
        fn pending_at(mut self, stage: &'static str) -> Self {
            self.pending.push(stage);
            self
        }

        /// Await forever for a scheduled-pending stage.
        async fn hold(&self, stage: &'static str) {
            if self.pending.contains(&stage) {
                std::future::pending::<()>().await
            }
        }

        fn failing(stage: &'static str, detail: &'static str) -> Self {
            Self {
                failures: vec![(stage, detail)],
                ..Self::new()
            }
        }

        fn failing_at(mut self, stage: &'static str, detail: &'static str) -> Self {
            self.failures.push((stage, detail));
            self
        }

        fn tracking_handle(
            mut self,
            handle_dropped: std::sync::Arc<std::sync::atomic::AtomicBool>,
        ) -> Self {
            self.handle_dropped = Some(handle_dropped);
            self
        }

        fn tracking_runtime(
            mut self,
            runtime_dropped: std::sync::Arc<std::sync::atomic::AtomicBool>,
        ) -> Self {
            self.runtime_dropped = Some(runtime_dropped);
            self
        }

        fn log(&self) -> Vec<String> {
            self.log.lock().unwrap().clone()
        }

        fn stage(&self, stage: &'static str) -> Result<()> {
            // Both must already be released: teardown takes the child-handle
            // mutex a still-live wait future (or the handle it belongs to)
            // would hold.
            if let Some(dropped) = &self.handle_dropped {
                assert!(
                    dropped.load(std::sync::atomic::Ordering::SeqCst),
                    "{stage} ran before the exec handle was dropped"
                );
            }
            if let Some(dropped) = &self.runtime_dropped {
                assert!(
                    dropped.load(std::sync::atomic::Ordering::SeqCst),
                    "{stage} ran before the polled runtime wait future was dropped"
                );
            }
            self.log.lock().unwrap().push(stage.to_string());
            match self.failures.iter().find(|(name, _)| *name == stage) {
                Some((_, detail)) => Err(anyhow::anyhow!("{detail}")),
                None => Ok(()),
            }
        }
    }

    impl ExecTeardown for StubTeardown {
        async fn stop_and_wait(&self) -> Result<()> {
            self.stage("stop")?;
            self.hold("stop").await;
            Ok(())
        }
        async fn kill_with_timeout(&self, _timeout: Duration) -> Result<()> {
            self.stage("kill")?;
            self.hold("kill").await;
            Ok(())
        }
        async fn wait(&self) -> Result<()> {
            self.stage("reap")?;
            self.hold("reap").await;
            Ok(())
        }
        async fn remove(&self) -> Result<()> {
            self.stage("remove")?;
            self.hold("remove").await;
            Ok(())
        }
    }

    /// A `RuntimeExit` future that never resolves and records its own drop, so a
    /// teardown can prove the **polled** wait future was cancelled, not merely
    /// that the event handle was.
    struct PendingRuntimeExit {
        dropped: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl std::future::Future for PendingRuntimeExit {
        type Output = microsandbox::MicrosandboxResult<std::process::ExitStatus>;

        fn poll(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            std::task::Poll::Pending
        }
    }

    impl Drop for PendingRuntimeExit {
        fn drop(&mut self) {
            self.dropped
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn stub_context() -> ExecContext<'static> {
        ExecContext {
            image: "stub-image",
            log_dir: "/logs/stub-sandbox",
        }
    }

    /// The two guest sinks of one stream run, named so they cannot be swapped.
    struct StreamSinks<'a> {
        stdout: &'a mut StubSink,
        stderr: &'a mut StubSink,
    }

    /// The caller-owned drop receipts a teardown asserts against.
    struct StreamReceipts {
        handle: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
        runtime: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    }

    impl StreamReceipts {
        fn none() -> Self {
            Self {
                handle: None,
                runtime: None,
            }
        }
    }

    /// Drive the production wrapper with a queued event list.
    async fn run_stream(
        teardown: &StubTeardown,
        events: Vec<microsandbox::sandbox::exec::ExecEvent>,
        sinks: StreamSinks<'_>,
        policy: OutputErrorPolicy,
    ) -> Result<i32> {
        run_stream_with_receipt(teardown, events, sinks, policy, StreamReceipts::none()).await
    }

    /// [`run_stream`] with caller-owned drop receipts for the event handle and
    /// the polled runtime wait future, so a teardown can assert both were
    /// released before it ran.
    async fn run_stream_with_receipt(
        teardown: &StubTeardown,
        events: Vec<microsandbox::sandbox::exec::ExecEvent>,
        sinks: StreamSinks<'_>,
        policy: OutputErrorPolicy,
        receipts: StreamReceipts,
    ) -> Result<i32> {
        let (sender, receiver) = tokio::sync::mpsc::channel(events.len().max(1) + 1);
        for event in events {
            sender.send(event).await.unwrap();
        }
        drop(sender);
        let handle = TrackingEvents {
            events: receiver,
            dropped: receipts
                .handle
                .unwrap_or_else(|| std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false))),
        };
        let runtime_exit: RuntimeExit<'_> = match receipts.runtime {
            Some(dropped) => Box::pin(PendingRuntimeExit { dropped }),
            None => runtime_never_exits(),
        };
        let StreamSinks { stdout, stderr } = sinks;
        stream_exec_with_cleanup(
            teardown,
            handle,
            runtime_exit,
            stdout,
            stderr,
            policy,
            stub_context(),
        )
        .await
    }

    #[tokio::test]
    async fn a_direct_sink_failure_is_a_launcher_failure_and_never_a_guest_success() {
        use microsandbox::sandbox::exec::ExecEvent;
        for (stream, then_flush, expected) in [
            ("stdout", false, "writing guest stdout failed"),
            ("stdout", true, "flushing guest stdout failed"),
            ("stderr", false, "writing guest stderr failed"),
            ("stderr", true, "flushing guest stderr failed"),
        ] {
            let teardown = StubTeardown::new();
            let mut stdout = StubSink::default();
            let mut stderr = StubSink::default();
            let bytes = b"secret-payload".to_vec().into();
            let sink = match stream {
                "stdout" => &mut stdout,
                _ => &mut stderr,
            };
            if then_flush {
                sink.flush_error = Some(std::io::ErrorKind::BrokenPipe);
            } else {
                // A real `write_all` partial-write schedule: the first poll
                // accepts three bytes and a later poll fails.
                *sink = StubSink::partial_then_error(3, std::io::ErrorKind::BrokenPipe);
            }
            let event = match stream {
                "stdout" => ExecEvent::Stdout(bytes),
                _ => ExecEvent::Stderr(bytes),
            };
            let result = run_stream(
                &teardown,
                vec![event, ExecEvent::Exited { code: 0 }],
                StreamSinks {
                    stdout: &mut stdout,
                    stderr: &mut stderr,
                },
                OutputErrorPolicy::DirectChecked,
            )
            .await;
            // A checked sink failure is an error; a queued Exited(0) never
            // overwrites it.
            assert!(result.is_err(), "{stream}");
            let message = format!("{:#}", result.unwrap_err());
            assert!(message.contains(expected), "{stream}: {message}");
            // No guest payload bytes appear in the diagnostic…
            assert!(!message.contains("secret-payload"), "{stream}: {message}");
            // …the write failure followed a real partial write, not a
            // zero-byte refusal…
            let accepted = match stream {
                "stdout" => &stdout.accepted,
                _ => &stderr.accepted,
            };
            let expected_accepted: &[u8] = if then_flush {
                b"secret-payload"
            } else {
                b"sec"
            };
            assert_eq!(accepted, expected_accepted, "{stream}");
            // …and the real teardown ran, in order.
            assert_eq!(teardown.log(), ["stop", "remove"], "{stream}");
        }
    }

    #[tokio::test]
    async fn the_legacy_sink_policy_keeps_a_guest_status_and_still_tries_flush() {
        use microsandbox::sandbox::exec::ExecEvent;
        let teardown = StubTeardown::new();
        let mut stdout = StubSink {
            write_steps: vec![Err(std::io::ErrorKind::BrokenPipe)],
            ..StubSink::default()
        };
        let mut stderr = StubSink {
            flush_error: Some(std::io::ErrorKind::BrokenPipe),
            ..StubSink::default()
        };
        let result = run_stream(
            &teardown,
            vec![
                ExecEvent::Stdout(b"out".to_vec().into()),
                ExecEvent::Stderr(b"err".to_vec().into()),
                ExecEvent::Exited { code: 7 },
            ],
            StreamSinks {
                stdout: &mut stdout,
                stderr: &mut stderr,
            },
            OutputErrorPolicy::LegacyBestEffort,
        )
        .await;
        assert_eq!(result.unwrap(), 7);
        // Flush is still attempted after the failed write, exactly as before.
        assert_eq!(stdout.flushes, 1);
        assert_eq!(stderr.flushes, 0);
        assert_eq!(stderr.accepted, b"err");
    }

    #[tokio::test]
    async fn a_stream_that_ends_without_exited_is_a_bounded_primary_failure() {
        use microsandbox::sandbox::exec::ExecEvent;
        let teardown = StubTeardown::new();
        let mut stdout = StubSink::default();
        let mut stderr = StubSink::default();
        let result = run_stream(
            &teardown,
            vec![ExecEvent::Stdout(b"partial".to_vec().into())],
            StreamSinks {
                stdout: &mut stdout,
                stderr: &mut stderr,
            },
            OutputErrorPolicy::DirectChecked,
        )
        .await;
        let message = format!("{:#}", result.unwrap_err());
        assert!(
            message.contains("event stream ended without Exited"),
            "{message}"
        );
        assert!(message.contains("/logs/stub-sandbox"), "{message}");
        assert_eq!(teardown.log(), ["stop", "remove"]);
    }

    #[tokio::test]
    async fn a_known_guest_status_survives_cleanup_and_a_cleanup_failure_does_not() {
        use microsandbox::sandbox::exec::ExecEvent;
        // Clean cleanup: the guest status is the result and the shared
        // after-exit cleanup accepts it.
        let teardown = StubTeardown::new();
        let mut stdout = StubSink::default();
        let mut stderr = StubSink::default();
        let exit = run_stream(
            &teardown,
            vec![ExecEvent::Exited { code: 7 }],
            StreamSinks {
                stdout: &mut stdout,
                stderr: &mut stderr,
            },
            OutputErrorPolicy::DirectChecked,
        )
        .await
        .unwrap();
        assert_eq!(exit, 7);
        let cleanup = cleanup_exec_sandbox(&teardown).await;
        assert!(cleanup.is_ok());
        assert!(cleanup_after_exit("probe", exit, cleanup).is_ok());

        // A stop failure escalates to kill+reap, is reported, and makes the
        // known guest status a launcher failure.
        let failing = StubTeardown::failing("stop", "stop went wrong");
        let exit = run_stream(
            &failing,
            vec![ExecEvent::Exited { code: 0 }],
            StreamSinks {
                stdout: &mut stdout,
                stderr: &mut stderr,
            },
            OutputErrorPolicy::DirectChecked,
        )
        .await
        .unwrap();
        assert_eq!(exit, 0);
        let cleanup = cleanup_exec_sandbox(&failing).await;
        let error = format!(
            "{:#}",
            cleanup_after_exit("probe", exit, cleanup).unwrap_err()
        );
        assert!(error.contains("guest command `probe` exited 0"), "{error}");
        assert!(error.contains("stop: stop went wrong"), "{error}");
        assert_eq!(failing.log(), ["stop", "kill", "reap", "remove"]);
    }

    #[tokio::test]
    async fn every_cleanup_step_is_attempted_and_each_failure_is_reported_in_order() {
        let teardown = StubTeardown::new()
            .failing_at("stop", "stop failed")
            .failing_at("kill", "kill failed")
            .failing_at("reap", "reap failed")
            .failing_at("remove", "remove failed");
        let cleanup = cleanup_exec_sandbox(&teardown).await;
        let message = format!("{:#}", cleanup.unwrap_err());
        assert_eq!(teardown.log(), ["stop", "kill", "reap", "remove"]);
        for expected in [
            "stop: stop failed",
            "kill: kill failed",
            "reap: reap failed",
            "remove: remove failed",
        ] {
            assert!(message.contains(expected), "{message}");
        }
        // A removal failure after a mostly-successful stop is still an error.
        let removal = StubTeardown::failing("remove", "removal failed");
        let message = format!("{:#}", cleanup_exec_sandbox(&removal).await.unwrap_err());
        assert!(message.contains("remove: removal failed"), "{message}");
        assert_eq!(removal.log(), ["stop", "remove"]);
    }

    #[tokio::test]
    async fn a_primary_sink_failure_and_a_cleanup_failure_keep_both_diagnostics() {
        use microsandbox::sandbox::exec::ExecEvent;
        let teardown = StubTeardown::failing("remove", "removal failed");
        let mut stdout = StubSink {
            write_steps: vec![Err(std::io::ErrorKind::BrokenPipe)],
            ..StubSink::default()
        };
        let mut stderr = StubSink::default();
        let result = run_stream(
            &teardown,
            vec![
                ExecEvent::Stdout(b"x".to_vec().into()),
                ExecEvent::Exited { code: 0 },
            ],
            StreamSinks {
                stdout: &mut stdout,
                stderr: &mut stderr,
            },
            OutputErrorPolicy::DirectChecked,
        )
        .await;
        let message = format!("{:#}", result.unwrap_err());
        let primary = message.find("writing guest stdout failed").unwrap();
        let cleanup = message.find("cleanup failed").unwrap();
        assert!(primary < cleanup, "{message}");
        assert!(message.contains("remove: removal failed"), "{message}");
        assert!(
            message.contains("full logs: /logs/stub-sandbox"),
            "{message}"
        );
    }

    #[tokio::test]
    async fn the_exec_handle_is_dropped_before_any_teardown_step() {
        use microsandbox::sandbox::exec::ExecEvent;
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let teardown = StubTeardown::new()
            .tracking_handle(dropped.clone())
            .failing_at("remove", "removal failed");
        let mut stdout = StubSink::default();
        let mut stderr = StubSink::default();
        let result = run_stream_with_receipt(
            &teardown,
            vec![
                ExecEvent::Stdout(b"x".to_vec().into()),
                ExecEvent::Exited { code: 3 },
            ],
            StreamSinks {
                stdout: &mut stdout,
                stderr: &mut stderr,
            },
            OutputErrorPolicy::LegacyBestEffort,
            StreamReceipts {
                handle: Some(dropped.clone()),
                runtime: None,
            },
        )
        .await;
        assert_eq!(result.unwrap(), 3);
        // The known guest status hands teardown to the shared cleanup path; the
        // teardown's own stage assertion requires the handle to be gone first.
        let cleanup = cleanup_exec_sandbox(&teardown).await;
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(teardown.log(), ["stop", "remove"]);
        assert!(cleanup.is_err(), "the injected removal failure is reported");
    }

    /// A teardown step left pending is cancelled by its bounded deadline, every
    /// later step still runs, and both exec handles the lifecycle owns — the
    /// event handle **and** the polled runtime wait future — are dropped before
    /// any teardown step begins. Paused time makes the real 10 s deadline
    /// deterministic instead of a slow sleep.
    #[tokio::test(start_paused = true)]
    async fn a_pending_teardown_step_hits_its_deadline_after_both_exec_handles_are_dropped() {
        use microsandbox::sandbox::exec::ExecEvent;
        let handle_dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let runtime_dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let teardown = StubTeardown::new()
            .tracking_handle(handle_dropped.clone())
            .tracking_runtime(runtime_dropped.clone())
            .pending_at("stop")
            .failing_at("remove", "removal failed");
        let mut stdout = StubSink::default();
        let mut stderr = StubSink {
            flush_error: Some(std::io::ErrorKind::BrokenPipe),
            ..StubSink::default()
        };
        let result = run_stream_with_receipt(
            &teardown,
            vec![
                ExecEvent::Stderr(b"err".to_vec().into()),
                ExecEvent::Exited { code: 0 },
            ],
            StreamSinks {
                stdout: &mut stdout,
                stderr: &mut stderr,
            },
            OutputErrorPolicy::DirectChecked,
            StreamReceipts {
                handle: Some(handle_dropped.clone()),
                runtime: Some(runtime_dropped.clone()),
            },
        )
        .await;
        let message = format!("{:#}", result.unwrap_err());
        // The primary failure stays first, the deadline and the later removal
        // failure follow in operation order.
        assert!(
            message.contains("flushing guest stderr failed"),
            "{message}"
        );
        assert!(
            message.contains(&format!("stop: timed out after {EXEC_STOP_TIMEOUT:?}")),
            "{message}"
        );
        assert!(message.contains("remove: removal failed"), "{message}");
        assert_eq!(teardown.log(), ["stop", "kill", "reap", "remove"]);
        // Both receipts were observed by the teardown's own stage assertion; the
        // read here keeps the requirement visible in this test too.
        assert!(handle_dropped.load(std::sync::atomic::Ordering::SeqCst));
        assert!(runtime_dropped.load(std::sync::atomic::Ordering::SeqCst));
    }
}
