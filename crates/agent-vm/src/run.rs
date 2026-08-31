//! `agent-vm <agent> [args...]` — boot a per-project sandbox and attach to
//! the chosen agent (or a shell).
//!
//! Phase 2 only knows about env-var auth (`ANTHROPIC_API_KEY`,
//! `OPENAI_API_KEY`); host-rooted refresh-able credentials land in
//! Phase 3/4.

use std::{
    env,
    io::IsTerminal as _,
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use microsandbox::{Sandbox, sandbox::PullPolicy};

use crate::layer;
use crate::mount;
use crate::session::ProjectSession;
use crate::user;

/// Paths that the guest will tmpfs-mount at boot, wiping anything our
/// `patch` builder baked into the rootfs underneath them. We refuse to mirror
/// a host project rooted here and fall back to `/workspace` instead.
const TMPFS_GUEST_PREFIXES: &[&str] = &["/tmp", "/run", "/dev/shm", "/var/run"];

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
///   pinned in `images/Dockerfile` for non-agent-vm uses of the image.
const GUEST_ALWAYS_ENV: &[(&str, &str)] = &[("IS_SANDBOX", "1"), ("LANG", "C.UTF-8")];

/// The launcher's baked fallback guest `PATH` — kept in sync by hand with
/// `images/Dockerfile`'s `ENV PATH=…`. Used only when the booted image's own
/// OCI config declares no `PATH` (e.g. the image metadata isn't cached yet
/// on a cold first run, before the pull that happens later in `launch()`).
/// See [`path_from_config_env`] and [`image_config_path_and_digest`].
const FALLBACK_GUEST_PATH: &str =
    "/opt/agent/.local/bin:/opt/agent/.claude/local/bin:/opt/agent/.opencode/bin:/usr/local/bin:/usr/bin:/usr/sbin:/bin";

/// Pulls the `PATH=` value out of an OCI config `env` vector (`KEY=VALUE`
/// entries). Returns `None` when absent or empty — either way the caller
/// falls back to [`FALLBACK_GUEST_PATH`]. The *last* `PATH=` entry wins,
/// matching how a shell applies successive assignments (an image config can
/// legally list `PATH` more than once across base+derived `ENV` layers).
fn path_from_config_env(env: &[String]) -> Option<String> {
    env.iter()
        .filter_map(|e| e.strip_prefix("PATH="))
        .next_back()
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
}

/// Best-effort read of the booted image's config `PATH`, plus the base
/// image's manifest digest (fed to the tooling-layer hash in `layer.rs`).
///
/// Any miss — image metadata not cached yet on a first run, an unparseable
/// image reference, or a cache I/O error — returns `(None, None)` so
/// `launch()` stays on [`FALLBACK_GUEST_PATH`] and defers the layer hash.
/// This is deliberately lenient: a PATH lookup failure must never abort a
/// launch that would otherwise have worked identically to today.
async fn image_config_path_and_digest(image: &str) -> (Option<String>, Option<String>) {
    let Ok(cache_dir) = crate::msb_install::effective_cache_dir() else {
        return (None, None);
    };
    let Ok(cache) = microsandbox_image::GlobalCache::new_async(&cache_dir).await else {
        return (None, None);
    };
    let Ok(reference) = image.parse::<microsandbox_image::Reference>() else {
        return (None, None);
    };
    match cache.read_image_metadata_async(&reference).await {
        Ok(Some(md)) => (path_from_config_env(&md.config.env), Some(md.manifest_digest)),
        _ => (None, None),
    }
}

/// `AGENT_VM_LAYER=""` (clap's `env` does not filter empty values) must
/// resolve as "unset", not as an explicit empty-path layer dir that would
/// hard-error `resolve_layer_dir` on a missing Dockerfile.
fn normalize_layer_flag(flag: Option<PathBuf>) -> Option<PathBuf> {
    flag.filter(|p| !p.as_os_str().is_empty())
}

/// Mirrors [`should_check_update`]'s flag-or-truthy-env pattern: the
/// `--yes` flag OR a truthy `AGENT_VM_YES` skips the interactive
/// tooling-layer-build confirmation, for CI/non-interactive callers. Truthy
/// values match the repo convention (`1|true|yes|on`, see `pull::env_truthy`).
fn should_auto_confirm(flag: bool, env_val: Option<&str>) -> bool {
    flag || matches!(env_val, Some("1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON"))
}

/// Interactive y/N confirmation before building a tooling layer (F3 in the
/// plan/ADR-0003).
///
/// When `auto` is set (`--yes` / `$AGENT_VM_YES`), always confirms without
/// prompting. Otherwise, when stdin isn't a terminal, returns an actionable
/// error rather than hanging on a `read_line` that will never receive
/// input — a non-interactive caller (CI, a script) needs to pass `--yes`
/// explicitly, not have the launch appear to hang.
async fn confirm_layer_build(tag: &str, auto: bool) -> Result<bool> {
    if auto {
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "tooling layer {tag} needs to be built, but stdin is not a terminal to confirm \
             interactively. Re-run with --yes, or set AGENT_VM_YES=1."
        );
    }
    eprint!("Build project tooling layer '{tag}'? [y/N] ");
    std::io::Write::flush(&mut std::io::stderr()).ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("reading tooling-layer build confirmation from stdin")?;
    let answer = line.trim().to_ascii_lowercase();
    Ok(answer == "y" || answer == "yes")
}

/// If the project declares a tooling layer, build+load it (lazily, hash-
/// cached, with confirmation on a miss — see ADR-0003) and return the
/// derived tag to boot instead of `base_image`. Returns `Ok(None)` when
/// there is no layer, so `launch()` boots `base_image` unchanged — a
/// non-layer project's behavior is byte-identical to before this function
/// existed.
///
/// Extracted out of `launch()` so the orchestration reads top-to-bottom
/// without the surrounding ~150 lines of mount/credential/network setup
/// interleaved with it, and so each step (cache hit, confirm, build, load)
/// is a single `?`-propagated call a reader can follow in order.
async fn resolve_boot_image_with_layer(
    base_image: &str,
    layer_flag: Option<&Path>,
    project_dir: &Path,
    auto_confirm: bool,
) -> Result<Option<String>> {
    let Some(layer_dir) = layer::resolve_layer_dir(layer_flag, project_dir)? else {
        return Ok(None);
    };

    // 1. Ensure the base is cached and get its manifest digest — needed
    //    both for the #12 content hash and to digest-pin docker's FROM
    //    (ADR-0003). Reuse the existing best-effort reader; only pull the
    //    base if it isn't cached yet (F4).
    let (_path, mut base_digest) = image_config_path_and_digest(base_image).await;
    if base_digest.is_none() {
        eprintln!("==> Tooling layer present; pulling base {base_image} first…");
        crate::pull::pull_image(base_image)
            .await
            .context("pulling base image to build the tooling layer FROM")?;
        base_digest = image_config_path_and_digest(base_image).await.1;
    }
    let base_digest = base_digest.context(
        "could not resolve base image digest after pull; cannot build a reproducible tooling layer",
    )?;

    // 2. Identity: content hash over the base digest + the layer directory
    //    tree. The tag IS the staleness check (see layer.rs's module doc).
    let id = layer::resolve(&layer_dir, project_dir, &base_digest)?;
    let cache_dir = crate::msb_install::effective_cache_dir()?;

    // 3. Hash hit ⇒ reuse the already-ingested derived image. No rebuild,
    //    no prompt — this is the common-case fast path on every launch
    //    after the first.
    if layer::derived_is_cached(&cache_dir, &id.tag).await? {
        eprintln!("==> Reusing cached tooling layer {}", id.tag);
        return Ok(Some(id.tag));
    }

    // 4. Hash miss (new project or an edited layer) ⇒ confirm, build, load.
    //    Any failure past this point is a hard fail — launch() must never
    //    silently fall back to booting the plain base with a missing
    //    toolchain (F2 in the plan/ADR-0003).
    layer::ensure_docker_buildx()?;
    if !confirm_layer_build(&id.tag, auto_confirm).await? {
        anyhow::bail!(
            "tooling layer {} not built (declined). Re-run and confirm, or pass --yes.",
            id.tag
        );
    }
    let pinned_base = layer::digest_pinned_base(base_image, &base_digest)?;
    // Under `cache_dir`, not the system tmp (AGENTS.md) — RAII-cleaned via
    // NamedTempFile's Drop regardless of how build/load below returns.
    let tar = tempfile::Builder::new()
        .prefix("agent-vm-layer-")
        .suffix(".tar")
        .tempfile_in(&cache_dir)
        .context("creating tooling-layer OCI archive tempfile")?;
    eprintln!("==> Building tooling layer {} …", id.tag);
    layer::build_derived_oci(&id, &pinned_base, tar.path())
        .await
        .with_context(|| format!("building tooling layer {}", id.tag))?;
    layer::load_derived_image(&cache_dir, tar.path(), &id.tag)
        .await
        .with_context(|| format!("loading tooling layer {} into the msb cache", id.tag))?;
    eprintln!("==> Tooling layer {} ready", id.tag);
    Ok(Some(id.tag))
}

fn guest_path_is_safe(project: &Path) -> bool {
    let s = match project.to_str() {
        Some(s) => s,
        None => return false,
    };
    !TMPFS_GUEST_PREFIXES
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

/// Which entry point to attach inside the sandbox.
#[derive(Clone, Copy, Debug)]
pub enum Agent {
    Claude,
    Codex,
    Opencode,
    Copilot,
    Shell,
}

impl Agent {
    fn command(self) -> &'static str {
        match self {
            Agent::Claude => "claude",
            Agent::Codex => "codex",
            Agent::Opencode => "opencode",
            Agent::Copilot => "copilot",
            Agent::Shell => "bash",
        }
    }

    /// Flags we always pass before the user's own args. The microVM is
    /// the security boundary, so the in-VM agent's "are you sure?"
    /// prompts add no protection and break agent-mode flows.
    ///
    /// `Agent::Shell` carries `-O histappend` so the interactive bash
    /// *appends* its in-memory history to the shared bind-mounted
    /// `~/.bash_history` on exit instead of overwriting it. Without
    /// this, two concurrent `agent-vm shell` invocations in the same
    /// project would have the later-exiting shell wholesale clobber
    /// the earlier shell's commands (the symlink target is the same
    /// host file — `.bash_history` in [`crate::session::GUEST_HOME_LINKS`],
    /// wired up per guest-user mode by the `.patch()` block in `launch()`
    /// (root mode) or [`crate::session::ProjectSession::provision_guest_home`]
    /// (non-root mode)).
    fn default_args(self) -> &'static [&'static str] {
        match self {
            Agent::Claude => &["--dangerously-skip-permissions"],
            Agent::Shell => &["-O", "histappend"],
            // Copilot CLI's `--allow-all-tools` disables its in-VM
            // "may I run this?" confirmations. The microVM is the
            // security boundary, so the extra prompts add no
            // protection and break non-interactive / agent-mode
            // flows — same reasoning as `--dangerously-skip-permissions`
            // for Claude. Drop it (`-> &[]`) if the user already
            // passed it; the filter in `launch` handles that.
            Agent::Copilot => &["--allow-all-tools"],
            Agent::Codex | Agent::Opencode => &[],
        }
    }
}

// Footer shown under `-h` (the short summary). A few high-value
// examples plus a pointer to `--help`. Printed verbatim by clap, so
// this is exactly what the user sees. One `Args` backs all five launch
// verbs (claude/codex/opencode/copilot/shell), so this footer can't vary
// per verb — the examples use `claude` and the header says so.
const LAUNCH_AFTER_HELP: &str = "\
Examples (claude shown; codex/opencode/shell take the same options):
  agent-vm claude                  launch Claude Code in the current project
  agent-vm shell                   open a bash shell instead
  agent-vm claude -p 8080:3000     publish guest :3000 to host 127.0.0.1:8080
  agent-vm claude -- --model opus  forward args to the agent (after --)

Trailing args go to the agent. Run with --help for networking, security, and env details.";

// Fuller footer shown under `--help`. Same single-`Args` constraint:
// claude/codex/opencode/copilot/shell all share this.
const LAUNCH_AFTER_LONG_HELP: &str = "\
Examples (claude shown; codex/opencode/shell take the same options):
  agent-vm claude                             launch in the current project
  agent-vm shell                              open a bash shell instead
  agent-vm shell -- cargo test                run one command, then exit
  agent-vm claude -- --model opus --resume    forward args to the agent
  agent-vm claude --memory 8 --cpus 4         a bigger sandbox
  agent-vm claude --mount ~/ref:ro            read-only extra mount
  agent-vm claude --mount ~/.claude/skills:ro:follow-links
                                               follow symlinks in a skills dir
  agent-vm claude --repo owner/other-repo     widen the GitHub allow-list

Networking (deny-by-default; flags compose):
  --publish        host  → guest   open an inbound port to a guest service
  --auto-publish   guest → host    mirror guest listeners onto host loopback
  --allow-egress   guest → IP/LAN  reach one IP or subnet
  --allow-lan      guest → LAN     reach the whole private range
  --allow-host     guest → host    reach the host's 127.0.0.1 services

Environment:
  AGENT_VM_MEMORY_GIB / AGENT_VM_CPUS   same as --memory / --cpus
  AGENT_VM_IMAGE_TAG                    same as --image
  AGENT_VM_ROOT                         same as --root (1|true|yes|on)
  AGENT_VM_UPDATE_CHECK                 check the registry for a newer image (1|true|yes|on)
  AGENT_VM_INSECURE_REGISTRY            allow plain-HTTP registry pulls
  AGENT_VM_STATE_DIR                    override the per-project state dir
  AGENT_VM_PROFILE                      print per-phase boot timings
  AGENT_VM_DEBUG_CONFIG                 dump the SandboxConfig JSON before boot
  AGENT_VM_NO_CHROME_MCP                disable Chrome MCP auto-configuration for Chrome-capable images
  RUST_LOG                              tracing filter (e.g. agent_vm=debug)";

#[derive(ClapArgs)]
#[command(after_help = LAUNCH_AFTER_HELP, after_long_help = LAUNCH_AFTER_LONG_HELP)]
pub struct Args {
    /// Sandbox memory, in GiB.
    #[arg(long, env = "AGENT_VM_MEMORY_GIB", default_value_t = 2,
          value_name = "GIB", help_heading = "Sandbox resources")]
    memory: u32,

    /// vCPU count for the sandbox.
    #[arg(long, env = "AGENT_VM_CPUS", default_value_t = 2,
          value_name = "N", help_heading = "Sandbox resources")]
    cpus: u8,

    /// Don't inject host gh/git credentials into the guest.
    ///
    /// With this set, no gh auth flows through the proxy and the guest
    /// agent can't `git push` / `gh pr create` etc. Useful for one-off
    /// throwaway sessions on a repo you don't trust the agent with.
    #[arg(long = "no-git", default_value_t = false, help_heading = "GitHub access")]
    no_git: bool,

    /// Add a repo to the GitHub allow-list (repeatable).
    ///
    /// The cwd's `git remote -v` GitHub entries are always included;
    /// use this to widen the allow-list for cross-repo work.
    #[arg(long = "repo", value_name = "OWNER/REPO", help_heading = "GitHub access")]
    repo: Vec<String>,

    /// Bind an extra host directory into the guest (repeatable).
    ///
    /// Format `HOST[:GUEST][:ro|:rw|:follow-links]`; `GUEST` defaults to
    /// `HOST` (mirror at the same absolute path). Append `:ro` for a
    /// read-only bind or `:rw` for read-write (the default). `GUEST`, if
    /// given, must be an absolute path (start with `/`); a trailing token
    /// that isn't a path is parsed as a mode keyword, e.g. `--mount ~/ref:ro`.
    ///
    /// `:follow-links` additionally walks `HOST` on the host side and, for
    /// every symlink it transitively contains that resolves to a directory,
    /// bind-mounts that *real* directory into the guest at its own real
    /// absolute host path. This is what makes symlinks whose target lies
    /// outside `HOST` (e.g. a skills directory full of `foo -> /elsewhere`
    /// links) resolve correctly in the guest — an ordinary bind mount only
    /// exposes the `HOST` subtree, so the guest's `readlink()` would name a
    /// path nothing is mounted at. `follow-links` implies `:ro` (bare
    /// `--mount ~/ref:follow-links` behaves as `ro`); combining it with
    /// `:rw` is a parse error. A resolved target outside your `$HOME` is a
    /// hard error; a symlink to a file, or a dangling symlink, is skipped
    /// with a warning. Example: `--mount ~/.claude/skills:ro:follow-links`.
    ///
    /// Each `--mount` (including each auto-discovered follow-links target)
    /// consumes one virtio-fs device shared with rootfs, network, vsock,
    /// console, and `--volume` disks. Capacity depends on the host interrupt
    /// model and runtime; do not treat a measurement from one platform as a
    /// portable mount limit.
    #[arg(long = "mount", value_name = "HOST[:GUEST][:ro|:rw|:follow-links]", help_heading = "Mounts & ports")]
    mount: Vec<String>,

    /// Publish a guest TCP port to the host, docker-style (repeatable).
    ///
    /// Format `[HOST_BIND:]HOST_PORT:GUEST_PORT`. HOST_BIND defaults to
    /// `127.0.0.1` — pass `0.0.0.0:HOST_PORT:GUEST_PORT` to expose on
    /// every host interface.
    ///
    /// The guest service must listen on `0.0.0.0` (or the assigned
    /// guest IP from `MSB_NET_IPV4`); a bare `127.0.0.1` bind inside
    /// the guest is not reachable because the smoltcp dial target is
    /// the guest's assigned VLAN address, not loopback.
    #[arg(long = "publish", short = 'p', value_name = "[BIND:]HOST_PORT:GUEST_PORT",
          help_heading = "Mounts & ports")]
    publish: Vec<String>,

    /// Auto-forward every guest listener onto the host (Lima-style).
    ///
    /// The runtime polls `/proc/net/tcp{,6}` inside the guest every ~2s
    /// and mirrors each detected wildcard (`0.0.0.0`/`[::]`) OR
    /// loopback (`127.0.0.1`/`[::1]`) TCP LISTEN socket onto a
    /// host listener at `127.0.0.1:<same port>` (or an ephemeral
    /// host port if the preferred one is taken). Loopback-only
    /// guest services are reachable via an in-guest agentd
    /// forwarder (`eth0_ip:port → 127.0.0.1:port`) — so anything
    /// listening inside the guest, whether on the wildcard
    /// interface or just loopback, becomes reachable on host
    /// `127.0.0.1`. agent-vm prints each new mapping to stderr as
    /// the runtime emits `PortEvent`s. Off by default.
    ///
    /// Security note: with this flag, every TCP service that
    /// becomes reachable inside the guest is also reachable from
    /// other processes on the host's loopback. If you don't want
    /// that, omit `--auto-publish` and use `--publish` to expose
    /// only the specific ports you mean to share.
    #[arg(long = "auto-publish", default_value_t = false, help_heading = "Mounts & ports")]
    auto_publish: bool,

    /// Allow guest egress to one IP or CIDR (repeatable).
    ///
    /// Examples: `--allow-egress 10.100.1.75` (single host),
    /// `--allow-egress 10.100.1.0/24` (CIDR),
    /// `--allow-egress fd00::1/128` (IPv6).
    ///
    /// The default policy (`NetworkPolicy::from_profiles([Public])`)
    /// only allows DNS and the `Public` destination group, so RFC1918
    /// (10/8, 172.16/12, 192.168/16, 100.64/10), loopback, link-
    /// local, and metadata addresses are all denied with
    /// ECONNREFUSED. Use this flag to reach a specific dev box on
    /// the same LAN as the host. Use `--allow-lan` instead if you
    /// want to open the entire Private group at once.
    #[arg(long = "allow-egress", value_name = "IP|CIDR", help_heading = "Network egress")]
    allow_egress: Vec<String>,

    /// Allow guest egress to the whole private LAN.
    ///
    /// Switches the egress policy from `from_profiles([Public])` to
    /// `from_profiles([Public, Private])` — adds the entire
    /// `DestinationGroup::Private` (10/8, 172.16/12, 192.168/16,
    /// 100.64/10, fc00::/7) to the allow list. Coarser than
    /// `--allow-egress <CIDR>`; useful for "trust everything on my
    /// LAN". Loopback, link-local, and metadata are still denied.
    ///
    /// Security note: a compromised in-guest process gets full
    /// access to every device on your LAN with this flag. Prefer
    /// `--allow-egress <CIDR>` for production-ish uses.
    #[arg(long = "allow-lan", default_value_t = false, help_heading = "Network egress")]
    allow_lan: bool,

    /// Allow the guest to reach the host's 127.0.0.1 services.
    ///
    /// The smoltcp stack rewrites the per-sandbox gateway IP
    /// (resolves as `host.microsandbox.internal` inside the guest)
    /// to host's loopback, so e.g. a dev server bound to
    /// `127.0.0.1:8080` on the host becomes reachable from the guest
    /// at `host.microsandbox.internal:8080`. Adds the
    /// `DestinationGroup::Host` (the gateway IP only) to the allow
    /// list; loopback, link-local, metadata, and the wider LAN
    /// remain denied.
    ///
    /// Security note: anything bound to the host's loopback —
    /// including admin UIs, dev DBs, the Docker socket if it's
    /// listening on a TCP port — becomes reachable from a possibly-
    /// compromised in-guest process. Use only when you actually need
    /// it.
    #[arg(long = "allow-host", default_value_t = false, help_heading = "Network egress")]
    allow_host: bool,

    /// Override the OCI image reference.
    ///
    /// Default: `ghcr.io/wirenboard/agent-vm-template:latest`. Use a
    /// timestamped tag (`...:YYYY-MM-DDTHH`) to pin a reproducible image.
    #[arg(long, env = "AGENT_VM_IMAGE_TAG", value_name = "REF", help_heading = "Image")]
    image: Option<String>,

    /// Check the registry for a newer image at launch (opt-in).
    ///
    /// HEADs the registry manifest and prints the "==> A newer image is
    /// available …" banner if the cached image is stale. Off by default so a
    /// normal launch makes no registry contact; run `agent-vm pull` to fetch an
    /// update. Can also be enabled persistently with a truthy
    /// `AGENT_VM_UPDATE_CHECK` (1|true|yes|on).
    #[arg(long = "update-check", default_value_t = false, help_heading = "Image")]
    update_check: bool,

    /// Tooling-layer directory (a Dockerfile built FROM the base image).
    ///
    /// Precedence: this flag, then $AGENT_VM_LAYER, then the default
    /// `.agent-vm/layer/` in the project. An explicitly-pointed-at dir
    /// missing a Dockerfile is an error; the default dir simply being
    /// absent means "no layer". When a layer is declared, the derived
    /// image (base + layer) is built, loaded registry-lessly, and booted
    /// in place of the base — see `docs/adr/0003-project-tooling-layers.md`.
    /// A hash miss (new/changed layer) prompts for confirmation unless
    /// `--yes` / `$AGENT_VM_YES` is set.
    #[arg(long = "layer", env = "AGENT_VM_LAYER", value_name = "DIR", help_heading = "Image")]
    layer: Option<PathBuf>,

    /// Assume "yes" to the tooling-layer build confirmation prompt.
    ///
    /// Needed for CI/non-interactive launches whenever the tooling-layer
    /// hash doesn't already match a previously built/loaded derived image
    /// (a new project, or an edited `.agent-vm/layer/Dockerfile`). Can also
    /// be set persistently with a truthy `AGENT_VM_YES` (1|true|yes|on).
    #[arg(long = "yes", short = 'y', default_value_t = false, help_heading = "Image")]
    yes: bool,

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
    root: bool,

    /// Args passed verbatim to the agent; use -- before any agent flags.
    ///
    /// Forwarded verbatim to the in-sandbox agent command. Use `--` if
    /// any argument starts with `-` to keep clap from claiming it.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
    agent_args: Vec<String>,
}

pub async fn launch(agent: Agent, args: Args) -> Result<i32> {
    // Fail fast if the private msb.db was forward-migrated by a newer
    // microsandbox than this build understands, instead of letting the SDK
    // surface sea-orm's opaque "Migration file ... is missing" error on
    // the first DB open (reap_stale_project_sandboxes below, then the
    // Sandbox builder). See src/msb_preflight.rs and issue #30.
    crate::msb_preflight::ensure_db_not_ahead().await?;

    // Resolve root vs. non-root guest mode up front — it gates dir
    // provisioning, the rootfs patch block, and the guest env/exec wiring
    // further down, so it has to be known before any of that runs.
    let root_mode = user::should_run_root(args.root, env::var("AGENT_VM_ROOT").ok().as_deref());
    let guest_identity = user::resolve_guest_identity(root_mode)?;
    // Independent of `guest_identity` (which is `None` under `--root`) so
    // the `--mount …:follow-links` $HOME guardrail is still enforced in
    // root mode instead of silently no-op'ing. See `mount::expand_follow_links`.
    let mount_home = env::var("HOME").ok().map(PathBuf::from);

    let session = ProjectSession::for_cwd()?;
    // AC#6 (agent-vm issue #40): fail closed, before touching the
    // filesystem or booting anything, if this sandbox's real agent/control
    // socket paths would overflow the platform's Unix-domain-socket path
    // limit. See `msb_install::ensure_socket_paths_fit`'s doc comment.
    crate::msb_install::ensure_socket_paths_fit(&session.sandbox_name)?;
    session.ensure_dirs()?;
    if !root_mode {
        session
            .provision_guest_home()
            .context("provisioning non-root guest HOME")?;
    }
    // Reap any orphan sandbox dirs left by earlier crashed launchers in
    // this same project before we boot. See
    // `reap_stale_project_sandboxes` for the full rationale.
    reap_stale_project_sandboxes(&session.project_hash).await;
    eprintln!(
        "==> {} in {} (state: {})",
        session.sandbox_name,
        session.project_dir.display(),
        session.state_dir.display(),
    );
    let _ = &session.project_hash;

    // `base_image` stays a separate binding from `image` for the lifetime of
    // `launch()`: the opt-in registry update-check below (run.rs:566ish)
    // must keep probing the *base*, never a reassigned tooling-layer tag,
    // which has no registry to probe (see the call site's comment there).
    let base_image = args
        .image
        .clone()
        .or_else(|| env::var("AGENT_VM_IMAGE_TAG").ok())
        .unwrap_or_else(|| crate::defaults::DEFAULT_IMAGE_REF.to_string());
    let mut image = base_image.clone();
    let memory_mib: u32 = args
        .memory
        .checked_mul(1024)
        .context("--memory in GiB overflows u32 MiB")?;
    let cpus = args.cpus;

    // Tooling-layer resolution (issue #13, on top of #12's identity-only
    // plumbing): if the project declares `.agent-vm/layer/Dockerfile`,
    // build+load the derived image now (lazily, hash-cached, with
    // confirmation on a miss) and boot it instead of the base. No layer ⇒
    // `image` is left as `base_image`, byte-identical to today.
    let layer_flag = normalize_layer_flag(args.layer.clone());
    let auto_confirm =
        should_auto_confirm(args.yes, env::var("AGENT_VM_YES").ok().as_deref());
    if let Some(derived) = resolve_boot_image_with_layer(
        &base_image,
        layer_flag.as_deref(),
        &session.project_dir,
        auto_confirm,
    )
    .await?
    {
        image = derived;
    }

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
    let host_path = session
        .project_dir
        .to_str()
        .context("project path contains non-UTF-8 bytes; not supported")?;
    let (project_guest_path, remap_reason) =
        resolve_project_guest_path(&session.project_dir, host_path);
    if let Some(reason) = remap_reason {
        eprintln!("==> Project path {host_path} {reason}; mounting at /workspace instead");
    }
    let mut patch_builder_steps = mkdir_chain(Path::new(&project_guest_path));
    // PullPolicy::IfMissing keeps the slow part (pull + materialize) off
    // every launch. We separately HEAD the manifest at the registry via
    // image_check::check_for_update and print a banner if there's a newer
    // image available — but only when opted in via `--update-check` /
    // `AGENT_VM_UPDATE_CHECK`; otherwise a normal launch makes no registry
    // contact at all. The user runs `agent-vm pull` explicitly to fetch it.
    let update_check_env = std::env::var("AGENT_VM_UPDATE_CHECK").ok();
    if should_check_update(args.update_check, update_check_env.as_deref()) {
        // The update banner is purely informational, so keep it OFF the
        // launch critical path: seed the baseline pulled-digest marker
        // (so the banner has something to compare against on this launch,
        // not just future ones) and probe the registry in the background.
        // The banner prints if the ~0.9s ghcr.io round-trip resolves
        // during boot; otherwise it's simply skipped and the next launch
        // catches up. Previously this was awaited and blocked every boot.
        //
        // Deliberately `base_image`, not `image`: when a tooling layer
        // reassigned `image` to the registry-less derived tag
        // (`agent-vm-layer:<hash>`), probing it would HEAD a nonexistent
        // registry ref and always miss. The pulled-marker + update banner
        // are a property of the base image the layer builds FROM.
        let img = base_image.clone();
        tokio::spawn(async move {
            seed_pulled_marker_if_absent(&img).await;
            notify_if_update_available(&img).await;
        });
    }

    // Snapshot host credentials into per-project token files and place
    // placeholder credentials.json files where the in-VM agents will
    // find them. The token files are passed to microsandbox below as
    // SecretValue::File entries; the proxy re-reads them on every
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
    let parsed_mounts = mount::parse_extra_mounts(&args.mount).context("parsing --mount")?;
    for em in &parsed_mounts {
        if !em.host.exists() {
            anyhow::bail!("--mount host path {:?} does not exist", em.host);
        }
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
            parsed_mounts.iter().map(|m| m.host.as_path()),
        ));
    } else if !args.repo.is_empty() {
        eprintln!(
            "==> --no-git skips cwd remote auto-detection, but --repo overrides are kept ({} entr{})",
            args.repo.len(),
            if args.repo.len() == 1 { "y" } else { "ies" },
        );
    }
    for r in &args.repo {
        let r = r.trim().to_string();
        if !r.is_empty() && !allowed_repos.iter().any(|x| x.eq_ignore_ascii_case(&r)) {
            allowed_repos.push(r);
        }
    }
    let use_github = !allowed_repos.is_empty();
    if use_github {
        eprintln!(
            "==> GitHub repo scope ({}): {}",
            allowed_repos.len(),
            allowed_repos.join(", "),
        );
    } else {
        eprintln!("==> GitHub repo scope: <none> (no api.github.com access)");
    }

    // D1: the Copilot API is reached with a GitHub OAuth token, but
    // unlike the gh CLI / repo-push path it is not repo-scoped — so
    // Copilot's token capture and egress must follow the *selected
    // agent*, not `use_github`. A user running `agent-vm copilot` in a
    // non-GitHub project (or with `--no-git`) still expects Copilot to
    // work; conversely a claude/codex/opencode/shell session in a
    // GitHub repo should NOT get Copilot egress opened or a duplicate
    // gh token written to a copilot secret file it never uses.
    let want_copilot = matches!(agent, Agent::Copilot);

    let creds =
        crate::secrets::refresh(&session.state_dir, &project_guest_path, use_github, want_copilot)
            .context("snapshotting host credentials")?;

    // D1: when Copilot is the selected agent but no usable token could
    // be captured, fail loudly here. Otherwise the guest would send
    // `Authorization: Bearer msb-copilot-placeholder-v2` to the Copilot
    // API with no registered substitution entry — the proxy drops the
    // connection (violation scan) or GitHub returns a confusing 401.
    if want_copilot && creds.copilot_token_file.is_none() {
        anyhow::bail!(
            "no GitHub Copilot token found on the host. Sign in on the host \
             (e.g. `gh auth login` with a Copilot seat, or run the Copilot \
             device-flow login that writes ~/.cache/claude-vm/copilot-token.json) \
             and retry, or pick another agent."
        );
    }

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
    if let Some(id) = &host_identity {
        eprintln!(
            "==> Git author identity: {} <{}>{}",
            id.name,
            id.email,
            id.gh_login
                .as_deref()
                .map(|l| format!(" (gh:{l})"))
                .unwrap_or_default(),
        );
    } else {
        eprintln!(
            "==> Git author identity: <none> (gh not logged in and no host gitconfig user.name/email; \
             in-VM `git commit` will refuse until you set one)"
        );
    }
    crate::secrets::write_guest_gh_config(
        &session.state_dir,
        creds.gh_token_file.is_some(),
        host_identity.as_ref(),
    )
    .context("writing guest gh/git config")?;

    // Phase 7 / issue #11: expand the parsed `--mount HOST[:GUEST]` extras —
    // appending one read-only mount per symlink-target directory that any
    // `:follow-links` entry's walk discovered, deduping repeats, and
    // rejecting guest-path collisions (see `mount::expand_follow_links`).
    // Reuses `parsed_mounts` from above rather than re-parsing `args.mount`
    // (that used to be a duplicate `parse_extra_mounts` call here). The
    // microsandbox runtime now enables msb_krun's userspace split irqchip
    // (requires msb_krun >= 0.1.13 — earlier versions' userspace IOAPIC
    // silently dropped IRQs on pin ≥ 32 and underflowed on RTE register
    // accesses). Device capacity remains host-specific, so this layer does
    // not impose a guessed portable cap on extra mounts (including
    // follow-links' discovered ones). See the vendored vm.rs `build_vm`
    // for details.
    let (extra_mounts, follow_link_warnings) =
        mount::expand_follow_links(parsed_mounts, mount_home.as_deref())
            .context("expanding --mount follow-links")?;
    for w in &follow_link_warnings {
        eprintln!("==> {w}");
    }
    // Belt-and-suspenders: `parse_extra_mounts` already canonicalize()s
    // every explicit HOST (which fails on a missing path), and every
    // discovered mount's host is a path `canonicalize()` just succeeded
    // on inside the follow-links walk — so this should never trip. Kept
    // as a cheap final guard rather than the real existence check.
    for em in &extra_mounts {
        if !em.host.exists() {
            anyhow::bail!("--mount host path {:?} does not exist", em.host);
        }
    }

    let is_local_registry = crate::pull::is_plain_http_registry(&image);
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
        .image(image.as_str())
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
    for volume in user::core_dir_volumes(
        guest_identity
            .as_ref()
            .map(|gi| (gi.host_home.as_str(), session.guest_home_dir())),
        &project_guest_path,
        &session.project_dir,
        &session.state_dir,
    ) {
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
    if let Some(gi) = &guest_identity {
        builder = builder.user(gi.user_spec.clone());
    }
    // Phase 7: extra `--mount HOST[:GUEST]` binds. Each gets its own
    // .volume() — and we also have to mkdir the guest path in the
    // patch builder so microsandbox's workdir/rootfs validation passes
    // (same dance as the project bind above).
    let mut extra_mount_mkdirs: Vec<String> = Vec::new();
    for em in &extra_mounts {
        eprintln!(
            "==> Mounting {} -> {}{}",
            em.host.display(),
            em.guest.display(),
            if em.readonly { " (read-only)" } else { "" }
        );
        let host = em.host.clone();
        let readonly = em.readonly;
        let guest_str = em
            .guest
            .to_str()
            .context("--mount guest path must be UTF-8")?
            .to_string();
        builder = builder.volume(guest_str.clone(), move |m| {
            mount::configure_extra_mount(m, host, readonly)
        });
        extra_mount_mkdirs.extend(mkdir_chain(&em.guest));
    }
    builder = builder
        .patch(|mut p| {
            for parent in extra_mount_mkdirs.drain(..) {
                p = p.mkdir(parent, None);
            }
            p
        });
    let mut builder = builder
        .patch(|mut p| {
            for parent in patch_builder_steps.drain(..) {
                p = p.mkdir(parent, None);
            }
            if root_mode {
                // Root mode: the dotfile symlinks live at un-shadowed
                // rootfs paths (/root/...), so baking them via `.patch()`
                // is correct — nothing mounts over /root at runtime.
                p = p
                    .mkdir("/root/.local", None)
                    .mkdir("/root/.local/share", None)
                    .mkdir("/root/.config", None);
                for (suffix, target_name) in crate::session::GUEST_HOME_LINKS {
                    p = p.symlink(
                        format!("/agent-vm-state/{target_name}"),
                        format!("/root/{suffix}"),
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
                p = p.append(
                    "/etc/passwd",
                    user::passwd_append_line(&gi.username, gi.uid, gi.gid, &gi.host_home),
                );
                // See `group_append_line`'s doc comment (user.rs) for why
                // gids in the system-reserved range are skipped.
                if let Some(line) = user::group_append_line(gi.gid) {
                    p = p.append("/etc/group", line);
                }
                p
            }
        })
        .env("CODEX_HOME", "/agent-vm-state/codex");

    // Parse `--publish` into PublishedPort entries up front so we can
    // wire them into the network builder below (the same place that
    // sets up secrets/intercept). Done outside the conditional so it
    // bails early on syntax errors regardless of cred state.
    let publish_ports = parse_publish_args(&args.publish).context("parsing --publish")?;
    for p in &publish_ports {
        eprintln!(
            "==> Publishing host {}:{}/{} → guest :{}",
            p.host_bind,
            p.host_port,
            match p.protocol {
                PublishProto::Tcp => "tcp",
                PublishProto::Udp => "udp",
            },
            p.guest_port,
        );
    }

    // Parse --allow-egress entries into IpNetwork values. Same
    // up-front-bail rule as --publish: syntax errors fail before
    // we boot the sandbox.
    let allow_egress_cidrs =
        parse_allow_egress(&args.allow_egress).context("parsing --allow-egress")?;
    for cidr in &allow_egress_cidrs {
        eprintln!("==> Egress policy: allowing {cidr}");
    }
    if args.allow_lan {
        eprintln!(
            "==> Egress policy: --allow-lan enabled (Private RFC1918 + 100.64/10 + fc00::/7 reachable)"
        );
    }
    if args.allow_host {
        eprintln!(
            "==> Egress policy: --allow-host enabled (host.microsandbox.internal → host 127.0.0.1 reachable)"
        );
    }

    // The netstack (`HostHttpProxyConnector::from_env()`) auto-installs a
    // guest-egress HTTP-CONNECT proxy from the operator's own env — nothing
    // to wire here, just surface confirmation at launch time matching the
    // `==> Egress policy: ...` banners above. Deliberately conditional
    // wording: the netstack silently falls back to direct egress when the
    // value isn't a usable `http://` proxy (see `active_guest_proxy_var`),
    // so this banner must not promise routing agent-vm can't guarantee.
    if let Some((var, value)) = active_guest_proxy_var() {
        eprintln!(
            "==> Guest egress proxy: {var}={value} (used when it parses as an \
             http:// proxy; NO_PROXY honored, otherwise egress goes direct)"
        );
    }

    let auto_publish = args.auto_publish;
    let allow_lan = args.allow_lan;
    let allow_host = args.allow_host;

    // For each provider with a host credential file, register a
    // SecretValue::File secret keyed on the placeholder string the
    // guest will send, then register the OAuth refresh endpoint as a
    // hook target so a 401-then-refresh attempt round-trips through a
    // real host-side rotation (see `intercept_hook`).
    //
    // The baseline now has the fork's file-backed `SecretSource` (re-read
    // on every connection, so a host-side token rotation propagates
    // without restarting the sandbox) and its per-route intercept-hook
    // dispatcher (`NetworkBuilder::intercept()`) — but agent-vm's
    // secrets.rs/intercept_hook.rs aren't wired onto them yet (issue
    // gregwebs/agent-vm#51). Rather than silently baking each file's
    // *current* contents into a static secret (dropping the rotation
    // guarantee and risking a leaked stale token on a later refresh), a
    // launch that actually needs credential injection fails closed.
    // `agent-vm shell --no-git` on a host with cached credentials is NOT
    // such a launch — Shell never speaks to a provider/GitHub API on the
    // guest's behalf — so it keeps booting. See `fail_closed.rs` for the
    // exact criteria.
    let has_creds = creds.anthropic_token_file.is_some()
        || creds.openai_token_file.is_some()
        || creds.gh_token_file.is_some()
        || creds.copilot_token_file.is_some();
    let needs_credential_injection =
        !args.no_git || crate::fail_closed::agent_requires_credentials(agent);
    crate::fail_closed::check_credential_injection_unneeded(has_creds, needs_credential_injection)?;

    let egress_policy = build_egress_policy(allow_lan, allow_host, &allow_egress_cidrs);
    if egress_policy.is_some() || !publish_ports.is_empty() || auto_publish {
        let policy = egress_policy.clone();
        let publish_ports_for_net = publish_ports.clone();
        // Gate `.tls()` on published ports exactly as before this PR.
        // `TlsBuilder::new()` defaults `enabled: true`, so calling `.tls()`
        // unconditionally would switch on MITM interception (and push the
        // sandbox CA into the guest) for a pure egress-override or
        // auto-publish launch that needs none of that — an unintended
        // widening neither feature asked for.
        let enable_tls = !publish_ports.is_empty();
        builder = builder.network(move |mut n| {
            if let Some(p) = policy {
                n = n.policy(p);
            }
            if enable_tls {
                n = n.tls(|t| t);
            }
            for p in &publish_ports_for_net {
                let host_bind = p.host_bind;
                n = match p.protocol {
                    PublishProto::Tcp => n.port_bind(host_bind, p.host_port, p.guest_port),
                    PublishProto::Udp => n.port_udp_bind(host_bind, p.host_port, p.guest_port),
                };
            }
            if auto_publish {
                n = n.auto_publish();
            }
            n
        });
    }

    // Still honour ANTHROPIC_API_KEY / OPENAI_API_KEY if explicitly set
    // by the user — that path stays a simple Bearer header, no
    // placeholder substitution involved.
    for var in ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"] {
        if let Ok(val) = env::var(var) {
            if !val.is_empty() {
                builder = builder.env(var, val);
            }
        }
    }
    // The image's PATH was set inside the Dockerfile, but it lives in the
    // shell rc files of /root. attach() launches the agent directly via
    // execve, so re-publish the same PATH here.
    //
    // Agent binaries live under the shared, world-readable /opt/agent
    // prefix (not /root) so both root and non-root guests resolve them
    // identically. `/usr/sbin` is here because dockerd, runc, iptables and
    // docker-proxy live there in debian, and dockerd does PATH lookups for
    // its helper binaries at runtime (not just at exec).
    //
    // The value now comes from the booted image's own OCI config `Env`
    // (`PATH=…`) rather than a hard-coded literal, so a tooling-layer's
    // `ENV PATH=/project/bin:$PATH` actually reaches the guest exec
    // environment. FALLBACK_GUEST_PATH — kept in sync by hand with the
    // `ENV PATH=…` in images/Dockerfile — is used only when the image
    // metadata isn't available (e.g. a cold cache on first run, before this
    // launch's own pull completes); for the base image the two are
    // byte-identical today, so this is behavior-identical in the common
    // case.
    // Reads the *derived* image's config once a tooling layer reassigned
    // `image` above, so a layer's `ENV PATH=/project/bin:$PATH` actually
    // reaches the guest exec environment (the whole point of #12's
    // PATH-from-config change). The manifest digest this call also returns
    // is unused here — `resolve_boot_image_with_layer` already fetched and
    // used the *base* image's digest earlier, before any build — so only
    // the PATH half of the tuple is bound.
    let (config_path, _) = image_config_path_and_digest(&image).await;
    let guest_path = config_path.unwrap_or_else(|| FALLBACK_GUEST_PATH.to_string());
    builder = builder.env("PATH", guest_path);

    // Non-root mode: mirror the host's own $HOME and username into the
    // guest (ADR-0002) — HOME is the host's literal $HOME string, USER/
    // LOGNAME the env-first-resolved username, both from
    // guest_identity. agentd also derives HOME from the /etc/passwd
    // entry appended above, but an explicit exec-env HOME wins over that
    // and is unambiguous either way. Root mode needs none of this — the
    // image's own ENV HOME=/root and the root passwd entry already do
    // the job.
    if let Some(gi) = &guest_identity {
        for (key, value) in user::guest_identity_env(gi) {
            builder = builder.env(key, value);
        }
    }

    // Environment injected into every guest regardless of agent/project.
    // Kept as one list so the set is discoverable and guard-testable (see
    // `guest_always_env_pins_utf8_locale_and_sandbox_flag`).
    for (key, value) in GUEST_ALWAYS_ENV {
        builder = builder.env(*key, *value);
    }

    // D1: GitHub Copilot CLI reads its token from COPILOT_GITHUB_TOKEN.
    // Hand it the placeholder; the credential proxy substitutes the real
    // GitHub OAuth token for it on the wire to the Copilot API. We set
    // it via env (not just ~/.copilot/config.json) because attach()'s
    // execve never sources /etc/profile.d, unlike the original Bash
    // agent-vm.
    //
    // Only set when Copilot is the selected agent. Exporting the
    // placeholder for a claude/codex/opencode/shell session would have
    // the guest emit `Authorization: Bearer msb-copilot-placeholder-v2`
    // to the Copilot API with no registered substitution entry (the
    // copilot secret is gated on the same condition above), which the
    // proxy drops as a violation or GitHub rejects with a 401. By here,
    // a Copilot launch is guaranteed to have a captured token (we bailed
    // earlier otherwise), so the placeholder always resolves.
    if want_copilot {
        builder = builder.env(
            "COPILOT_GITHUB_TOKEN",
            crate::secrets::COPILOT_TOKEN_PLACEHOLDER,
        );
    }

    let profile = env::var("AGENT_VM_PROFILE").is_ok();
    eprintln!(
        "==> Booting sandbox from {image} ({memory_mib} MiB, {cpus} vCPU; first run pulls layers, otherwise ~3s)"
    );
    let t_create = Instant::now();
    let config = builder.build().await.context("preparing sandbox config")?;
    if env::var("AGENT_VM_DEBUG_CONFIG").is_ok() {
        eprintln!(
            "[debug] sandbox config JSON: {}",
            serde_json::to_string_pretty(&config).unwrap_or_default()
        );
    }
    let (progress, task) = Sandbox::create_with_pull_progress(config);
    let render_task = tokio::spawn(crate::pull_progress::render(progress));
    // See pull.rs: await render before propagating errors so finish()
    // clears the bars, and use the logging helper so render-task panics
    // are visible instead of silently swallowed.
    let result = task
        .await
        .context("create-with-pull-progress join")
        .and_then(|inner| inner.context("creating sandbox"));
    crate::pull_progress::await_render(render_task).await;
    let sandbox = result?;
    if profile {
        eprintln!("[profile] create: {:?}", t_create.elapsed());
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

    // Confirm the image's API contract matches what this binary
    // expects. Out-of-range → clear actionable error instead of
    // mysterious mount-not-found / agent-crashing-on-startup
    // failures inside the VM.
    let image_api = crate::image_api_version::check(&sandbox)
        .await
        .context("verifying image-API contract version")?;
    let chrome_mcp_enabled = crate::image_capabilities::chrome_mcp_enabled(
        &sandbox,
        &image,
        image_api,
        env::var_os("AGENT_VM_NO_CHROME_MCP").is_some(),
    )
    .await;
    crate::secrets::sync_chrome_mcp(&session.state_dir, chrome_mcp_enabled)
        .context("synchronizing Chrome MCP configuration")?;

    // Subscribe to the runtime's auto-publish event stream and surface each
    // mapping to the user. Only spawned when `--auto-publish` was requested
    // — `Sandbox::port_events()` allows only one subscriber per
    // `AgentClient` (a second call overwrites the first), and this is the
    // sole caller today. The loop ends on its own when `recv()` yields
    // `None` (sandbox stopped), so nothing further needs to guard the task.
    if args.auto_publish {
        eprintln!("==> auto-publish: watching guest LISTEN sockets via /proc/net/tcp{{,6}}");
        let sb_for_events = sandbox.clone();
        tokio::spawn(async move {
            use microsandbox::protocol::network::PortEvent;
            let mut events = sb_for_events.port_events().await;
            while let Some(event) = events.recv().await {
                match event {
                    PortEvent::Added {
                        host_bind,
                        host_port,
                        guest_port,
                    } => {
                        eprintln!(
                            "==> auto-published guest :{guest_port} -> host {host_bind}:{host_port}"
                        );
                    }
                    PortEvent::Removed { guest_port, .. } => {
                        eprintln!("==> auto-publish removed :{guest_port}");
                    }
                }
            }
        });
    }

    let inner_cmd = agent.command();
    // Prepend agent-vm's default flags (e.g. --dangerously-skip-permissions
    // for Claude) unless the user already provided them.
    let mut inner_args: Vec<String> = agent
        .default_args()
        .iter()
        .filter(|d| !args.agent_args.iter().any(|u| u == *d))
        .map(|s| s.to_string())
        .collect();
    if matches!(agent, Agent::Shell) && !args.agent_args.is_empty() {
        // `agent-vm shell foo bar` runs `foo bar` as a command. Without
        // `-c`, bash treats the first non-option positional as a script
        // filename and PATH-searches for it, so `agent-vm shell ls` lands
        // on `/usr/bin/ls` and prints "cannot execute binary file" the
        // moment bash hits the ELF magic. Joining the user's args into a
        // single `-c` command line (each arg shell-escaped so quoting is
        // preserved across the boundary) is the standard fix.
        let cmd = args
            .agent_args
            .iter()
            .map(|a| shell_escape(a))
            .collect::<Vec<_>>()
            .join(" ");
        inner_args.push("-c".into());
        inner_args.push(cmd);
    } else {
        inner_args.extend(args.agent_args);
    }

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
    // DB — needed because chromium on Linux ignores the system CA bundle
    // and honours only its per-user NSS DB, so the chrome-devtools MCP
    // would otherwise fail every HTTPS page with ERR_CERT_AUTHORITY_INVALID
    // — used to run here, a ~270ms `certutil` fork on *every* launch's
    // critical path. It now lives in the in-image `agent-vm-chrome-mcp`
    // wrapper, so it runs once when the chrome MCP actually starts: off
    // the launch path, and skipped entirely when chrome is unused. The CA
    // is per-install (not bakeable into the shared image); see the opt-in
    // Chrome DevTools layer wrapper. So no chrome prelude is injected here anymore —
    // we pass an empty string for it.
    //
    // Assemble the in-guest `bash -c` line via `build_agent_shell_line`,
    // which is unit-tested directly. The IPv6-nameserver strip is the
    // `STRIP_IPV6_NAMESERVERS` const (see its doc comment / PLAN.md B3).
    let shell_line = build_agent_shell_line(
        &project_guest_path,
        "",
        inner_cmd,
        &inner_args,
    );
    let cmd = "bash";
    let agent_args: Vec<String> = vec!["-c".into(), shell_line];

    let t_run = Instant::now();
    let exit = if std::io::stdin().is_terminal() {
        eprintln!("==> Attaching to {inner_cmd}");
        // Pin the agent's cwd to the real project path via the exec request
        // (vsock, byte-safe), NOT libkrun's `KRUN_WORKDIR` — which may be the
        // ASCII `/` placeholder for a non-ASCII project. `attach()` alone
        // leaves cwd unset, falling back to that placeholder; `attach_with`
        // lets us set it, matching the streaming path below.
        sandbox
            .attach_with(cmd, |a| {
                // PID 1 (agentd) must stay root to `setuid` per exec, so
                // this per-exec `.user(...)` governs the exec'd process's
                // actual uid. It's independent of the sandbox-builder
                // `.user()` set above (MSB_USER → InitResolved.default_user
                // → passthroughfs's BindIdentityMap, for bind-mounted file
                // owner bits) — both calls are load-bearing, for different
                // reasons; neither is a substitute for the other.
                let mut a = a.args(agent_args).cwd(project_guest_path.clone());
                if let Some(gi) = &guest_identity {
                    a = a.user(gi.user_spec.clone());
                }
                a
            })
            .await
            .with_context(|| {
                format!(
                    "attaching to {inner_cmd} (full logs: {})",
                    sandbox_log_dir(&session.sandbox_name).display()
                )
            })?
    } else {
        // No host TTY (piped, redirected, smoke-tested under `sg`/`sudo` etc.).
        // attach() needs a real /dev/tty for raw-mode stdin, so use the
        // streaming exec API instead: write stdout/stderr to ours as they
        // arrive. That keeps progress visible on long-running agent
        // commands (codex exec can take >30s for a single response) and
        // lets us inspect partial output when the user Ctrl-Cs or the
        // shell times out.
        eprintln!("==> Running {inner_cmd} in sandbox (no TTY; streaming output)");
        use microsandbox::sandbox::exec::ExecEvent;
        use tokio::io::AsyncWriteExt as _;
        let mut handle = sandbox
            .exec_stream_with(cmd, |e| {
                let mut e = e.args(agent_args).cwd(project_guest_path.clone());
                if let Some(gi) = &guest_identity {
                    e = e.user(gi.user_spec.clone());
                }
                e
            })
            .await
            .with_context(|| {
                format!(
                    "running {inner_cmd} in sandbox (full logs: {})",
                    sandbox_log_dir(&session.sandbox_name).display()
                )
            })?;
        let mut stdout = tokio::io::stdout();
        let mut stderr = tokio::io::stderr();
        // Race the exec event stream against the sandbox's own runtime exit
        // (issue #41): if the msb VMM child dies mid-session, the relay
        // socket closing should already end the event stream (`recv()` ->
        // `None`), but that relies on the SDK's reader loop observing the
        // socket EOF promptly. This is the belt-and-suspenders backstop —
        // `sandbox.wait()` resolving first means the exec await can never
        // hang on a VMM that's already gone, no matter how the event stream
        // behaves.
        //
        // Follow-up fix (verified live, see verifications.md item 3): on a
        // real VMM kill, the relay socket EOFs essentially instantly, so
        // `events.recv() -> None` wins this race against `sandbox.wait()`
        // completing almost every time. If we reported a plain
        // "stream ended" diagnostic right there, `sandbox.wait()`'s exit
        // classification — and the `msb-exit.log` post-mortem write it
        // performs — would never happen, because the future backing this
        // race would be dropped mid-flight. `next_exec_step` now gives
        // `runtime_exit` a bounded chance to finish *after* observing the
        // stream close, so the classification/log-write reliably happens
        // before we report anything.
        let mut runtime_exit: RuntimeExit = Box::pin(sandbox.wait());
        // Track whether we actually saw an Exited event. The previous
        // `let mut code = 1` conflated "stream closed without Exited"
        // (infra failure) with "agent exited with 1" (real failure) —
        // CI couldn't tell them apart. Review finding #9. Now we
        // return Err on premature stream close so the launcher
        // bubbles up an actionable error.
        let mut exit_code: Option<i32> = None;
        let mut stream_ended_without_exit = false;
        loop {
            match next_exec_step(
                &mut handle,
                &mut runtime_exit,
                STREAM_END_RUNTIME_EXIT_GRACE,
            )
            .await
            {
                ExecStep::Event(ExecEvent::Stdout(b)) => {
                    stdout.write_all(&b).await.ok();
                    stdout.flush().await.ok();
                }
                ExecStep::Event(ExecEvent::Stderr(b)) => {
                    stderr.write_all(&b).await.ok();
                    stderr.flush().await.ok();
                }
                ExecStep::Event(ExecEvent::Exited { code: c }) => {
                    exit_code = Some(c);
                    break;
                }
                ExecStep::Event(ExecEvent::Failed(payload)) => {
                    anyhow::bail!(
                        "exec session failed: {payload:?} (full logs: {})",
                        sandbox_log_dir(&session.sandbox_name).display()
                    );
                }
                ExecStep::Event(ExecEvent::Started { .. } | ExecEvent::StdinError(_)) => {}
                ExecStep::StreamEnded => {
                    stream_ended_without_exit = true;
                    break;
                }
                ExecStep::RuntimeExited(detail) => {
                    anyhow::bail!(
                        "sandbox process exited unexpectedly while the exec stream was still \
                         open ({detail}); partial output above; see msb-exit.log under {} for \
                         the VMM's post-mortem record",
                        sandbox_log_dir(&session.sandbox_name).display()
                    );
                }
            }
        }
        match exit_code {
            Some(c) => c,
            None if stream_ended_without_exit => anyhow::bail!(
                "exec session event stream ended without Exited (agentd disconnect or microsandbox bug; partial output above; full logs: {})",
                sandbox_log_dir(&session.sandbox_name).display()
            ),
            None => unreachable!("loop only exits via Exited, StreamEnded, or an Err bail!"),
        }
    };

    if profile {
        eprintln!("[profile] run:    {:?}", t_run.elapsed());
    }

    eprintln!("==> Stopping sandbox");
    let t_stop = Instant::now();
    sandbox.stop_and_wait().await.ok();
    if profile {
        eprintln!("[profile] stop:   {:?}", t_stop.elapsed());
    }
    let t_remove = Instant::now();
    Sandbox::remove(&session.sandbox_name).await.ok();
    if profile {
        eprintln!("[profile] remove: {:?}", t_remove.elapsed());
    }

    // Phase 5 safety net (host-cred mutation check) runs via the
    // SnapshotGuard above, which drops at end of scope including
    // any `?`-propagated error path.

    Ok(exit)
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
    microsandbox_sandboxes_root().join(sandbox_name).join("logs")
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

/// One `--publish [HOST_BIND:]HOST_PORT:GUEST_PORT[/proto]` entry, parsed.
#[derive(Clone, Debug)]
struct PublishPort {
    host_bind: std::net::IpAddr,
    host_port: u16,
    guest_port: u16,
    protocol: PublishProto,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublishProto {
    Tcp,
    /// Reserved for when the underlying PortPublisher gains UDP
    /// support. Parser currently rejects `/udp` so this variant
    /// is unreachable from user input, but kept so the eventual
    /// enable change is a single-site edit.
    #[allow(dead_code)]
    Udp,
}

/// Parse `--publish` entries. Accepts docker-style:
///   `HOST_PORT:GUEST_PORT`                 → 127.0.0.1 bind, TCP
///   `HOST_IP:HOST_PORT:GUEST_PORT`         → explicit IPv4 bind
///   `[HOST_IP6]:HOST_PORT:GUEST_PORT`      → explicit IPv6 bind (bracket form)
///   any of the above + `/tcp` (UDP rejected — not implemented)
///
/// The connection enters the smoltcp in-process stack as a dial to
/// the guest's assigned MSB_NET_IPV4 (or v6) on `GUEST_PORT`, so the
/// in-guest service has to listen on `0.0.0.0`/`::` (or that exact
/// guest IP) — a bare `127.0.0.1` bind inside the guest is not
/// reachable from the publisher.
///
/// `/udp` is parsed but REJECTED with a clear error: the underlying
/// `PortPublisher::spawn_listener_one` short-circuits non-TCP ports
/// silently, so silently accepting `/udp` would leave the user with
/// a "published" port that has no listener. When UDP support lands
/// upstream, drop the rejection here.
fn parse_publish_args(raw: &[String]) -> Result<Vec<PublishPort>> {
    use std::net::IpAddr;
    let mut out = Vec::with_capacity(raw.len());
    for entry in raw {
        let (body, proto) = match entry.rsplit_once('/') {
            Some((b, p)) if matches!(p, "tcp" | "udp" | "TCP" | "UDP") => {
                (b, p.to_ascii_lowercase())
            }
            _ => (entry.as_str(), "tcp".to_string()),
        };
        if proto == "udp" {
            anyhow::bail!(
                "--publish {entry:?}: UDP is not yet supported by the underlying smoltcp \
                 PortPublisher; remove `/udp` to publish a TCP port instead"
            );
        }
        let protocol = PublishProto::Tcp;

        // Split off an IPv6 bracketed prefix first (docker convention)
        // so `[::1]:8080:80` doesn't trip the generic colon split.
        let (host_bind, rest) = if let Some(after_bracket) = body.strip_prefix('[') {
            let (v6_str, after) = after_bracket.split_once("]:").ok_or_else(|| {
                anyhow::anyhow!(
                    "--publish {entry:?}: bracketed IPv6 must be `[ADDR]:HOST_PORT:GUEST_PORT`"
                )
            })?;
            let addr = v6_str.parse::<std::net::Ipv6Addr>().with_context(|| {
                format!("--publish {entry:?}: HOST_BIND {v6_str:?} is not an IPv6")
            })?;
            (Some(IpAddr::V6(addr)), after)
        } else {
            (None, body)
        };

        let parts: Vec<&str> = rest.split(':').collect();
        let (host_bind, host_port, guest_port) = match (host_bind, parts.as_slice()) {
            (Some(bind), [h, g]) => (
                bind,
                parse_port(entry, "HOST_PORT", h)?,
                parse_port(entry, "GUEST_PORT", g)?,
            ),
            (None, [h, g]) => (
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                parse_port(entry, "HOST_PORT", h)?,
                parse_port(entry, "GUEST_PORT", g)?,
            ),
            (None, [ip, h, g]) => (
                ip.parse::<IpAddr>().with_context(|| {
                    format!("--publish {entry:?}: HOST_BIND {ip:?} is not an IP")
                })?,
                parse_port(entry, "HOST_PORT", h)?,
                parse_port(entry, "GUEST_PORT", g)?,
            ),
            _ => anyhow::bail!(
                "--publish {entry:?} must be [HOST_BIND:]HOST_PORT:GUEST_PORT or \
                 [IPv6_BIND]:HOST_PORT:GUEST_PORT"
            ),
        };
        if host_port == 0 || guest_port == 0 {
            anyhow::bail!("--publish {entry:?}: port 0 is not allowed");
        }
        out.push(PublishPort {
            host_bind,
            host_port,
            guest_port,
            protocol,
        });
    }
    Ok(out)
}

fn parse_port(entry: &str, field: &str, s: &str) -> Result<u16> {
    s.parse::<u16>()
        .with_context(|| format!("--publish {entry:?}: {field} {s:?} is not a u16"))
}

/// Parse `--allow-egress` entries. Each entry is an IP literal or
/// a CIDR (e.g. `10.100.1.75` or `10.100.1.0/24`). A bare IP is
/// expanded to a /32 (v4) or /128 (v6) CIDR — that matches the
/// shape the policy builder's `Destination::Cidr` expects.
fn parse_allow_egress(raw: &[String]) -> Result<Vec<ipnetwork::IpNetwork>> {
    let mut out = Vec::with_capacity(raw.len());
    for entry in raw {
        // Try CIDR first (foo/N); fall back to bare IP.
        let cidr = if entry.contains('/') {
            entry
                .parse::<ipnetwork::IpNetwork>()
                .with_context(|| format!("--allow-egress {entry:?}: not a valid CIDR"))?
        } else {
            let ip: std::net::IpAddr = entry.parse().with_context(|| {
                format!("--allow-egress {entry:?}: not an IP address or CIDR")
            })?;
            // /32 for v4, /128 for v6 — single-host rule.
            ipnetwork::IpNetwork::from(ip)
        };
        out.push(cidr);
    }
    Ok(out)
}

/// Egress policy for the requested overrides, or `None` when none were
/// requested — leaves the SDK default `NetworkPolicy::from_profiles([Public])`
/// untouched rather than installing an equivalent-but-distinct policy, so a
/// plain launch's egress behavior can never silently drift from the SDK
/// default as that default evolves.
///
/// `--allow-lan` adds `NetworkProfile::Private`, `--allow-host` adds
/// `NetworkProfile::Host`, and each `--allow-egress` CIDR becomes a
/// `Rule::allow_egress(Destination::Cidr(..))` prepended ahead of the
/// profile-derived rules. `Public` is always retained.
fn build_egress_policy(
    allow_lan: bool,
    allow_host: bool,
    allow_egress_cidrs: &[ipnetwork::IpNetwork],
) -> Option<microsandbox::NetworkPolicy> {
    if !allow_lan && !allow_host && allow_egress_cidrs.is_empty() {
        return None;
    }
    use microsandbox::NetworkProfile;
    use microsandbox_network::policy::{Destination, Rule};

    let mut profiles = vec![NetworkProfile::Public];
    if allow_lan {
        profiles.push(NetworkProfile::Private);
    }
    if allow_host {
        profiles.push(NetworkProfile::Host);
    }
    let mut policy = microsandbox::NetworkPolicy::from_profiles(profiles);

    // Prepend the explicit CIDR allows ahead of the profile-derived group
    // rules. NOTE: with every rule here an `allow` under the policy's
    // `default_egress == Deny`, allow-list ORDER is functionally inert today
    // (the first matching allow wins, and every candidate rule allows) — this
    // is kept only so a future `deny` rule inserted here would take
    // precedence over the group rules, not because correctness needs it now.
    let mut cidr_rules: Vec<Rule> = allow_egress_cidrs
        .iter()
        .map(|net| Rule::allow_egress(Destination::Cidr(*net)))
        .collect();
    cidr_rules.append(&mut policy.rules);
    policy.rules = cidr_rules;
    Some(policy)
}

/// The proxy env var the netstack will actually pick up, plus a
/// credential-free rendering of its value, or `None` if none is set.
///
/// Mirrors `HostHttpProxyConnector::from_env()`'s precedence exactly
/// (`vendor/microsandbox/crates/network/lib/host_proxy.rs`): the
/// curl/wget-convention **lowercase** spelling wins over the uppercase one
/// (`first_environment_value(lowercase, uppercase)`), values are trimmed,
/// and a whitespace-only value counts as unset. Purely for the launch-time
/// banner — the netstack does the real parsing and `NO_PROXY` handling.
fn active_guest_proxy_var() -> Option<(&'static str, String)> {
    active_guest_proxy_var_from(|var| std::env::var(var).ok())
}

/// Pure core of [`active_guest_proxy_var`], taking a lookup function instead
/// of reading the real process env so tests don't need unsafe
/// `std::env::set_var`/`remove_var` mutation under `cargo test`'s parallel
/// threads.
fn active_guest_proxy_var_from(
    lookup: impl Fn(&str) -> Option<String>,
) -> Option<(&'static str, String)> {
    for (upper, lower) in [
        ("HTTPS_PROXY", "https_proxy"),
        ("HTTP_PROXY", "http_proxy"),
        ("ALL_PROXY", "all_proxy"),
    ] {
        // Lowercase first, matching the netstack's own preference — the
        // banner must name the variable the netstack will actually use.
        for var in [lower, upper] {
            if let Some(value) = lookup(var) {
                let value = value.trim();
                if !value.is_empty() {
                    return Some((var, redact_proxy_userinfo(value)));
                }
            }
        }
    }
    None
}

/// `http://user:pass@proxy:3128/pac` -> `http://proxy:3128/pac`.
///
/// A proxy URL's userinfo is a live credential — the netstack turns it into
/// a Basic `Proxy-Authorization` header (`host_proxy.rs`'s
/// `basic_authorization`) — and the vendored netstack deliberately logs only
/// scheme+host+port for exactly that reason (`ProxyEndpoint::display`). A
/// launch banner must not be the thing that spills it into terminal
/// scrollback or a CI log.
fn redact_proxy_userinfo(raw: &str) -> String {
    let (scheme, rest) = match raw.split_once("://") {
        Some((scheme, rest)) => (Some(scheme), rest),
        None => (None, raw),
    };
    // Split the authority off first so an '@' inside a path/query can't be
    // mistaken for userinfo.
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    let authority = match authority.rsplit_once('@') {
        Some((_userinfo, host_port)) => host_port,
        None => authority,
    };
    match scheme {
        Some(scheme) => format!("{scheme}://{authority}{tail}"),
        None => format!("{authority}{tail}"),
    }
}

/// Build the GitHub repo allow-list by scanning `project_dir` and
/// each `extra_mount_dir` for:
///   * every `git remote -v` URL that points at github.com,
///   * every github.com URL listed in that dir's `.gitmodules`.
/// Matches main-branch claude-vm.sh:1463-1514 — without this,
/// `git push` from inside a submodule (or a mounted sibling repo)
/// would hit api.github.com anonymous and 401.
///
/// Failure modes (not a repo, no `.gitmodules`, non-github remote)
/// just contribute nothing — caller passes `--repo` to widen.
fn detect_github_repos<'a>(
    project_dir: &Path,
    extra_mount_dirs: impl IntoIterator<Item = &'a Path>,
) -> Vec<String> {
    let mut slugs: Vec<String> = Vec::new();
    scan_dir_for_github_slugs(project_dir, &mut slugs);

    // Dedup against the project dir so a mount that *is* the
    // project dir (or a symlink to it) doesn't re-run the same scan.
    let project_canon = project_dir.canonicalize().ok();
    for dir in extra_mount_dirs {
        if let (Some(pc), Ok(mc)) = (project_canon.as_ref(), dir.canonicalize()) {
            if &mc == pc {
                continue;
            }
        }
        scan_dir_for_github_slugs(dir, &mut slugs);
    }
    slugs
}

/// Scan one directory: top-level remotes + one level of submodule
/// URLs in `.gitmodules`. Submodule scanning is shallow (matches
/// claude-vm.sh; recursing into each submodule's `.gitmodules`
/// would balloon scope and add little value in practice).
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
        if let Some(slug) = parse_github_slug(url) {
            if !slugs.iter().any(|s| s.eq_ignore_ascii_case(&slug)) {
                slugs.push(slug);
            }
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
        "-c", "core.fsmonitor=",
        "-c", "core.fsmonitorHookVersion=",
        // Editor/pager fall back to cat — nothing we run here
        // needs them but a repo `core.pager = !bad-script` would
        // otherwise fire on output paging.
        "-c", "core.pager=cat",
        "-c", "core.editor=:",
        // Trust the dir even if owned by another UID (we only read).
        "-c", "safe.directory=*",
        // Don't fetch anything across this invocation.
        "-c", "protocol.allow=never",
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
    } else if let Some(r) = url.strip_prefix("ssh://git@github.com:") {
        // some hosts include a port-style colon; strip until next /
        r.split_once('/').map(|(_, p)| p)?
    } else {
        return None;
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

/// Seed the image's baked Claude LSP plugins into the persistent state dir on
/// first boot (PLAN.md D2). The image installs them at build time under
/// `/opt/agent/.claude` (shared, world-readable prefix — see the non-root
/// guest ADR), but the runtime persistence symlink — `~/.claude ->
/// /agent-vm-state/claude`, i.e. `/root/.claude` in `--root` mode or
/// `<state_dir>/home/.claude` in the non-root default — shadows that tree so
/// the booted guest's `claude plugin list` is empty. The image ships
/// `/opt/agent-vm/seed-claude-plugins.sh`, which copies the stash into
/// the state dir once. Guarded on the script's presence so older images (no
/// stash) are an inert no-op, and idempotent so it only does work on first boot.
const SEED_CLAUDE_PLUGINS: &str =
    "[ -x /opt/agent-vm/seed-claude-plugins.sh ] && /opt/agent-vm/seed-claude-plugins.sh || true";

/// Build the `bash -c` line that runs inside the guest: the prelude
/// (IPv6-nameserver strip, stdin redirect, optional chrome-CA install,
/// optional project runtime hook) followed by `exec`'ing the chosen
/// agent with its args. Pure and string-only so it can be unit-tested
/// without booting a sandbox — the launch path calls exactly this, so
/// the tested behavior and the live behavior cannot drift.
fn build_agent_shell_line(
    project_guest_path: &str,
    chrome_mcp_prelude: &str,
    inner_cmd: &str,
    inner_args: &[String],
) -> String {
    let path = shell_escape(project_guest_path);
    let prelude = format!(
        "{STRIP_IPV6_NAMESERVERS}\n\
         {SEED_CLAUDE_PLUGINS}\n\
         [ -t 0 ] || exec < /dev/null\n\
         {chrome_mcp_prelude}\
         _hook={path}/.agent-vm.runtime.sh\n\
         if [ -f \"$_hook\" ]; then\n\
         \techo \"==> sourcing $_hook\" >&2\n\
         \tcd {path} && . \"$_hook\" || {{ rc=$?; echo \"==> .agent-vm.runtime.sh failed (exit $rc)\" >&2; exit $rc; }}\n\
         fi",
    );
    let mut shell_line = prelude;
    shell_line.push_str("; exec ");
    shell_line.push_str(&shell_escape(inner_cmd));
    for a in inner_args {
        shell_line.push(' ');
        shell_line.push_str(&shell_escape(a));
    }
    shell_line
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_from_config_env_reads_the_path_entry() {
        let env = vec!["LANG=C.UTF-8".to_string(), "PATH=/opt/agent/.local/bin:/usr/bin".to_string(), "TZ=UTC".to_string()];
        assert_eq!(
            path_from_config_env(&env),
            Some("/opt/agent/.local/bin:/usr/bin".to_string())
        );
    }

    #[test]
    fn path_from_config_env_absent_is_none() {
        let env = vec!["LANG=C.UTF-8".to_string()];
        assert_eq!(path_from_config_env(&env), None);
    }

    #[test]
    fn path_from_config_env_empty_value_is_none() {
        let env = vec!["PATH=".to_string()];
        assert_eq!(path_from_config_env(&env), None);
    }

    #[test]
    fn path_from_config_env_last_entry_wins() {
        let env = vec!["PATH=/first".to_string(), "PATH=/second".to_string()];
        assert_eq!(path_from_config_env(&env), Some("/second".to_string()));
    }

    #[test]
    fn path_from_config_env_ignores_non_path_keys_containing_path_substring() {
        let env = vec!["XPATH=/should-not-match".to_string()];
        assert_eq!(path_from_config_env(&env), None);
    }

    #[test]
    fn normalize_layer_flag_treats_empty_as_unset() {
        assert_eq!(normalize_layer_flag(Some(PathBuf::from(""))), None);
        assert_eq!(
            normalize_layer_flag(Some(PathBuf::from("/a/b"))),
            Some(PathBuf::from("/a/b"))
        );
        assert_eq!(normalize_layer_flag(None), None);
    }

    #[test]
    fn should_auto_confirm_flag_or_env() {
        // Default: neither set → prompt.
        assert!(!should_auto_confirm(false, None));
        assert!(!should_auto_confirm(false, Some("")));
        assert!(!should_auto_confirm(false, Some("0")));
        // Flag opt-in.
        assert!(should_auto_confirm(true, None));
        // Env opt-in, same truthy set as should_check_update.
        assert!(should_auto_confirm(false, Some("1")));
        assert!(should_auto_confirm(false, Some("true")));
        assert!(should_auto_confirm(false, Some("yes")));
        assert!(should_auto_confirm(false, Some("on")));
        // Either input enables (flag OR env).
        assert!(should_auto_confirm(true, Some("0")));
    }

    #[test]
    fn yes_flag_parses_via_clap() {
        #[derive(clap::Parser)]
        struct TestCli {
            #[command(flatten)]
            args: Args,
        }
        use clap::Parser as _;

        let cli = TestCli::try_parse_from(["agent-vm"]).expect("parses with no flags");
        assert!(!cli.args.yes);

        let cli = TestCli::try_parse_from(["agent-vm", "--yes"]).expect("parses --yes");
        assert!(cli.args.yes);

        // Short form.
        let cli = TestCli::try_parse_from(["agent-vm", "-y"]).expect("parses -y");
        assert!(cli.args.yes);
    }

    // `resolve_boot_image_with_layer` is only exercised end-to-end by the
    // opt-in docker+registry e2e paths (see layer.rs's `#[ignore]`d
    // `e2e_*` tests and the manual verification recorded for issue #13),
    // but its "no layer declared" short circuit is pure and network-free:
    // `layer::resolve_layer_dir` returns `Ok(None)` on a missing
    // `.agent-vm/layer/` before this function's first `.await`, so this
    // is safe to pin as an ordinary fast unit test. It locks in the
    // guarantee that a non-layer project's boot path is byte-identical to
    // before this ticket: no base-digest read, no docker, no msb-cache
    // touch, `image` stays the base unchanged.
    #[tokio::test]
    async fn resolve_boot_image_with_layer_returns_none_for_a_project_with_no_layer() {
        let project = tempfile::tempdir().unwrap();
        let got = resolve_boot_image_with_layer(
            "ghcr.io/wirenboard/agent-vm-template:latest",
            None,
            project.path(),
            false,
        )
        .await
        .unwrap();
        assert_eq!(got, None);
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

    #[test]
    fn update_check_is_off_by_default_and_opt_in() {
        // Default: no flag, no env → no probe.
        assert!(!should_check_update(false, None));
        assert!(!should_check_update(false, Some("")));
        assert!(!should_check_update(false, Some("0")));
        assert!(!should_check_update(false, Some("false")));
        assert!(!should_check_update(false, Some("garbage")));
        // Flag opt-in.
        assert!(should_check_update(true, None));
        // Env opt-in (repo truthy set).
        assert!(should_check_update(false, Some("1")));
        assert!(should_check_update(false, Some("true")));
        assert!(should_check_update(false, Some("yes")));
        assert!(should_check_update(false, Some("on")));
        // Either input enables (flag OR env).
        assert!(should_check_update(true, Some("0")));
    }

    #[test]
    fn root_flag_parses_via_clap() {
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

    #[test]
    fn should_check_update_matches_repo_truthy_convention_exactly() {
        // Uppercase variants in the repo's allowlist (mirrors
        // pull::env_truthy) are truthy.
        assert!(should_check_update(false, Some("TRUE")));
        assert!(should_check_update(false, Some("YES")));
        assert!(should_check_update(false, Some("ON")));
        // The allowlist is NOT fully case-insensitive: mixed-case variants
        // outside the exact literal set are left off by design (consistent
        // with pull::env_truthy), so e.g. "True" does NOT enable the probe.
        assert!(!should_check_update(false, Some("True")));
        assert!(!should_check_update(false, Some("Yes")));
        assert!(!should_check_update(false, Some("On")));
        assert!(!should_check_update(false, Some("TrUe")));
    }

    #[test]
    fn update_check_flag_parses_via_clap() {
        // `Args` is normally flattened into a subcommand variant
        // (`main.rs`'s `Cmd::Shell(run::Args)` etc.); wrap it the same way
        // here so `--update-check` goes through real clap parsing rather
        // than calling `should_check_update` directly.
        #[derive(clap::Parser)]
        struct TestCli {
            #[command(flatten)]
            args: Args,
        }
        use clap::Parser as _;

        // No flag → off by default.
        let cli = TestCli::try_parse_from(["agent-vm"]).expect("parses with no flags");
        assert!(!cli.args.update_check);

        // `--update-check` parses and flips the field on.
        let cli = TestCli::try_parse_from(["agent-vm", "--update-check"])
            .expect("parses --update-check");
        assert!(cli.args.update_check);

        // The removed `--no-update-check` flag is no longer a recognized
        // option, but `agent_args` is a `trailing_var_arg` +
        // `allow_hyphen_values` catch-all, so clap does NOT hard-reject an
        // unknown `--xxx`: it silently absorbs it as a positional and
        // forwards it to the launched agent/shell command instead of
        // erroring. Lock in that (surprising but pre-existing, unrelated to
        // this change) behavior so it doesn't silently change later.
        let cli = TestCli::try_parse_from(["agent-vm", "--no-update-check"])
            .expect("old flag string still parses (absorbed into agent_args, not rejected)");
        assert!(!cli.args.update_check);
        assert_eq!(cli.args.agent_args, vec!["--no-update-check".to_string()]);
    }

    #[test]
    fn shell_escape_handles_simple_and_quoted() {
        assert_eq!(shell_escape("foo"), "'foo'");
        assert_eq!(shell_escape("--flag=value with spaces"), "'--flag=value with spaces'");
        assert_eq!(shell_escape("don't"), "'don'\\''t'");
        assert_eq!(shell_escape(""), "''");
    }

    // ── IPv6 resolv.conf strip (PLAN.md B3 / upstream issue #5) ───

    #[test]
    fn build_agent_shell_line_starts_with_v6_strip_and_execs() {
        let line = build_agent_shell_line("/work/proj", "", "claude", &[]);
        // The prelude opens with the IPv6-nameserver strip, sourced from
        // the single `STRIP_IPV6_NAMESERVERS` const so the live launch
        // path and this test can't drift.
        assert!(line.starts_with(STRIP_IPV6_NAMESERVERS), "got: {line}");
        assert!(line.starts_with("sed -i '/^nameserver .*:/d' /etc/resolv.conf"));
        assert!(line.contains("exec 'claude'"));
    }

    #[test]
    fn build_agent_shell_line_includes_chrome_prelude_and_args() {
        let line =
            build_agent_shell_line("/p", "CHROME_CA_STUFF\n", "codex", &["exec".into()]);
        assert!(line.contains("CHROME_CA_STUFF"));
        assert!(line.contains("exec 'codex' 'exec'"));
    }

    #[test]
    fn build_agent_shell_line_seeds_claude_plugins_before_exec() {
        // D2: the prelude seeds the baked LSP plugins into the persistent
        // state dir, and must do so before the agent execs.
        let line = build_agent_shell_line("/work/proj", "", "claude", &[]);
        let seed = line.find(SEED_CLAUDE_PLUGINS).expect("seed step present");
        let exec = line.find("exec 'claude'").expect("exec present");
        assert!(seed < exec, "seed must run before exec; got: {line}");
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
        assert_eq!(parse_github_slug("https://example.com/github.com/o/r"), None);
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
        let map: std::collections::HashMap<&str, &str> =
            GUEST_ALWAYS_ENV.iter().copied().collect();
        // Claude Code's root-guard bypass must stay set.
        assert_eq!(map.get("IS_SANDBOX"), Some(&"1"));
        // A UTF-8 locale must be pinned: without it the guest is C/POSIX,
        // which renders a Cyrillic cwd as `M-P…` escapes and makes the
        // agents' filesystem encoding ASCII (mishandling non-ASCII paths).
        // Removing or non-UTF-8-ing this regresses Cyrillic-path support.
        let lang = map.get("LANG").expect("guest LANG must be pinned to a UTF-8 locale");
        assert!(
            lang.to_ascii_lowercase().replace('-', "").contains("utf8"),
            "guest LANG must be a UTF-8 locale, got {lang:?}"
        );
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
        let (guest, reason) =
            resolve_project_guest_path(Path::new("/home/a\tb"), "/home/a\tb");
        assert_eq!(guest, "/workspace");
        assert!(reason.is_some_and(|r| r.contains("control characters")));
    }

    // ── parse_publish_args ───────────────────────────────────────

    #[test]
    fn parse_publish_args_two_part_defaults_to_loopback_tcp() {
        let p = parse_publish_args(&["8080:80".into()]).expect("ok");
        assert_eq!(p.len(), 1);
        assert_eq!(
            p[0].host_bind,
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        );
        assert_eq!(p[0].host_port, 8080);
        assert_eq!(p[0].guest_port, 80);
        assert_eq!(p[0].protocol, PublishProto::Tcp);
    }

    #[test]
    fn parse_publish_args_three_part_with_bind() {
        let p = parse_publish_args(&["0.0.0.0:5000:5000".into()]).expect("ok");
        assert_eq!(
            p[0].host_bind,
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        );
        assert_eq!(p[0].host_port, 5000);
        assert_eq!(p[0].guest_port, 5000);
    }

    #[test]
    fn parse_publish_args_explicit_tcp_suffix() {
        let p = parse_publish_args(&["8080:80/tcp".into()]).expect("ok");
        assert_eq!(p[0].protocol, PublishProto::Tcp);
    }

    /// UDP must be REJECTED with a clear error. Previously the parser
    /// accepted it, the stderr banner said "Publishing …/udp", and
    /// `PortPublisher::spawn_listener_one` silently dropped it — user
    /// got a "successful" publish that actually had no listener.
    #[test]
    fn parse_publish_args_rejects_udp() {
        let err = parse_publish_args(&["53:53/udp".into()])
            .expect_err("UDP must be rejected until upstream supports it")
            .to_string();
        assert!(
            err.contains("UDP is not yet supported"),
            "error should mention UDP unsupported, got: {err}"
        );
    }

    /// IPv6 host bind must work via the docker-style `[ADDR]:p:p`
    /// bracket form. Previously the parser split the whole body on
    /// `:` and IPv6 was unreachable.
    #[test]
    fn parse_publish_args_ipv6_bracket_bind() {
        let p = parse_publish_args(&["[::1]:8080:80".into()]).expect("ok");
        assert_eq!(p[0].host_bind, std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));
        assert_eq!(p[0].host_port, 8080);
        assert_eq!(p[0].guest_port, 80);
    }

    #[test]
    fn parse_publish_args_ipv6_bracket_wildcard() {
        let p = parse_publish_args(&["[::]:5000:5000".into()]).expect("ok");
        assert_eq!(
            p[0].host_bind,
            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        );
    }

    #[test]
    fn parse_publish_args_ipv6_bracket_missing_closer_is_rejected() {
        // `[::1` without `]:` should be a clear error, not a silent
        // misparse.
        assert!(parse_publish_args(&["[::1:8080:80".into()]).is_err());
    }

    // ── parse_allow_egress ───────────────────────────────────────

    #[test]
    fn parse_allow_egress_accepts_bare_ipv4() {
        let r = parse_allow_egress(&["10.100.1.75".into()]).expect("ok");
        assert_eq!(r.len(), 1);
        // Bare IPv4 → /32 single-host CIDR.
        assert_eq!(r[0].prefix(), 32);
        assert_eq!(r[0].network().to_string(), "10.100.1.75");
    }

    #[test]
    fn parse_allow_egress_accepts_ipv4_cidr() {
        let r = parse_allow_egress(&["10.100.1.0/24".into()]).expect("ok");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].prefix(), 24);
    }

    #[test]
    fn parse_allow_egress_accepts_ipv6_cidr() {
        let r = parse_allow_egress(&["fd00::/64".into()]).expect("ok");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].prefix(), 64);
    }

    #[test]
    fn parse_allow_egress_accepts_bare_ipv6() {
        let r = parse_allow_egress(&["fd00::1".into()]).expect("ok");
        assert_eq!(r[0].prefix(), 128);
    }

    #[test]
    fn parse_allow_egress_rejects_garbage() {
        assert!(parse_allow_egress(&["not-an-ip".into()]).is_err());
        assert!(parse_allow_egress(&["10.0.0.1/99".into()]).is_err());
        assert!(parse_allow_egress(&["".into()]).is_err());
    }

    // ── build_egress_policy ──────────────────────────────────────

    use microsandbox_network::policy::{Action, Destination, DestinationGroup};

    /// The `DestinationGroup`s a profile actually opened for egress —
    /// i.e. the unrestricted `Rule::allow_egress(Destination::Group(..))`
    /// rules `from_profiles` emits per requested profile. Excludes the
    /// single narrow `Rule::allow_dns()` rule every non-empty profile set
    /// also gets (port 53 only, destination `Group(Host)` regardless of
    /// whether the `Host` *profile* was requested) — that rule alone must
    /// never be mistaken for `--allow-host` having opened the Host group.
    fn group_rule_destinations(policy: &microsandbox::NetworkPolicy) -> Vec<DestinationGroup> {
        policy
            .rules
            .iter()
            .filter(|r| r.ports.is_empty())
            .filter_map(|r| match r.destination {
                Destination::Group(g) => Some(g),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn no_flags_returns_none() {
        assert!(build_egress_policy(false, false, &[]).is_none());
    }

    #[test]
    fn allow_lan_adds_private_group() {
        let policy = build_egress_policy(true, false, &[]).expect("Some");
        assert_eq!(policy.default_egress, Action::Deny);
        // Installing a policy must not disturb ingress — `--publish`'s
        // port_bind depends on `default_ingress == Allow`.
        assert_eq!(policy.default_ingress, Action::Allow);
        let groups = group_rule_destinations(&policy);
        assert!(groups.contains(&DestinationGroup::Public));
        assert!(groups.contains(&DestinationGroup::Private));
        assert!(!groups.contains(&DestinationGroup::Host));
    }

    #[test]
    fn allow_host_adds_host_group() {
        let policy = build_egress_policy(false, true, &[]).expect("Some");
        let groups = group_rule_destinations(&policy);
        assert!(groups.contains(&DestinationGroup::Public));
        assert!(groups.contains(&DestinationGroup::Host));
        assert!(!groups.contains(&DestinationGroup::Private));
    }

    #[test]
    fn allow_lan_and_host_add_both_groups() {
        let policy = build_egress_policy(true, true, &[]).expect("Some");
        let groups = group_rule_destinations(&policy);
        assert!(groups.contains(&DestinationGroup::Public));
        assert!(groups.contains(&DestinationGroup::Private));
        assert!(groups.contains(&DestinationGroup::Host));
    }

    #[test]
    fn allow_egress_cidr_prepends_rule() {
        let cidrs = parse_allow_egress(&["10.0.0.5".into()]).expect("ok");
        let policy = build_egress_policy(false, false, &cidrs).expect("Some");
        // The prepended CIDR rule comes before the DNS + group rules
        // `from_profiles` emits.
        match &policy.rules[0].destination {
            Destination::Cidr(net) => assert_eq!(net.prefix(), 32),
            other => panic!("expected Cidr rule first, got {other:?}"),
        }
        // Public + DNS are still present further down the rule list.
        assert!(group_rule_destinations(&policy).contains(&DestinationGroup::Public));
        // Exactly one ports-bearing rule survives: `Rule::allow_dns()`
        // (UDP/TCP 53). This also pins `group_rule_destinations`'s filter.
        assert_eq!(
            policy.rules.iter().filter(|r| !r.ports.is_empty()).count(),
            1
        );
    }

    #[test]
    fn allow_egress_ipv6_cidr() {
        let cidrs = parse_allow_egress(&["fd00::1/128".into()]).expect("ok");
        let policy = build_egress_policy(false, false, &cidrs).expect("Some");
        match &policy.rules[0].destination {
            Destination::Cidr(net) => assert!(net.is_ipv6()),
            other => panic!("expected Cidr rule first, got {other:?}"),
        }
    }

    #[test]
    fn allow_egress_preserves_cli_order() {
        let cidrs = parse_allow_egress(&["10.0.0.1".into(), "10.0.0.2".into()]).expect("ok");
        let policy = build_egress_policy(false, false, &cidrs).expect("Some");
        let cidr_dests: Vec<_> = policy.rules[..2]
            .iter()
            .map(|r| match &r.destination {
                Destination::Cidr(net) => net.ip().to_string(),
                other => panic!("expected Cidr rule, got {other:?}"),
            })
            .collect();
        assert_eq!(cidr_dests, vec!["10.0.0.1", "10.0.0.2"]);
    }

    #[test]
    fn combined_cidr_and_lan() {
        let cidrs = parse_allow_egress(&["10.0.0.5".into()]).expect("ok");
        let policy = build_egress_policy(true, false, &cidrs).expect("Some");
        match &policy.rules[0].destination {
            Destination::Cidr(_) => {}
            other => panic!("expected Cidr rule first, got {other:?}"),
        }
        let groups = group_rule_destinations(&policy);
        assert!(groups.contains(&DestinationGroup::Public));
        assert!(groups.contains(&DestinationGroup::Private));
    }

    // ── active_guest_proxy_var ───────────────────────────────────

    #[test]
    fn active_guest_proxy_var_absent_is_none() {
        assert!(active_guest_proxy_var_from(|_| None).is_none());
    }

    #[test]
    fn active_guest_proxy_var_ignores_empty_values() {
        assert!(active_guest_proxy_var_from(|_| Some("   ".to_string())).is_none());
    }

    #[test]
    fn active_guest_proxy_var_detects_uppercase() {
        let (var, value) = active_guest_proxy_var_from(|v| {
            (v == "HTTPS_PROXY").then(|| "http://proxy.example:3128".to_string())
        })
        .expect("Some");
        assert_eq!(var, "HTTPS_PROXY");
        assert_eq!(value, "http://proxy.example:3128");
    }

    #[test]
    fn active_guest_proxy_var_detects_lowercase() {
        let (var, _) = active_guest_proxy_var_from(|v| {
            (v == "https_proxy").then(|| "http://proxy.example:3128".to_string())
        })
        .expect("Some");
        assert_eq!(var, "https_proxy");
    }

    #[test]
    fn active_guest_proxy_var_detects_all_proxy() {
        let (var, _) =
            active_guest_proxy_var_from(|v| (v == "ALL_PROXY").then(|| "socks5://x".to_string()))
                .expect("Some");
        assert_eq!(var, "ALL_PROXY");
    }

    #[test]
    fn active_guest_proxy_var_prefers_lowercase_spelling() {
        // Matches the netstack's `first_environment_value(lowercase, uppercase)`.
        let (var, value) = active_guest_proxy_var_from(|v| match v {
            "https_proxy" => Some("http://lower.example:3128".to_string()),
            "HTTPS_PROXY" => Some("http://upper.example:3128".to_string()),
            _ => None,
        })
        .expect("Some");
        assert_eq!(var, "https_proxy");
        assert_eq!(value, "http://lower.example:3128");
    }

    #[test]
    fn active_guest_proxy_var_redacts_embedded_credentials() {
        let (_, value) = active_guest_proxy_var_from(|v| {
            (v == "https_proxy").then(|| "http://alice:hunter2@proxy.example:3128".to_string())
        })
        .expect("Some");
        assert_eq!(value, "http://proxy.example:3128");
        assert!(
            !value.contains("hunter2"),
            "credential leaked into banner: {value}"
        );
    }

    #[test]
    fn redact_proxy_userinfo_leaves_credential_free_values_intact() {
        assert_eq!(
            redact_proxy_userinfo("http://proxy.example:3128"),
            "http://proxy.example:3128"
        );
        assert_eq!(
            redact_proxy_userinfo("proxy.example:3128"),
            "proxy.example:3128"
        );
        assert_eq!(
            redact_proxy_userinfo("http://[::1]:3128"),
            "http://[::1]:3128"
        );
        // An '@' after the authority is path, not userinfo.
        assert_eq!(
            redact_proxy_userinfo("http://proxy:3128/a@b"),
            "http://proxy:3128/a@b"
        );
    }

    #[test]
    fn redact_proxy_userinfo_strips_userinfo_before_ipv6_authority() {
        assert_eq!(
            redact_proxy_userinfo("http://u:p@[::1]:3128"),
            "http://[::1]:3128"
        );
    }

    #[test]
    fn parse_publish_args_rejects_bad_input() {
        assert!(parse_publish_args(&["80".into()]).is_err());
        assert!(parse_publish_args(&["a:b".into()]).is_err());
        assert!(parse_publish_args(&["0:80".into()]).is_err());
        assert!(parse_publish_args(&["80:0".into()]).is_err());
        assert!(parse_publish_args(&["999999:80".into()]).is_err());
        assert!(parse_publish_args(&["1:2:3:4".into()]).is_err());
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
            slugs.iter().any(|s| s.eq_ignore_ascii_case("gregwebs/microsandbox")),
            "expected gregwebs/microsandbox in scope, got {slugs:?}"
        );
    }

    #[test]
    fn parse_gitmodules_returns_empty_when_file_missing() {
        let tmp = std::env::temp_dir().join(format!(
            "agent-vm-gitmodules-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        let slugs = parse_gitmodules_github_slugs(&tmp);
        std::fs::remove_dir_all(&tmp).ok();
        assert!(slugs.is_empty(), "no .gitmodules → no slugs, got {slugs:?}");
    }
}

/// Seed the pulled-digest marker from microsandbox's cache when we have
/// no record yet, so the update banner has a baseline to diff against on
/// this very launch.
///
/// The marker (what the banner compares to the registry) was historically
/// written *only* by `agent-vm pull`. A user who acquired the image via a
/// launch's `IfMissing` auto-pull — or via an older agent-vm that never
/// wrote it — had no baseline, so the banner could never fire. Here, if
/// the image is already cached and unmarked, we record its per-platform
/// manifest digest. Then a stale cache trips the banner on the next probe
/// (i.e. immediately, since the call below seeds before we probe).
///
/// Safe on the launch path: `IfMissing` never re-pulls, so `Image::get`'s
/// digest is accurate (the re-pull staleness that makes pull.rs avoid
/// `Image::get` — see pulled_marker.rs — can't apply here). Verified
/// empirically that `Image::get(...).manifest_digest()` is the same
/// per-platform digest `image_check::fetch_remote_digest` returns, so the
/// comparison is apples-to-apples. Only ever *seed* — never overwrite an
/// existing marker, which is the authoritative record of our last pull.
async fn seed_pulled_marker_if_absent(image: &str) {
    if crate::pulled_marker::read(image).is_some() {
        return;
    }
    // Not cached yet (genuine first run) → Image::get errors → nothing to
    // seed, and there's correctly nothing newer to flag: the imminent
    // IfMissing pull lands the current image.
    //
    // Baseline v0.6.15's Image::get resolves the active local backend
    // internally (crate::backend::default_backend()), so no separate
    // LocalBackend handle is needed here any more.
    if let Ok(handle) = microsandbox::Image::get(image).await
        && let Some(digest) = handle.manifest_digest()
    {
        match crate::pulled_marker::write(image, digest) {
            Ok(()) => tracing::debug!(image, digest, "seeded pulled-digest baseline from cache"),
            Err(e) => tracing::warn!(error = %e, "failed to seed pulled-digest marker"),
        }
    }
}

async fn notify_if_update_available(image: &str) {
    use crate::image_check::{UpdateState, check_for_update};
    // The probe does up to three sequential registry round-trips for a
    // token-auth registry (manifest GET → 401 → token → authed GET),
    // each carrying its own 5s per-request timeout. This runs inline on
    // the launch hot path before boot, so cap the whole thing: a slow or
    // flaky registry must never delay launch by more than a single
    // request's worth of wait. The banner is best-effort — on timeout we
    // simply stay quiet and continue with the cached image.
    let probe = tokio::time::timeout(UPDATE_PROBE_BUDGET, check_for_update(image));
    match probe.await {
        Ok(Ok(Some(UpdateState::UpdateAvailable { cached, remote }))) => {
            eprintln!(
                "==> A newer image is available in the registry (cached {cached}, registry {remote})"
            );
            eprintln!(
                "==> Run `agent-vm pull` to fetch it. Continuing with the cached image."
            );
        }
        // UpToDate / NotCached: nothing to say.
        // Ok(Err)/None: registry unreachable etc. — stay quiet.
        // Err(Elapsed): probe exceeded the budget — stay quiet.
        _ => {}
    }
}

/// Whether to run the launch-time registry update probe.
///
/// Off by default. Enabled by the `--update-check` flag OR a truthy
/// `AGENT_VM_UPDATE_CHECK` env var. `env_val` is the raw value of that
/// variable (`None` when unset), so this stays pure and unit-testable.
/// Truthy values match the repo convention (`1|true|yes|on`,
/// see `pull::env_truthy`).
fn should_check_update(flag: bool, env_val: Option<&str>) -> bool {
    flag || matches!(env_val, Some("1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON"))
}

/// Wall-clock budget for the launch-path update probe. Bounds the worst
/// case across all of the probe's registry round-trips so a slow or
/// unreachable registry can't stall boot; matches a single request's
/// per-request timeout in `image_check`.
const UPDATE_PROBE_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

