# ADR-0021: Project-scoped Pi home and the wrapper's parity policy

## Status

Accepted. Implementation decision for [agent-vm #96](https://github.com/gregwebs/agent-vm/issues/96). It extends [ADR-0012](0012-stable-pi-image-customization-seam.md) (the `pi` wrapper gains a second decision and records what it deliberately does not do) and [ADR-0002](0002-mirror-host-home-and-username.md) (the one shared guest-HOME link table). It complements [ADR-0020](0020-protect-host-pi-credential-files.md), which keeps host Pi credential **files** out of the guest; the guest-managed credential this ADR persists, the every-launch warning about it, and the mixed ownership behind it, are [#93](https://github.com/gregwebs/agent-vm/issues/93)/[#91](https://github.com/gregwebs/agent-vm/issues/91)/[#94](https://github.com/gregwebs/agent-vm/issues/94).

## Context

Pi reads **project** resources from `<cwd>/.pi/{extensions,skills,prompts,npm,git}` (plus `<cwd>/.agents/skills`) and **user** state from `<agentDir> = ~/.pi/agent` — `auth.json`, `models.json`, `settings.json`, `trust.json`, `themes/`, `prompts/`, `bin/`, `sessions/`, and the global package tree (`npm/`, `git/`). Two different paths, resolved by two different functions, so the checkout's `.pi/` and the user's `~/.pi` cannot alias.

Agent-vm gives every project a persistent host state dir, bind-mounted at `/agent-vm-state`, and maps per-tool state as a **symlink from the guest `$HOME` into that mount** (`credential_provider::guest_home_links()`). Before #96 the `pi` tool declared no such link, so:

- **Root mode** (`HOME=/root`, rebaked per boot) lost `~/.pi` on every relaunch: a `/login` was gone the next time the guest started.
- **Non-root mode** wrote a **real** `~/.pi` directory into the persistent `<state>/home`, where it was invisible to root mode and outside the per-tool state layout.

Those two defects also cost the user Pi's own project-trust answer: Pi's trust store lives at `<agentDir>/trust.json`, i.e. `~/.pi/agent/trust.json`, so losing `~/.pi` lost a one-time "Trust" decision too.

Agent-vm's guiding principle is that it **intervenes in Pi's behaviour only where agent-vm introduced the condition**, and otherwise forwards Pi's own behaviour and flags. Agent-vm introduces two conditions here: it persists guest credentials in project-scoped state readable by any guest process (so it must warn), and it owns the Pi binary as a root-owned image layer (so Pi's update check is unactionable). It introduces no project-trust condition and no telemetry condition — so it defaults neither, and Pi's own trust prompt and telemetry policy apply unchanged.

## Decision

### 1. `~/.pi` is a compiled, unconditional `GENERIC_HOME_LINKS` entry

`HomeLink { home_relative: ".pi", state_relative: "pi" }` is appended to `GENERIC_HOME_LINKS`, and `pi` is a generic **eager state dir** (`GENERIC_EAGER_STATE_DIRS`, folded into `eager_state_dirs()`). It is not a `provider`: the `pi` tool declares no `credentials` (Pi enrols providers in-session), so there is no `ProviderSpec` to hang it off. It is not a `persist` entry, for four reasons:

1. `persist` would land at `/agent-vm-state/persist/.pi`, not `/agent-vm-state/pi` as the ticket specifies, and would not match the `claude`/`codex`/`opencode` shape.
2. `persist` targets are deliberately **not** pre-created, so a directory-valued entry needs a manual `mkdir -p` once per project. `~/.pi` is a directory; that papercut is unacceptable for a shipped tool.
3. `persist` is **closure-scoped**: a tool whose `tools` closure does not reach `pi` would get no `~/.pi` at all. The compiled table is unconditional, which is what "root and non-root mappings resolve `~/.pi` to project state" needs.
4. A bare `pi` typed into `agent-vm shell` is a first-class path in ADR-0012.

The eager dir matters: Pi does `mkdir -p ~/.pi/agent` on startup, and `mkdir` through a **dangling** symlink fails with `EEXIST` rather than creating the target. `ensure_dirs` otherwise creates only a link target's *parent*.

**Consequence of the same table:** `config::validate_persist` iterates `guest_home_links()`, so a user `persist = [".pi"]` or `".pi/agent"` is now a **hard error** naming the reserved path. That is deliberate — those paths are reserved by the compiled mapping, exactly as `.claude` and `.config/gh` already are.

### 1b. A one-shot upgrade move for the pre-#96 directory

The non-root guest HOME (`<state>/home`) is persistent and **predates** a tool that creates `~/.pi`, so every project where Pi has ever run non-root already holds a real `<state>/home/.pi` directory. Compiled links are provisioned with `force_symlink`, which refuses a real directory, so naively adding the link would make **every** launch verb (including the `shell` a user would reach for to repair it) fail on those projects.

`ProjectSession::migrate_legacy_pi_home` therefore runs on the launch path, before `ensure_dirs`, in **both** guest modes. It `rename`s a real `<state>/home/.pi` to `<state>/pi` — same filesystem, so atomic and never destructive. It treats an **empty** `<state>/pi` as absent (the placeholder `ensure_dirs` and `agent-vm clipboard` create) and **refuses to merge two populated homes**, naming both paths and the host-side `mv` remedy. Running it in both modes means a user who upgrades and launches with `--root` first still gets their old non-root state moved, rather than silently seeing an empty one.

**The security boundary it actually enforces.** `<state>/home` is guest-writable (the non-root guest HOME is bind-mounted from it), so a previous guest can leave it as a symlink to the host `$HOME`. A pathname-based `symlink_metadata` on the final `.pi` component would then `lstat` the host's real `~/.pi` through the symlinked ancestor and rename it into guest-visible state, including `agent/auth.json` and `models.json`. The migration therefore does not resolve a joined pathname: it opens the state root once and performs every check and the rename relative to that descriptor through the `host_paths::GuestStateDir` primitives, opening each ancestor `O_NOFOLLOW` (`entry_type` `lstat`s the final component; `dir_is_empty`, `remove_empty_dir`, and `rename_entry` resolve their parents no-follow and `renameat` against the pinned descriptors). A symlinked ancestor is a hard error — the launch fails closed rather than following it — and a one-time `is_symlink` preflight is deliberately not used, because it would leave a swap window. Two concurrent launchers are serialized by a host-only `flock` in the sibling `<hash>.secrets/` directory (never bind-mounted), and both source and target are re-read under it, so a peer's completed migration is recognized as a no-op instead of failing with ENOENT or a false "two populated homes".

`force_symlink`'s contract is unchanged for every other compiled link; this is one named, deletable method rather than a general "compiled links may migrate" mechanism. Delete it once no supported state dir can predate #96.

### 2. The wrapper injects no project-trust default and no telemetry default

Writing `args = ["--approve"]` on the `pi` tool is **wrong** on mechanics alone: Pi dispatches a subcommand only when it is the *first* argument, and `run::inner_argv` prepends the tool's default argv, so `agent-vm pi list` would become `pi --approve list` — `list` would become a prompt and run an agent turn. ADR-0012's Decision names this exact failure for `--extension`; it applies identically to any prepended flag. But the deciding reason is the **parity principle**: agent-vm introduces no project-trust condition, so it forces no trust decision. `images/tools/pi/pi.sh` forwards `--approve`/`--no-approve`/`-a`/`-na` and `PI_TELEMETRY` untouched and injects neither.

- **No `--approve` default.** Pi derives whether it can prompt from **its own** mode, not from agent-vm: `hasUI: isInitialRuntime && trustPromptMode === "interactive"` (`dist/main.js`) and `hasUI: appMode === "interactive"` (`dist/package-manager-cli.js`). So the non-interactive cases that a `--approve` default would have been compensating for — `-p`/print, a pipe, CI, or a bare `pi` inside `agent-vm shell -- bash -c` — behave identically under vanilla Pi. `resolveProjectTrusted` (`dist/core/project-trust.js`) checks `trustOverride`, then `hasTrustRequiringProjectResources`, then `trust.json`, then `defaultProjectTrust` (`always`/`never`/`ask`), and on `ask` with no UI returns `false` silently — dropping the checkout's `.pi/` resources exactly as vanilla Pi does.
- **The one agent-vm-specific reason to force trust is gone.** The reason a user's answer did not stick was agent-vm's own state loss: root mode rebaked `~/.pi` every boot, so `~/.pi/agent/trust.json` (`dist/core/trust-manager.js`) was lost too. Decision 1 makes the trust store persistent, so a one-time interactive "Trust" answer is remembered and Pi never has to ask again.
- **No `PI_TELEMETRY` default.** Pi's telemetry policy is Pi's own; agent-vm introduces no telemetry condition. `PI_TELEMETRY` is left exactly as the environment sets it — unset stays unset, an explicit value passes through.

The wrapper does not scan argv: there is no injected flag pair to keep off the
guest command line. `pi <subcommand>` is still forwarded verbatim (ADR-0012),
so a subcommand gets neither the `--extension` nor any flag.

### 3. `PI_SKIP_VERSION_CHECK` and the mandatory extension are the only interventions

The wrapper makes two decisions and then execs — the `PI_SKIP_VERSION_CHECK` enforcement and subcommand dispatch — plus the mandatory extension:

- `export PI_SKIP_VERSION_CHECK=1`. Pi's `dist/utils/version-check.js` skips the startup fetch for **any** non-empty value. agent-vm owns the Pi binary (a root-owned image layer; the pin lives in `images/tools/pi/package.json`), so the fetch is noise and an unrequested network call. Enforced, not defaulted — the issue's word.
- subcommand dispatch, forwarded verbatim, its allowlist pinned against the real `pi --help` at build time (ADR-0012).
- `--extension /opt/agent-vm/pi-extensions/guest-credential-warning.js` on the non-subcommand path. agent-vm introduced the credential-persistence condition, so agent-vm is the one that warns.

`verify-pi.sh` checks the version pin, the subcommand allowlist, and that the extension loads.

## Consequences

- **Root and non-root both persist `~/.pi`** at `/agent-vm-state/pi`. A guest-created Pi credential survives a relaunch; the credential warning's persistence clause matches this (`images/tools/pi/extensions/guest-credential-warning.js` and `script/test/pi-layer-runtime.sh` change together).
- **A project the user has not trusted loads nothing from the checkout's `.pi/`.** That is Pi's own default in every non-interactive mode, and the microVM is still the boundary. A user who wants the project's extensions either answers Pi's interactive trust prompt once — remembered in the now-persistent `~/.pi/agent/trust.json` — or passes Pi's own `--approve`.
- **The wrapper forces neither trust nor telemetry, matching Pi's own behaviour in every mode.** It injects only `--extension`; an explicit approve flag is forwarded exactly once, verbatim. The mandatory warning is unchanged.
- **The upgrade path is non-destructive and can halt.** A pre-#96 real `<state>/home/.pi` is moved automatically; if `<state>/pi` already holds Pi state the launch stops and names both paths, and the fix is a host-side `mv` of one of them. Documented in `USAGE.md`.
- **`pi update self` still fails** on the root-owned `/opt/agent-vm/pi` prefix (ADR-0012, unchanged).
- **The launch goldens include one `.pi` row** (`link:.pi /agent-vm-state/pi`).
- **A project that *is* (or is inside) `$HOME`** could alias the checkout's `.pi/` with the state `.pi`. This is pre-existing for `.claude`/`.gitconfig`, and `guest_home::mount_conflicts` only inspects `Declared` links; widening it is out of scope here.

## Alternatives

- **`persist = [".pi"]`.** Rejected — Decision 1's four reasons.
- **A `CredentialProvider::Pi`.** Rejected: it drags in a `doctor` row, a proxy placeholder, and capture machinery for a tool that declares no credentials.
- **Injecting `--approve` by default (in the wrapper, or `args = ["--approve"]` in `default-tools.toml`).** Rejected: pure divergence from Pi, and the condition it compensated for — a non-interactive guest that could not answer the trust prompt — was agent-vm's own state loss (root mode rebaked `~/.pi`, so a one-time answer never stuck). Decision 1 fixes that. The `default-tools.toml` spelling has an additional, independent defect (a prepended flag displaces argv[1] and turns `pi list` into a prompt, ADR-0012), but the parity principle is the deciding reason.
- **An extension answering Pi's `project_trust` event with `trusted: "yes"`.** Rejected for the same principle: it is still forcing a trust decision the user did not ask for, just through a different mechanism. It would also have side-stepped the argv scan — such an extension runs inside Pi's own trust resolution rather than ahead of the parser — but that mechanical advantage is not a reason to keep the intervention. The rejection rests on the principle, not on the mechanics.
- **Defaulting `PI_TELEMETRY=0`.** Rejected: Pi's telemetry default is Pi's own policy, not an agent-vm-introduced condition. agent-vm leaves the variable alone.
- **`PI_CODING_AGENT_DIR` as a `CODEX_HOME`-style env pointer.** Rejected, and the reasoning matters: the variable **does** relocate sessions, global packages and auth, because they all live under `getAgentDir()`. The real reasons are (a) the ticket specifies the whole `~/.pi` at `/agent-vm-state/pi`, while the variable maps only the `agent/` subdirectory; (b) a config `env` pair reaches only the tools that declare it, so a bare `pi` inside `agent-vm shell` (and any tool added later) would silently lose the mapping, whereas the compiled link is unconditional; (c) `CODEX_HOME` exists only because a `~/.codex` symlink would shadow codex's own install prefix — Pi installs under `/opt/agent-vm/pi`, so it has no such conflict and the default symlink shape applies with no second mechanism.
