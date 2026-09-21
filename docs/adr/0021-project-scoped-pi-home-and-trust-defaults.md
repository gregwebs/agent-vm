# ADR-0021: Project-scoped Pi home and trust defaults

## Status

Accepted. Implementation decision for [agent-vm #96](https://github.com/gregwebs/agent-vm/issues/96). It extends [ADR-0012](0012-stable-pi-image-customization-seam.md) (the `pi` wrapper gains two more decisions) and [ADR-0002](0002-mirror-host-home-and-username.md) (the one shared guest-HOME link table). It complements [ADR-0020](0020-protect-host-pi-credential-files.md), which keeps host Pi credential **files** out of the guest; the guest-managed credential this ADR persists, the every-launch warning about it, and the mixed ownership behind it, are [#93](https://github.com/gregwebs/agent-vm/issues/93)/[#91](https://github.com/gregwebs/agent-vm/issues/91)/[#94](https://github.com/gregwebs/agent-vm/issues/94).

## Context

Pi reads **project** resources from `<cwd>/.pi/{extensions,skills,prompts,npm,git}` (plus `<cwd>/.agents/skills`) and **user** state from `<agentDir> = ~/.pi/agent` — `auth.json`, `models.json`, `settings.json`, `trust.json`, `themes/`, `prompts/`, `bin/`, `sessions/`, and the global package tree (`npm/`, `git/`). Two different paths, resolved by two different functions, so the checkout's `.pi/` and the user's `~/.pi` cannot alias.

Agent-vm gives every project a persistent host state dir, bind-mounted at `/agent-vm-state`, and maps per-tool state as a **symlink from the guest `$HOME` into that mount** (`credential_provider::guest_home_links()`). Before #96 the `pi` tool declared no such link, so:

- **Root mode** (`HOME=/root`, rebaked per boot) lost `~/.pi` on every relaunch: a `/login` was gone the next time the guest started.
- **Non-root mode** wrote a **real** `~/.pi` directory into the persistent `<state>/home`, where it was invisible to root mode and outside the per-tool state layout.

Separately, Pi's project-trust prompt has no good answer inside the microVM: a non-interactive guest cannot answer it, and Pi then returns "not trusted" and silently drops the checkout's own `.pi/` extensions and skills. And Pi's startup behaviour includes a "newer pi available" fetch (pure noise — agent-vm owns the binary) and install telemetry that must default off.

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

### 2. The trust default, the version-check enforcement and the telemetry default live in the wrapper, not in `default-tools.toml`

Writing `args = ["--approve"]` on the `pi` tool is **wrong**: Pi dispatches a subcommand only when it is the *first* argument, and `run::inner_argv` prepends the tool's default argv, so `agent-vm pi list` would become `pi --approve list` — `list` would become a prompt and run an agent turn. ADR-0012's Decision names this exact failure for `--extension`; it applies identically to any prepended flag.

`images/tools/pi/pi.sh` is the one place that knows the subcommand set **and** has a build-time gate (`verify-pi.sh`) keeping that knowledge honest against the pin. So the wrapper:

- injects `--approve` on the non-subcommand path, suppressed by any approve-family token (`--approve`, `-a`, `--no-approve`, `-na`) seen before `--`. Pi's own parse is last-wins, so an explicit user flag beats the default regardless of the scan; the scan exists only so the guest command line does not carry a contradictory pair. This reaches a bare `pi` from `agent-vm shell` and Pi invoked by a script inside the guest, which config `args` cannot reach.
- therefore also amends ADR-0012's "exactly one decision" framing: the wrapper now makes three decisions (env defaults, subcommand dispatch, extension + trust default).

`verify-pi.sh` greps `pi --help` for `--approve` and `--no-approve` at build time, so a pin bump that renames or drops them fails the build rather than breaking every launch at runtime.

### 3. `PI_SKIP_VERSION_CHECK` is enforced; `PI_TELEMETRY` is a default

- `export PI_SKIP_VERSION_CHECK=1`. Pi's `dist/utils/version-check.js` skips the startup fetch for **any** non-empty value. agent-vm owns the Pi binary (a root-owned image layer; the pin lives in `images/tools/pi/package.json`), so the fetch is noise and an unrequested network call. Enforced, not defaulted — the issue's word.
- `: "${PI_TELEMETRY:=0}"; export PI_TELEMETRY`. Pi's `dist/core/telemetry.js` enables on `1`/`true`/`yes` and treats anything else as disabled, and consults the settings file only when the variable is **absent**. `:=` assigns only when unset or empty, so a non-empty value already in the guest environment wins. This is a **default**, and the supported override is a **guest-side** value: a tool's config `env = { PI_TELEMETRY = "1" }`, or `export PI_TELEMETRY=1` inside `agent-vm shell`. agent-vm forwards no host `PI_TELEMETRY` into the guest (it forwards only `ANTHROPIC_API_KEY`/`OPENAI_API_KEY`), and this ADR deliberately does not add a third name.

## Consequences

- **Root and non-root both persist `~/.pi`** at `/agent-vm-state/pi`. A guest-created Pi credential now genuinely survives a relaunch — which is why the credential warning's persistence clause is restored in the same change (`images/tools/pi/extensions/guest-credential-warning.js` and `script/test/pi-layer-runtime.sh` change together).
- **The upgrade path is non-destructive and can halt.** A pre-#96 real `<state>/home/.pi` is moved automatically; if `<state>/pi` already holds Pi state the launch stops and names both paths, and the fix is a host-side `mv` of one of them. Documented in `USAGE.md`.
- **`pi update self` still fails** on the root-owned `/opt/agent-vm/pi` prefix (ADR-0012, unchanged).
- **The six launch goldens gained one row** (`link:.pi /agent-vm-state/pi`).
- **Two argv-scan imprecisions are accepted and pinned** by `script/test/pi-wrapper.sh` (W14/W15). The scan does not model option *values*, because Pi has ~20 value-taking options and nothing in the wrapper could keep a copy of that list honest against the pin: `pi --name -a` drops the default without setting an override (fails toward **less** trust — safe direction), and `pi --name -- --no-approve` still emits the pair (Pi's last-wins then resolves it in the user's favour — correct outcome, untidy command line).
- **A project that *is* (or is inside) `$HOME`** could alias the checkout's `.pi/` with the state `.pi`. This is pre-existing for `.claude`/`.gitconfig`, and `guest_home::mount_conflicts` only inspects `Declared` links; widening it is out of scope here.

## Alternatives

- **`persist = [".pi"]`.** Rejected — Decision 1's four reasons.
- **A `CredentialProvider::Pi`.** Rejected: it drags in a `doctor` row, a proxy placeholder, and capture machinery for a tool that declares no credentials.
- **`args = ["--approve"]` (and an `env` pair) in `default-tools.toml`.** Rejected — Decision 2's subcommand regression, plus the fact that config `env` publishes unconditionally and has no "honour an existing value" semantics.
- **`PI_CODING_AGENT_DIR` as a `CODEX_HOME`-style env pointer.** Rejected, and the reasoning matters: the variable **does** relocate sessions, global packages and auth, because they all live under `getAgentDir()`. The real reasons are (a) the ticket specifies the whole `~/.pi` at `/agent-vm-state/pi`, while the variable maps only the `agent/` subdirectory; (b) a config `env` pair reaches only the tools that declare it, so a bare `pi` inside `agent-vm shell` (and any tool added later) would silently lose the mapping, whereas the compiled link is unconditional; (c) `CODEX_HOME` exists only because a `~/.codex` symlink would shadow codex's own install prefix — Pi installs under `/opt/agent-vm/pi`, so it has no such conflict and the default symlink shape applies with no second mechanism.
- **Teach the wrapper Pi's option-value table** to close the two argv-scan imprecisions. Rejected: no build-time gate could keep that copy honest against the pin, and both consequences are bounded and pinned.
