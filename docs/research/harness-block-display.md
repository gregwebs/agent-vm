# Showing sandbox blocks inside coding-agent harnesses

Research date: 2026-10-11. For [Research harness plugins for displaying sandbox blocks](https://github.com/gregwebs/agent-vm/issues/318) in [Explore live network approvals](https://github.com/gregwebs/agent-vm/issues/296). Agent-vm baseline: `b33cf68`. Image submodule `vendor/agent-vm-images` at `087f8ba`.

## Scope and evidence

This compares extension points in the four launch verbs the question names: Claude Code, OpenAI Codex CLI, opencode and pi. It is a primary-source reading. It is **not an implementation or UX decision**. No harness was installed or run, and no hook, plugin or extension was exercised. Everything about harness behavior below is **documentation or source evidence, not tested behavior**. Untested inferences are marked **(assumption)**.

Versions matter. The image pins Claude Code `2.1.286`, Codex `rust-v0.159.3`, opencode `v1.18.34` and pi `@earendil-works/pi-coding-agent 0.87.1` (`images/standard/Dockerfile`, `images/tools/pi/package.json`). The Claude Code, Codex and opencode docs read here are the current published docs, which may be newer than those pins. Where the Claude Code changelog dates a feature, the date is given. Codex status-line items were checked in source at the pinned tag, and opencode's plugin hook types at the pinned tag. Pi was read from the pinned npm tarball (docs plus `.d.ts` files).

The constraint from [#297](https://github.com/gregwebs/agent-vm/issues/297#issuecomment-6107888118) still applies. Anything shown in the guest only displays a block and can be forged. Acting on a block always happens on the host.

## Bottom line

- **All four harnesses can show a host-originated block message without user action.** The paths differ, and so does who sees the message:
  - **Claude Code** has the most paths. A `FileChanged` hook can watch an absolute path; its `systemMessage` reaches **the human only**. A plugin **monitor** is a long-running command whose output lines reach **the agent** as notifications, and the agent can then tell the human. `PostToolUse`/`PostToolUseFailure` `additionalContext` reaches the agent next to a failed tool result. A status line with `refreshInterval` gives the human a persistent indicator. [C1][C2][C4][C5]
  - **pi**: a long-lived extension can call `ctx.ui.notify`/`setStatus`/`setWidget`, which reach **the human**. `pi.sendMessage` can add a custom message that goes to **the model** and can also be shown. A `tool_result` handler can rewrite a tool result. agent-vm already ships a mandatory pi extension through its `pi` wrapper, so packaging cost is lowest here. [P1][P2][P3]
  - **opencode**: a plugin is a long-lived JS/TS module with an SDK client. It can show `client.tui.showToast` to **the human**, add model context with `client.session.prompt({noReply: true})` for **the agent**, or rewrite tool output in `tool.execute.after`. [O1][O2][O5]
  - **Codex** has the fewest paths. There is no file-watch hook, background monitor or custom status-line command. Display is tied to hook events, mainly `PostToolUse`, which also fires after a non-zero Bash exit. Its `systemMessage` appears as a UI warning (**human**) and its `additionalContext` reaches the **agent**. Non-managed hooks need a one-time trust review unless they come from a managed `requirements.toml` layer. [X1][X2][X4][X5]
- **The agent seeing the block works in every harness.** The agent can then tell the human "run `agent-vm …` on your host". In each harness the same mechanism can instead feed a human-only surface. What the agent sees is a prompt-injection surface, because a guest process chooses which hostname gets blocked. See [Security notes](#security-notes).
- **No host→guest event channel exists yet.** The host writes nothing about blocks into the guest today. The cheapest channel follows an existing precedent: a host-written file under the per-project state mount `/agent-vm-state` (compare `clipboard.txt`). That mount is guest-writable and shared by concurrent launches of the same project. Whether guest-side file watching sees host-side writes through virtiofs is **untested**, so consumers should be able to poll.
- **Packaging seams already exist.** These are the image-owned `/opt/agent-vm/pi-extensions` plus the `pi` wrapper, the `/opt/agent-vm/seed.d/*` hooks the launcher runs on every boot, the provider "bypass" writers that merge into guest-state config, and per-tool `args`/`env` in `default-tools.toml`. Each harness also has a system or managed config tier that merges with the user's config.

## 1. Agent-vm context (source inspection)

| Fact | Where |
|---|---|
| The launch catalog is `dsh`, `pi`, `codex`, `opencode`, `claude`, `copilot`, `shell`. `claude` gets `--dangerously-skip-permissions`. `codex` gets `CODEX_HOME=/agent-vm-state/codex`. `codex` and `opencode` carry no default argv; their bypass config is written as files instead. | `crates/agent-vm/src/default-tools.toml` |
| Core binds are the guest HOME (non-root mode), the project dir and the per-project state dir at `/agent-vm-state`. | `crates/agent-vm/src/user.rs` `core_dir_volumes` |
| Guest `/tmp`, `/run`, `/dev/shm` and `/var/run` are guest tmpfs, so a host bind cannot land there. | `crates/agent-vm/src/guest_paths.rs` |
| Harness config lives in the state dir through HOME symlinks: `~/.claude → claude`, `~/.claude.json`, `~/.local/share/opencode`, `~/.config/opencode → opencode-config`, `~/.pi → pi`. Codex has `CODEX_HOME=/agent-vm-state/codex` instead. | `credential_provider.rs` `guest_home_links`, `guest_home.rs` |
| Provider "bypass" writers **merge** keys into guest-state config on every launch: `claude/settings.json`, `claude.json`, `opencode-config/opencode.json`. Codex `codex/config.toml` is written only if absent. | `credential_provider.rs` `write_anthropic_bypass`, `write_opencode_bypass`, `write_openai_bypass` |
| Precedent for a host→guest file: `<state>/clipboard.txt` is visible in the guest at `/agent-vm-state/clipboard.txt`, and the host CLI reads and writes it. | `crates/agent-vm/src/clipboard.rs` |
| The launcher runs every executable in `/opt/agent-vm/seed.d/*` on **every** launch, before the agent execs. Hooks must be idempotent. The claude layer installs `10-claude-plugins`. It copies image-baked plugins into the state dir once and merges `enabledPlugins`/`extraKnownMarketplaces` into the state `settings.json`, keeping user keys. | `run.rs` `RUN_IMAGE_SEED_HOOKS`; images `tools/claude/seed-claude-plugins.sh` |
| The `pi` wrapper always passes `--extension /opt/agent-vm/pi-extensions/guest-credential-warning.js`. That extension calls `ctx.ui.notify(…, "warning")` on `session_start` when `ctx.hasUI`. Image authors may add more extensions under `/opt/agent-vm/pi-extensions`. | images `tools/pi/pi.sh`, `tools/pi/extensions/guest-credential-warning.js`, `tools/pi/README.md` |
| Denials are enforced on the host network path. DNS for non-allowed names returns NXDOMAIN when a forwarder is available. No structured denial event stream or host→guest event channel was found. | `egress_policy.rs` (banner text), `network.rs`; [zellij research §4](https://github.com/gregwebs/agent-vm/blob/research/zellij-approval-surfaces/docs/research/zellij-approval-surfaces.md) |
| Binds are virtiofs. Guest-written files appear host-side (agentd heartbeat). | `ARCHITECTURE.md` heartbeat section; ADR-0002 |

## 2. Claude Code (pinned 2.1.286)

### Extension points that can show a message without user action

| Path | Trigger | Who sees it | Notes |
|---|---|---|---|
| `FileChanged` hook | A watched file changes on disk. The watcher is a filesystem watcher, not a tool-call inspector. A `SessionStart` hook can return `watchPaths` (absolute paths) to watch a file outside the working directory. | **Human only**. `systemMessage` appears as "a brief terminal notification" in interactive sessions. `additionalContext` is not among the fields read for this event. | No decision control. Added in 2.1.83 (2026-03-25). [C1 §FileChanged][C11] |
| Plugin **monitor** (`experimental.monitors`) | Starts at session start (`when: "always"`) and runs for the whole session. | **Agent**: "What it prints reaches Claude as notifications." Claude "interjects when an event arrives". Monitor descriptions also show in the task panel. | Interactive sessions only. Not started when the Monitor tool is unavailable, which includes when `DISABLE_TELEMETRY` or `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` is set. The image sets the latter only inside its installer script, not at runtime. Added in 2.1.105. [C3 §monitors][C4 §Monitors][C5 §Monitor tool][C11] |
| `PostToolUse` / `PostToolUseFailure` / `PostToolBatch` hooks | After a tool call, for example a failed `curl` | **Agent** through `additionalContext`, a system reminder next to the tool result. A synchronous hook's `systemMessage` is a warning shown to **the human**. | 10,000-character cap. Async hooks deliver `additionalContext`/`systemMessage` to Claude on the next turn, and *not* to the human. `asyncRewake` with exit 2 wakes an idle Claude. [C1 §JSON output, §PostToolUseFailure, §Run hooks in the background] |
| `SessionStart` hook | Session start or resume | **Agent** (`additionalContext`) | Good for static guidance such as "agent-vm block events are at `<path>`". It can also return `watchPaths` for `FileChanged`. [C1 §SessionStart, §Add context for Claude] |
| `terminalSequence` hook output | Any hook | **Human**, as a desktop notification through OSC 9/99/777, or the window title through OSC 0/1/2 | Interactive sessions only. Restricted to those OSCs plus BEL. Added in 2.1.141. [C1 §Emit terminal notifications][C11] |
| Status line (`statusLine` + `refreshInterval`) | Event-driven, plus every N seconds (minimum 1) | **Human only** (persistent footer) | One `statusLine` per settings resolution, so agent-vm's would conflict with a user's own. A plugin's `settings` can set only `agent` and `subagentStatusLine`, not `statusLine`. `refreshInterval` added in 2.1.97. [C2][C3 §settings][C11] |
| MCP **channel** (`notifications/claude/channel`) | Server push | **Agent** | Research preview. Custom channels need `--dangerously-load-development-channels`. Requires claude.ai or Console auth, and Team/Enterprise orgs must enable it. Not a stable packaging target. [C6][C7] |
| MCP tool (pull) | The agent calls it | Agent, plus the tool call visible to the human | No push. Standard MCP `list_changed` only refreshes lists. [C12] |

### How it would learn about blocks

- **Watch:** `SessionStart` returns `watchPaths: ["/agent-vm-state/…/blocks.jsonl"]`, and a `FileChanged` hook formats a new record into `systemMessage`. Whether Claude Code's watcher sees writes the host makes through virtiofs is **untested (assumption: it may not)**.
- **Tail/poll:** a monitor runs a small script that polls or tails the file and prints one line per new block. Polling avoids the watcher question.
- **Inference only:** a `PostToolUseFailure` hook can match "Could not resolve host" or similar without any host channel. It cannot tell an agent-vm block from an ordinary network failure **(assumption)**.

### Packaging options

| Option | Mechanism | Conflict with user settings |
|---|---|---|
| Image plugin plus `--plugin-dir` | Add `--plugin-dir /opt/agent-vm/claude-plugin` to `claude`'s default `args`. The plugin bundles hooks and a monitor. [C10] | Plugin hooks merge with the user's hooks. A user-defined catalog entry for `claude` would drop the flag. |
| Seed into state | Reuse the `seed.d` pattern to install or enable a plugin in `~/.claude` (state). | Visible and removable by the user. The seed only adds and never overwrites, so user changes persist. |
| Managed drop-in | `/etc/claude-code/managed-settings.d/agent-vm.json` baked into the image. [C9] | Managed hooks merge and cannot be disabled by user `disableAllHooks`. A managed `statusLine` would override the user's. A malformed managed file stops Claude Code from starting. [C1 §Hook locations][C9] |
| Bypass writer | Merge hooks into `claude/settings.json` from `write_anthropic_bypass`. | Mixes agent-vm keys into user-owned state. |

## 3. OpenAI Codex CLI (pinned rust-v0.159.3)

| Path | Trigger | Who sees it | Notes |
|---|---|---|---|
| `PostToolUse` hook | After Bash and other tools. "For Bash, it also runs after commands that exit with a non-zero status." | **Agent**: `additionalContext` "is added as extra developer context". **Human**: `systemMessage` is "surfaced as a warning in the UI". | Plain stdout is ignored. Model-visible output is capped at about 2,500 tokens by default. [X1 §PostToolUse, §Common output fields, §Large hook output] |
| `SessionStart`, `UserPromptSubmit`, `Stop` hooks | Lifecycle | Agent (context) and human (`systemMessage`) | `Stop` is a natural "check for new blocks at end of turn" point. [X1] |
| Background (`async`) hooks | Same events | Delivered "at the next safe point". If no turn is active, delivery "waits until the next user turn". | Cannot wake an idle session. Up to 8 concurrent. [X1 §Run hooks in the background] |
| `tui.status_line` | n/a | Human | Fixed item identifiers only (`model`, `git-branch`, `run-state`, …). No custom command or file item exists at the pinned tag. **Not usable.** [X2][X5] |
| `notify` | Only `agent-turn-complete` | Runs an external program | Not driven by block events. [X3 §notify] |
| `tui.notifications` | Codex's own events | Human (OSC 9/BEL) | Cannot carry custom text. [X2] |

There is no file-watch event and no persistent monitor. A block can surface only when the agent next uses a tool, ends a turn, or the user types.

**Trust and packaging.**

- Non-managed hooks (user, project or plugin) "must be reviewed and trusted before they run". Trust is recorded against the hook's hash, and new or changed hooks are "skipped until trusted" via `/hooks`. `--dangerously-bypass-hook-trust` skips this per invocation. [X1 §Review and trust hooks]
- Managed hooks from `requirements.toml` (`/etc/codex/requirements.toml` on Unix) are "trusted by policy". They need a `managed_dir` with absolute script paths, and users cannot disable them from the hook browser. [X1 §Managed hooks][X4 §Locations and precedence]
- The packaging options are:
  - an image `/etc/codex/requirements.toml` that adds `[hooks]` only;
  - hooks in `CODEX_HOME/hooks.json` (state) plus a one-time user trust;
  - adding `--dangerously-bypass-hook-trust` to `codex`'s args.

  Whether a `requirements.toml` containing only `[hooks]` changes any other user-visible policy is **untested**. Hooks are on by default (`features.hooks`). [X1 §Turn hooks off]

## 4. opencode (pinned v1.18.34)

| Path | Who sees it | Notes |
|---|---|---|
| Plugin module with a long-lived watcher started from the plugin function, which then calls `client.tui.showToast({message, variant})` | **Human** (toast) | The plugin function receives `client`, `$`, `directory`, `serverUrl`. Plugins run in the opencode process. [O1][O2 §TUI][O5] |
| Same plugin calling `client.session.prompt({ path:{id}, body:{ noReply:true, parts:[…] } })` | **Agent** ("Inject context without triggering AI response") | Needs a session id, available from `session.*` events. Visibility to the human in the transcript is **untested**. [O2 §Sessions] |
| `tool.execute.after` hook | **Agent**: it can rewrite `output.output` and `output.title` of a tool result | Types from the pinned tag. [O5] |
| `event` hook (`session.idle`, `session.error`, …) | n/a | A trigger point. [O1 §Events] |
| HTTP `/tui/show-toast` on the TUI's server | Human | The TUI picks a random port unless `--port` is passed. An external guest process could use it only if the port is known. [O3] |

No custom status-line command was found in the docs. MCP is pull-only.

**Packaging.**

- Plugins load from `~/.config/opencode/plugins/` (state, via the `opencode-config` link), from `.opencode/plugins/` in the project, or from npm. npm plugins are installed with Bun at startup, which needs network that default-deny egress blocks. [O1]
- `OPENCODE_CONFIG_DIR` adds a directory searched "for agents, commands, modes, and plugins". It could point at an image-owned `/opt/agent-vm/opencode` through the tool's `env` in `default-tools.toml`. [O4 §Custom directory]
- There is also a managed `/etc/opencode/opencode.json` tier that overrides everything. [O4 §Managed settings]
- Config files merge, and plugin hooks from all sources run in sequence, so conflicts are limited to deliberate key overrides. [O1 §Load order][O4]

## 5. pi (pinned 0.87.1)

| Path | Who sees it | Notes |
|---|---|---|
| `ctx.ui.notify(msg, "warning")` | **Human** | Already used by agent-vm's mandatory extension. [P2][local `guest-credential-warning.js`] |
| `ctx.ui.setStatus(key, text)` / `setWidget(key, lines)` | **Human** (persistent footer entry or widget above or below the editor) | Fire-and-forget. RPC clients may display or ignore them. [P2][P5] |
| `pi.sendMessage({customType, content, display}, {triggerTurn, deliverAs})` | **Agent** ("Custom content stored and sent to the model"). Also the human when `display: true`. | `deliverAs: "nextTurn"` avoids interrupting. `triggerTurn` can start a turn. [P1 §State][P2][P3] |
| `tool_result` handler | **Agent** (can replace `content` and `isError`) | Handlers compose. [P1 §Events][P2] |
| `before_agent_start` | Agent (prompt sections) | For static guidance. [P1] |

Long-lived watchers must start in `session_start` and close in `session_shutdown`, not in the factory. [P1 §Respect the runtime lifecycle] pi has no built-in MCP in the pinned package docs.

**Packaging.** Add a second file under `/opt/agent-vm/pi-extensions` and either load it from `pi.sh` (`--extension`, like the warning) or make it optional. This is the existing image-owned seam (ADR-0012, ADR-0023). It needs no user config and does not conflict with user extensions, because extensions compose. Only `ctx.hasUI` (TUI/RPC) modes show UI.

## 6. What the host→guest channel would need to provide

The minimum common to all four harnesses is a host-written, read-only-by-convention record stream that a guest-side consumer can poll. Requirements implied by the paths above:

1. **Location.** It must be under an existing bind, which in practice means the state dir (`/agent-vm-state`). Guest tmpfs paths are not reachable by a host bind. The state dir is per project and shared by concurrent launches, so the stream must be **per launch**. One option is a file keyed by a launch id, with the path passed to the guest in an env var.
2. **Format.** Append-only JSONL with these properties:
   - a monotonically increasing sequence number, so consumers keep a cursor and show only new records;
   - the block kind (#297: all blocks are shown, labelled by kind) and the destination as plain text;
   - a timestamp, and a count or first/last-seen for coalesced repeats;
   - no URLs with tokens, request bodies or credentials.
3. **Bounding.** Size cap or rotation. Coalescing so a guest-triggered flood cannot grow the file without limit or spam the UI.
4. **Change detection.** Polling must work. Whether guest inotify, Claude Code's `FileChanged` watcher or Node `fs.watch` see host-side writes through virtiofs is **untested**. One alternative avoids the question: the host uses the microsandbox exec API to run a writer inside the guest that appends to a guest-local tmpfs file (zellij research §4, path 2).
5. **Liveness.** A session marker, so a consumer can ignore a stale file left by a previous launch.
6. **Direction.** The host writes and never reads it back as authority. The guest can edit or forge it (same caveat as the state-dir path in the zellij research).
7. **Remedy text.** The host-side command to run is better left to the consumer's fixed text, or rendered from host data, than taken from a guest-influenced field.

An MCP pull tool (`list_sandbox_blocks`) works in Claude Code, Codex and opencode but not pi. It would read the same file. It shows blocks only when the agent asks.

## 7. Agent-visible versus human-only

| Harness | Human only | Agent (and can relay to human) |
|---|---|---|
| Claude Code | `FileChanged` `systemMessage`, status line, `terminalSequence`, synchronous-hook `systemMessage` | Monitor notifications, `PostToolUse*`/`Stop`/`SessionStart` `additionalContext`, async hooks, `asyncRewake` |
| Codex | `systemMessage` warning | `additionalContext` on `PostToolUse`/`Stop`/`SessionStart`/`UserPromptSubmit` |
| opencode | `tui.showToast` | `session.prompt({noReply})`, `tool.execute.after` output rewrite |
| pi | `notify`, `setStatus`, `setWidget` | `sendMessage` (`display` controls human visibility), `tool_result` rewrite |

## Security notes

- **Forgeable display.** Every surface above runs in the guest. A compromised guest can suppress or forge it. This matches #297.
- **Agent-facing text is an injection vector.** A guest process can cause a block of `attacker.example`, and an agent told about it may ask the human to allow it. The host-side approval surface must show the canonical host, scope and session from host records and require explicit confirmation. A suggested command in agent text should be a navigation aid, not an approval. Keep destination strings short, escaped and labelled as data.
- **Harness-specific hazards:**
  - Claude Code warns that `additionalContext` phrased like system commands can trigger prompt-injection defenses. [C1 §Add context for Claude]
  - Codex spills oversized hook output to `<temp_dir>/hook_outputs/…`. [X1 §Large hook output]
- **Managed tiers are policy tiers.** `/etc/claude-code/managed-settings.d`, `/etc/codex/requirements.toml` and `/etc/opencode/` override or bind the user. Using them for a display-only feature crosses agent-vm's parity principle (ADR-0021). That tradeoff is for the human to weigh.

## Untested assumptions and open questions

1. Whether guest-side file watchers see host writes through virtiofs: Claude Code `FileChanged`, Node `fs.watch`, inotify.
2. Whether the docs-described features behave the same at the pinned versions. Claude Code is covered by changelog dates. Codex hook trust and `PostToolUse` semantics and opencode `noReply` were not dated against the pins.
3. Codex: whether a `requirements.toml` containing only `[hooks]` has side effects. Whether hook trust persists in `CODEX_HOME` across launches.
4. opencode: how a `noReply` message renders to the human. Whether a plugin from `OPENCODE_CONFIG_DIR` loads without network (no `package.json` deps).
5. Claude Code: whether plugin monitors run under agent-vm's auth setup (Monitor-tool availability conditions). Whether monitor output counts against context in a noisy flood.
6. Whether the guest should be told at all for non-agent tools (`shell`, `dsh`, `copilot`), which are out of scope here.

## Sources

Claude Code (code.claude.com, retrieved 2026-10-11):
- [C1] Hooks reference: https://code.claude.com/docs/en/hooks
- [C2] Status line: https://code.claude.com/docs/en/statusline
- [C3] Plugin manifest reference: https://code.claude.com/docs/en/plugins-reference
- [C4] Plugin components: https://code.claude.com/docs/en/plugins/components
- [C5] Tools reference, Monitor tool: https://code.claude.com/docs/en/tools-reference#monitor-tool
- [C6] Channels: https://code.claude.com/docs/en/channels
- [C7] Channels reference: https://code.claude.com/docs/en/channels-reference
- [C8] Settings: https://code.claude.com/docs/en/settings
- [C9] Managed settings: https://code.claude.com/docs/en/managed-settings
- [C10] CLI reference (`--plugin-dir`, `--settings`): https://code.claude.com/docs/en/cli-reference
- [C11] Changelog (2.1.83 FileChanged; 2.1.97 refreshInterval; 2.1.105 plugin monitors; 2.1.141 terminalSequence; 2.1.286 dated 2026-09-30): https://code.claude.com/docs/en/changelog
- [C12] MCP: https://code.claude.com/docs/en/mcp

OpenAI Codex:
- [X1] Hooks: https://learn.chatgpt.com/docs/hooks.md
- [X2] Config reference (`tui.status_line`, `tui.notifications`, `notify`, `features.hooks`): https://learn.chatgpt.com/docs/config-file/config-reference.md
- [X3] Advanced config, notifications: https://learn.chatgpt.com/docs/config-file/config-advanced.md
- [X4] Managed configuration: https://learn.chatgpt.com/docs/enterprise/managed-configuration.md
- [X5] Source at pinned tag, status-line items: https://github.com/openai/codex/blob/rust-v0.159.3/codex-rs/tui/src/bottom_pane/status_line_setup.rs
- [X6] AGENTS.md (global `CODEX_HOME/AGENTS.md`): https://learn.chatgpt.com/docs/agent-configuration/agents-md.md

opencode:
- [O1] Plugins: https://opencode.ai/docs/plugins/
- [O2] SDK (`session.prompt` `noReply`, `tui.showToast`): https://opencode.ai/docs/sdk/
- [O3] Server (`/tui/show-toast`, TUI random port): https://opencode.ai/docs/server/
- [O4] Config (precedence, `OPENCODE_CONFIG_DIR`, managed `/etc/opencode/`): https://opencode.ai/docs/config/
- [O5] Plugin hook types at pinned tag: https://github.com/sst/opencode/blob/v1.18.34/packages/plugin/src/index.ts
- [O6] Rules (global `~/.config/opencode/AGENTS.md`): https://opencode.ai/docs/rules/

pi (`@earendil-works/pi-coding-agent@0.87.1` npm tarball, https://registry.npmjs.org/@earendil-works/pi-coding-agent/-/pi-coding-agent-0.87.1.tgz):
- [P1] `docs/extensions.md`
- [P2] `dist/core/extensions/types.d.ts` (`ExtensionUIContext.notify/setStatus/setWidget/setFooter`, `sendMessage`, `ToolResultEventResult`)
- [P3] `dist/core/messages.d.ts` (`CustomMessage.display`)
- [P4] `docs/configuration.md` (agent-dir `AGENTS.md`)
- [P5] `docs/rpc-extension-ui.md`

Local: `crates/agent-vm/src/{default-tools.toml,guest_home.rs,guest_paths.rs,user.rs,credential_provider.rs,clipboard.rs,run.rs,egress_policy.rs}`, `ARCHITECTURE.md`, `vendor/agent-vm-images/images/{standard/Dockerfile,tools/claude/seed-claude-plugins.sh,tools/pi/pi.sh,tools/pi/extensions/guest-credential-warning.js,tools/pi/README.md}`; prior research `research/zellij-approval-surfaces` and `research/live-network-notifications`.
