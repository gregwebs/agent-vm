# Live network approvals: zellij as a guest display or host approval surface

Research date: 2026-10-10. For [Research zellij as an approval surface (guest and host)](https://github.com/gregwebs/agent-vm/issues/309) in [Explore live network approvals](https://github.com/gregwebs/agent-vm/issues/296). Feeds [Choose the notification and approval experience](https://github.com/gregwebs/agent-vm/issues/297). Agent-vm baseline: `766cd51e044a2832caa46fad3c8c638b2532dcd3`. Target: zellij **0.45.0**, the version pinned in `vendor/agent-vm-images/images/Dockerfile` (`ARG ZELLIJ_VERSION=0.45.0`). Current upstream is **0.45.1** (2026-08-28); differences are noted where they matter.

## Scope and evidence

This is a primary-source comparison, **not an implementation or UX decision**. Evidence classes are marked inline:

- **Documented**: the official zellij user guide (read via its single-page build at zellij.dev, which describes 0.45.0 behaviour explicitly), the v0.45.0 `CHANGELOG.md`, and the v0.45.1 release notes. [Z1][Z2][Z3]
- **Source**: first-party zellij source at tag `v0.45.0`, downloaded as the GitHub tag tarball and read, not built. [Z4]–[Z9] A source reading shows what the code does on that path. It is not a test.
- **agent-vm code**: read at the baseline commit. File references are under `crates/agent-vm/src/`.
- **Untested assumption**: anything labelled *assumption* or *unknown*.

**Run locally, exactly:** `zellij --version` and `zellij setup --check` on the macOS host. Both reported the Homebrew **0.44.3** install, not 0.45.0. `setup --check` printed config, cache and data dirs, but no socket dir. Nothing else was run. No session, pane, plugin, pipe or escape-sequence experiment was performed, nothing was installed, and no guest was booted.

Required experience (from #296/#298): the launcher effectively disappears after startup. Attached guest-app input is never taken. A denied request fails immediately. The human may later allow that host for the **session** or **project permanently**, then retry. The guest is untrusted, and the default guest user numerically matches the host user ([CONTEXT.md](../../CONTEXT.md), *Guest user*).

## Bottom line

- **Guest-side zellij is feasible but is a cosmetic, advisory display at best.** Everything it shows is guest-controlled. It needs a host→guest event path that does not exist today. The boot-image contract does not require zellij, so user-owned images may lack it. It also adds the transparency costs below to every interactive launch. The guest's own OSC 9/777 desktop notification is a lighter advisory path with the same trust level: plain attach already passes it to the host terminal, and zellij 0.45 forwards it too. [Z1 §Desktop notifications]
- **Host-side zellij can isolate an approval pane from guest *rendering*.** Each pane has its own emulator grid, and the socket lives in a host directory with mode 0700 that agent-vm does not bind by default. But in 0.45.0, **guest output can move host focus**. A pane that writes zellij's nested-session DCS frame (`ESC P 26661 n … ESC \`) with a `FocusHost{direction}` message makes the host move the focus of the clients viewing that pane to the adjacent pane. That path has no "is this a live nested guest" check. [Z6] So a focused, keystroke-confirmed approval pane next to the guest pane could receive keystrokes the user meant for the agent. A host approval surface would need (a) an approval gesture that cannot be typed blindly, (b) a way to neutralise that DCS path (no config option for it was found), or (c) a "key-to-open" design where nothing approval-capable is adjacent or focused until the user acts. *Exploitability is untested.*
- **Transparency is achievable for keys, not for the whole terminal.** Locked default mode plus `keybinds clear-defaults=true` binds no keys, so Ctrl+o/t/s reach the tool. That claim is from the docs and not tested here. But zellij is a full terminal emulator. It owns scrollback (host scrollback is lost to the alternate screen), captures the mouse by default, has OSC 8 hyperlinks **off by default**, and answers OSC 52 clipboard reads with an empty reply. The interactive client also **does not return the pane's exit code**. [Z1][Z7][Z9]
- **Host-side zellij is a new host dependency** with real practicality costs: bundling or version skew, nesting inside a user's own zellij/tmux, exit-code and non-TTY plumbing. Its license is compatible (MIT). [Z8]

## 1. Transparency and terminal pass-through

| Concern | Finding | Evidence |
|---|---|---|
| Keystrokes (Ctrl+o, Ctrl+t, Ctrl+s…) | `default_mode "locked"` starts in locked mode. `keybinds clear-defaults=true { … }` removes all defaults, and `unbind` removes individual keys. Locked mode's only default binding is `Ctrl g` (unlock). A config that clears defaults and binds nothing in `locked` leaves no key that zellij consumes. The "Unlock-First (non-colliding)" preset is the documented route for collisions. Outer-terminal prefix keys (tmux/zellij) are taken before the inner zellij sees them. | Documented [Z1 §Options default_mode, §Overriding keys, §FAQ]. *Not tested:* that no key is consumed with an empty locked block. |
| Frameless/minimal UI | `pane_frames false` / `pane_frame_style "none"`, a layout without tab/status bar plugins, `show_startup_tips false`, `show_release_notes false`. `--layout-string` takes a layout inline. | Documented [Z1 §Options, §Inline Layouts] |
| Scrollback | The client enters the host terminal's alternate screen (`ESC[?1049h`), so scrollback lives in zellij (`scroll_buffer_size`, default 10000) instead of the host terminal. With no keybindings there are no keyboard scroll or search keys. Mouse-wheel scrolling enters scroll mode implicitly (`scroll_mode_sync`, default true). | Source [Z9]. Documented [Z1 §Options, §Modes] |
| Mouse | `mouse_mode` defaults to true, so zellij handles mouse events, and Shift bypasses it. `mouse_click_through` defaults to false: the first click only focuses a pane. *Assumption:* `mouse_mode false` stops zellij from requesting host mouse reporting, so mouse-aware tools lose it. | Documented [Z1 §Options, §Known Issues] |
| OSC 52 clipboard | Writes pass through (or via `copy_command`). **Reads return empty since 0.45.0** unless `dangerously_enable_paste_buffer_read`. Plain attach leaves reads to the host terminal's policy. | Documented [Z1 §Terminal Features, §FAQ] |
| OSC 8 hyperlinks | `osc8_hyperlinks` defaults to **false**, so links emitted by tools are not clickable unless enabled. | Documented [Z1 §Options] |
| Kitty keyboard protocol | Used with the host terminal when supported (`support_kitty_keyboard_protocol`, default on if the terminal supports it). The grid tracks per pane whether the app requested it. | Documented [Z1]. Source [Z9] |
| Bracketed paste | Tracked per pane. Pastes are wrapped when the pane enabled the mode. | Source [Z9] |
| True color, images, focus | Truecolor themes are supported. Kitty graphics, Sixel (only when the terminal supports it) and focus reporting (mode 1004) are passed through or emulated. Zellij re-renders everything, so fidelity depends on its emulator. | Documented [Z1 §Terminal Features, §Themes]. *Untested* for Claude Code/codex UIs. |
| Resize | Zellij sizes the pane PTY. Since 0.45.0 each tab is sized to the clients viewing it. *Assumption:* the pane's foreground process gets SIGWINCH as with any PTY, and agent-vm's attach forwards it as it does today. | Documented [Z1 §mirror_session note] |
| Startup latency | No documented figure. **Unknown**, not measured. | none |
| Exit code | The interactive client's `start_client` returns `Option<ConnectToSession>` and exits with a reason message, not the pane's status. Only CLI *actions* return a custom status. A command pane's exit status is visible via `zellij action list-panes --json` (`exit_status`) while the pane exists. By default a command pane stays open after exit ("press ENTER to re-run") unless `close_on_exit=true`. | Source [Z7]. Documented [Z1 §Programmatic Control, §Layouts close_on_exit, §Zellij Run] |

Implication: a wrapper must recover the exit code out of band, for example from a host-private status file written by the inner launcher, or from `list-panes --json` before teardown. It must also stop the session itself, because a remaining floating or plugin pane keeps the session alive (*assumption*).

## 2. Non-disruptive display

- `zellij run`, `zellij action new-pane`, `zellij edit` and `zellij plugin` accept **`--no-focus`**: "Open the pane without changing the focus of any client". This was new in 0.45.0 (PR #5346). Floating panes take `--floating --x/--y/--width/--height`, `--pinned` (always on top) and `--borderless`. The docs show a one-line, borderless, pinned overlay used as a custom status element. [Z1 §Zellij Run, §Borderless Panes][Z2]
- `set-pane-color` can flash a pane. `show-floating-panes` / `hide-floating-panes` toggle visibility (exit codes 0/2/1), and `close-pane --pane-id` dismisses a pane. All accept a pane id, so no focus change is needed. [Z1 §Controlling Floating Panes, §Changing Pane Colors]
- A plugin pane (a status-bar-like WASM plugin) can receive messages via pipes and re-render without focus. Building one means writing, shipping and permissioning a WASM plugin. [Z1 §Pipes]
- *Untested:* whether `--no-focus` combined with hidden floating panes makes them visible, and whether a pinned overlay hides cells the tool needs (it overlaps the main pane by design).
- Dismissal "without losing place": closing or hiding a non-focused pane does not move focus by construction. Leaving scroll mode keeps the pane's scroll position (0.45.0). [Z1 §Modes]

## 3. External control and session addressing

- **Control surface:** `zellij --session <name> action …`, `zellij run`, `zellij pipe` (to a named plugin or broadcast; launches the plugin on first message; supports STDIN streaming and plugin backpressure) and `zellij subscribe` (streams any pane's rendered viewport as NDJSON). Inputs `write-chars`, `paste` and `send-keys` take `--pane-id`, so **any client that can reach the session can type into any pane, including an approval pane, and read every pane**. [Z1 §CLI, §Pipe, §Subscribe, §Programmatic Control]
- **Addressing:** by session name (`--session`, or `ZELLIJ_SESSION_NAME` inside panes). Panes are `terminal_N` / `plugin_N`, and new-pane actions print the created id. [Z1 §CLI Actions, §Scripting Pane and Tab Creation]
- **Socket location (0.45.0 source):** `ZELLIJ_SOCK_DIR` = `$ZELLIJ_SOCKET_DIR` if set, else `ProjectDirs::runtime_dir()`, else `std::env::temp_dir()/zellij-<uid>`, each followed by `/contract_version_1/<session>`. [Z4] `directories` 6.0.0's `runtime_dir` is `$XDG_RUNTIME_DIR/<project>` on Linux and **none on macOS**. [D1] So:
  - Linux: `$XDG_RUNTIME_DIR/zellij/contract_version_1/` (fallback `$TMPDIR` or `/tmp/zellij-<uid>/…`).
  - macOS: `$TMPDIR/zellij-<uid>/contract_version_1/`, where `$TMPDIR` is the per-user `/var/folders/…/T/`.
  - The client creates the socket dir and `chmod 0700`s the leaf `contract_version_1` directory. [Z5] Access control is filesystem permission only. No peer-credential or token check was found on the IPC path, and none is documented. *Unknown:* whether one exists elsewhere.
  - The log lives at `$temp_dir/zellij-<uid>/zellij-log/zellij.log`, and the plugin-permission cache at `<cache>/permissions.kdl` (on macOS, `~/Library/Caches/org.Zellij-Contributors.Zellij`). [Z1 §Plugin API - Logging][Z4]
- Sessions created by one zellij version can be attached by another that shares contract version 1. [Z1 §FAQ]

## 4. Guest-side zellij (display only, advisory)

**How a denial reaches the guest.** Today a denial is enforced on the host side of the network path (`network.rs`, default-deny egress since #302). The guest only sees a failed connection or NXDOMAIN, and there is no host→guest event channel. Candidate paths, all *unbuilt*:

1. Host writes an event file into an existing host-owned bind. The state dir is already mounted at `/agent-vm-state` (`user.rs` `core_dir_volumes`). A guest watcher then calls `zellij pipe` / `zellij run --floating --no-focus`.
2. Host uses the microsandbox exec API (already used for `attach_with` / `exec_stream_with` in `run.rs`) to run `zellij --session <s> action …` inside the guest.
3. Guest-local inference: the tool or a shim sees the failure and displays it. No host involvement.

**Security.** Every pixel in the guest's terminal is guest-controlled. A compromised guest can suppress, delay or forge the bar, so the display is advisory only and must never carry approval authority. Path 1 must not let the guest write anything the host later trusts. The state dir is guest-writable, so the host must treat the events it wrote there as write-only from its side.

**Availability.** The base image installs zellij 0.45.0 with a hard failure (`AGENT_INSTALL_SOFT_FAIL=` empty in `images/Dockerfile`), and `standard` derives from it. But the **boot image contract** requires only Bash, the selected program and passwd/group files. User-owned `--image` / config images and local rootfs images may lack zellij, and older retained default images may carry a different zellij. [CONTEXT.md *Boot image contract*, *Image selection*] Non-TTY launches (`stdin` not a terminal, which takes the `exec_stream_with` branch) would not use zellij at all.

**Cost.** Every interactive launch pays the transparency costs in §1. A lighter alternative with identical trust: the guest emits OSC 9/777, which a plain attach already passes to the host terminal. Zellij 0.45 forwards these too (`host_notification_protocol`). Whether a terminal shows it is "up to the host terminal and the operating system". [Z1 §Desktop notifications]

## 5. Host-side zellij (possible trusted approval surface)

**Shape (illustrative, not proposed syntax):** the launcher starts host zellij with a generated config and an inline layout. The main pane runs the real `agent-vm` launch, which attaches the guest. A trusted approval pane runs host-only code, for example a review command against host-owned records, opened `--floating --no-focus --pinned` on demand or kept hidden.

**What isolates the approval pane:**

- Rendering: each pane has its own emulator grid, and guest bytes in the main pane draw only inside that pane. *Assumption from architecture.* No zellij doc states this as a security guarantee.
- Socket and config: under the host's `$TMPDIR` / `$XDG_RUNTIME_DIR` and `~/.config/zellij` / the cache dir. agent-vm's core binds are the **guest HOME** (sourced from `<state_dir>/home`, not the real `$HOME`), the **project dir** (the canonical cwd, writable) and the **state dir** (`/agent-vm-state`), plus explicit `--mount`s (`user.rs` `core_dir_volumes`, `run.rs` ~L1146–1200, `mount.rs` `prepare`). No default bind covers `$TMPDIR`, `$XDG_RUNTIME_DIR` or zellij's config/cache. The guest env is an allowlist (`GUEST_ALWAYS_ENV`, `RAW_FORWARDED_ENV` in `run.rs`), so `ZELLIJ*` variables are not forwarded. Guest `/tmp`, `/run`, `/dev/shm` and `/var/run` are guest tmpfs (`guest_paths.rs`).
- **Gaps:** (a) Running from a cwd that contains these directories exposes them through the writable project bind. `cd ~ && agent-vm` exposes the whole host `$HOME`, as `mount.rs` itself notes, including `~/.config/zellij/config.kdl` (keybinds) and, on macOS, `~/Library/Caches/...Zellij/permissions.kdl` (plugin grants). A cwd at or above `/var/folders/…/T` exposes the macOS socket dir. (b) A `--mount` can cover them. `ProtectedHostFiles` today guards only Pi's credential files. (c) `--allow-host` makes host loopback reachable, which would include the zellij web server (`127.0.0.1:8082`) if a user enabled it. It is off by default. [Z1 §Options web_server] *Unknown:* whether a host Unix socket reached through virtio-fs is even connectable from the guest kernel. Treat exposure as a breach either way: the files are writable.

**What breaks isolation (source reading, untested):**

- **Focus steering by guest output.** The pane grid recognises DCS `26661 n` frames unconditionally ([Z6] `grid.rs` ~L4410). `Screen::handle_nested_session_message_from_pane` handles `FocusHost{direction: Some(d)}` by calling `tab.focus_pane_adjacent_to(pane_id, d, client)` for every client focused on that pane, floating panes included. That branch has **no `is_tracked` guard**, while `ToggleHostFullscreen` and `ShortcutUpdate` do ([Z6] `screen.rs` ~L3035–3130, `tab/mod.rs` ~L5234). `nested_session_handling "never"` only changes the automatic reaction to an announce. It does not disable frame parsing. So guest output can move focus onto an adjacent approval pane, and the user's next keystrokes land there. A guest can also `Announce` itself and then request host fullscreen of its own pane, which may obscure a tiled approval pane.
- **Spoofing.** The guest can draw a fake "approval" UI inside its own pane, set its pane title via OSC 0/2 (visible when frames are on), and raise OSC 9/99/777 desktop notifications that zellij forwards. Only properties the guest cannot write distinguish the real pane: its position, a host-drawn frame/colour, and the fact that it holds focus.
- **Emulator attack surface.** Zellij parses all guest output: VT, DCS, Sixel, kitty graphics and OSC 133. A parser bug is a host-process bug. Zellij runs as the host user outside the VM, so this **moves part of the guest→host attack surface out of the VM boundary**, compared with today's byte relay to the user's own terminal emulator. That terminal already parses the same bytes, but it is not the process that holds approval authority.

**Focus and the "attached input is never taken" rule.** An approval pane that grabs focus on a denial violates the rule: the next keystrokes meant for the agent go to the approval pane. `--no-focus` opening plus an explicit user gesture to focus it (a "key-to-open bar") respects the rule. It requires one bound key in locked mode, which reintroduces a collision risk. Given the `FocusHost` path, the approval action itself should not be a single blind-typeable key (for example Enter or `y`) in a pane adjacent to the guest pane.

## 6. Host-side practicality

- **Install/bundle:** first-party release assets exist for `{x86_64,aarch64}-apple-darwin` and `{x86_64,aarch64}-unknown-linux-musl`, plus `zellij-no-web-*` variants built without the web-server capability, each with a `.sha256sum`. [Z3 assets][Z1 §Web Client compile-time flag] Options: bundle a pinned `zellij-no-web` with agent-vm (size and release-cadence cost), or depend on the user's `PATH` zellij (version skew: this host has 0.44.3, which lacks `--no-focus` and nested handling).
- **License:** MIT. [Z8]
- **Version skew:** the socket dir is shared across versions with the same contract (`contract_version_1`). A bundled zellij's sessions appear in the user's own `zellij ls` and can be attached by it. That is acceptable, since same-uid host processes are already trusted, but confusing. 0.45 changed plugin API signatures and defaults (frames, stacks), so config written for one minor version may not suit another. [Z1 §FAQ][Z2]
- **Users already in tmux, screen or zellij:** the outer multiplexer takes its prefix keys first. Inside an outer zellij 0.45, the inner session is detected as nested and the outer shows an "ask" prompt by default (`nested_session_handling`). 0.45.1 detects nesting over SSH without forwarding env vars. [Z1 §Nested Sessions][Z3] Double scrollback and mouse ownership compound. *Untested.*
- **SSH:** host zellij runs fine in an SSH PTY. OSC 52 is the only clipboard path that works remotely. [Z1 §FAQ]
- **Signals and piping:** in the main pane, `agent-vm`'s stdin is a zellij pane PTY. Ctrl+C is a byte that agent-vm's raw-mode attach forwards, as today. *Assumption:* behaviour is unchanged. Zellij's own SIGINT/SIGTERM/SIGHUP handling defaults to **detach** (`on_force_close`), which would leave the session and the guest running after a closed terminal unless set to `quit`. [Z1 §Options on_force_close] Non-interactive runs (`!stdin.is_terminal()` in `run.rs`) must bypass zellij to keep stdin/stdout piping and exit codes. Interactive exit codes need an out-of-band path (§1).

## 7. Unknowns and questions for #297

**Focused technical follow-ups (none done here):**

- Reproduce the `FocusHost` DCS focus move from inside a guest through agent-vm attach against host zellij 0.45.0/0.45.1. Check whether upstream would accept an `is_tracked` guard or a config switch to ignore nested frames.
- Measure startup latency and test exit-code recovery, `on_force_close quit`, SIGWINCH and Ctrl+C under a host wrapper.
- Confirm that locked mode with `clear-defaults` passes Ctrl+o/t/s/g and kitty-encoded keys through to Claude Code and codex. Check mouse, OSC 8 and scrollback ergonomics.
- Check whether a host Unix socket reached through a virtio-fs bind is connectable from the guest. Decide whether `ProtectedHostFiles` or the mount planner should refuse binds that cover zellij's socket, config or cache dirs.
- Measure `--no-focus` behaviour with hidden floating panes and with pinned overlays.

**Human choices still open:**

1. Is a guest-side display worth its transparency cost, given that it is advisory and an OSC 9/777 notification offers the same trust level more cheaply?
2. Should a host-side approval surface live inside the launch's terminal at all, or in a separate host CLI or terminal as #298 found? Accepting zellij as a host dependency trades the "launcher disappears" property for an in-terminal surface whose isolation from guest output is partial.
3. If host-side: is a key-to-open bar plus a non-blind confirmation acceptable? Which key may be bound in locked mode without colliding with tools?
4. Bundled zellij versus the user's zellij, and what to do when the user is already inside zellij or tmux.

## Conclusion

Guest-side zellij can show denials but adds only advisory, guest-forgeable UI, and it needs a new host→guest event path. Host-side zellij keeps its socket and config out of the guest by default and gives the approval pane its own render grid. In 0.45.0, though, guest output can steer host focus through the nested-session protocol, and zellij moves terminal parsing of guest bytes into a host process. Both options cost terminal transparency (scrollback, mouse, OSC 8, clipboard reads) and exit-code fidelity. The evidence supports these trade-offs. It does not select an experience; that belongs to #297.

## Primary sources

Retrieved 2026-10-10.

- [Z1] Zellij User Guide, single-page build: <https://zellij.dev/documentation/print.html>. Sections cited by name: FAQ; Options (`default_mode`, `pane_frames`, `pane_frame_style`, `mouse_mode`, `mouse_click_through`, `scroll_buffer_size`, `osc8_hyperlinks`, `support_kitty_keyboard_protocol`, `on_force_close`, `host_notification_protocol`, `nested_session_handling`, `dangerously_enable_paste_buffer_read`, `scroll_mode_sync`, `web_server`); Configuring Keybindings / Modes / Overriding keys; Zellij Run & Edit; CLI Actions; Zellij Plugin & Pipe; Zellij Subscribe; CLI Recipes (Borderless Panes, Controlling Floating Panes, Blocking Panes); Programmatic Control; Layouts (`close_on_exit`); Permissions; Plugin API - Logging; Pipes; Nested Sessions; Web Client; Terminal Features (Desktop notifications, Clipboard). The guide labels 0.45.0 changes explicitly.
- [Z2] zellij `CHANGELOG.md` at v0.45.0, section `[0.45.0] - 2026-08-20`: <https://github.com/zellij-org/zellij/blob/v0.45.0/CHANGELOG.md> (PRs #5346 `--no-focus`, #5417 nested sessions, #5472 paste-buffer read opt-in, #5485 OSC 9/777).
- [Z3] zellij v0.45.1 release notes and asset list: <https://github.com/zellij-org/zellij/releases/tag/v0.45.1>.
- [Z4] Socket, temp and cache dirs: <https://github.com/zellij-org/zellij/blob/v0.45.0/zellij-utils/src/consts.rs> (L89–111 cache/permissions; L320–349 Unix `ZELLIJ_TMP_DIR`, `ZELLIJ_SOCK_DIR`); `ZELLIJ_SOCKET_DIR`: <https://github.com/zellij-org/zellij/blob/v0.45.0/zellij-utils/src/envs.rs#L29-L31>.
- [Z5] Socket dir creation and `0o700`: <https://github.com/zellij-org/zellij/blob/v0.45.0/zellij-client/src/lib.rs#L420-L445>.
- [Z6] Nested-session protocol: <https://github.com/zellij-org/zellij/blob/v0.45.0/zellij-utils/src/nested_session.rs#L16-L19> (DCS 26661); parsing <https://github.com/zellij-org/zellij/blob/v0.45.0/zellij-server/src/panes/grid.rs#L4410-L4416>; handling <https://github.com/zellij-org/zellij/blob/v0.45.0/zellij-server/src/screen.rs#L3035-L3130>; focus move <https://github.com/zellij-org/zellij/blob/v0.45.0/zellij-server/src/tab/mod.rs#L5234-L5250>.
- [Z7] Client exit: <https://github.com/zellij-org/zellij/blob/v0.45.0/zellij-client/src/lib.rs#L930-L940> and L1399–1408; CLI action status <https://github.com/zellij-org/zellij/blob/v0.45.0/zellij-client/src/cli_client.rs#L240-L256>, <https://github.com/zellij-org/zellij/blob/v0.45.0/zellij-server/src/route.rs#L2196-L2206>.
- [Z8] License (MIT): <https://github.com/zellij-org/zellij/blob/v0.45.0/LICENSE.md>.
- [Z9] Emulator state: alternate screen <https://github.com/zellij-org/zellij/blob/v0.45.0/zellij-client/src/lib.rs#L51>; per-pane bracketed paste and kitty-keyboard flags <https://github.com/zellij-org/zellij/blob/v0.45.0/zellij-server/src/panes/grid.rs#L717> and L761.
- [D1] `directories` 6.0.0 (zellij's `Cargo.lock` pin), `ProjectDirs::runtime_dir`: <https://docs.rs/directories/6.0.0/directories/struct.ProjectDirs.html#method.runtime_dir>.
- agent-vm at `766cd51`: `crates/agent-vm/src/run.rs` (`GUEST_ALWAYS_ENV`, `RAW_FORWARDED_ENV`, TTY/non-TTY branch ~L1608, volume wiring ~L1146), `user.rs` (`core_dir_volumes`), `mount.rs` (`MountContext`, `prepare`), `session.rs`, `host_paths.rs` (`state_root`), `guest_paths.rs` (`TMPFS_GUEST_PREFIXES`), `network.rs` (egress flags), `protected_host_files.rs`; `vendor/agent-vm-images/images/Dockerfile` and `install-zellij.sh` at submodule `087f8ba`; [CONTEXT.md](../../CONTEXT.md).
- Related: [live-network-notifications research (#298)](https://github.com/gregwebs/agent-vm/blob/research/live-network-notifications/docs/research/live-network-notifications.md).
