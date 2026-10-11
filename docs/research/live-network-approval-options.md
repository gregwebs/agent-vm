# Live network approvals: experience options compared

Date: 2026-10-11. For [Choose the notification and approval experience](https://github.com/gregwebs/agent-vm/issues/297) in [Explore live network approvals](https://github.com/gregwebs/agent-vm/issues/296). This records every option examined and why one was picked to try first. It is not an implementation spec.

Inputs:
- the clickable sketches in [`docs/prototypes/live-network-approvals-prototype.html`](../prototypes/live-network-approvals-prototype.html) (variants A–D across four scenarios);
- [notification research](https://github.com/gregwebs/agent-vm/blob/6712d31f33d974e3e237ab74a20e5ccac5c4b79b/docs/research/live-network-notifications.md);
- [zellij research](https://github.com/gregwebs/agent-vm/blob/fabc60c/docs/research/zellij-approval-surfaces.md);
- source inspection of the launcher's terminal attach (`crates/agent-vm/src/run.rs`, SDK `attach_with`).

Platform claims below are documentation or memory, not exercised behavior, unless stated.

## Fixed rules for every option

- A denied request has already failed. Approval never replays it; the app or user retries.
- Only host-controlled authority changes policy. Anything drawn by the guest, or reachable by it, can at most *display* a block.
- **Showing a block** and **acting on a block** are separate. This effort tries showing first. Acting gets its own agent-vm CLI experience.
- All sandbox blocks are shown, including ones no approval can lift: administrator/platform restrictions and credential or GitHub repository refusals. These are labelled as such and never presented as approvable.

## Decision: try A first

Start with the simplest version of the most promising path: **a host OS notification that can open a host terminal**. Then use it and judge the experience before adding anything else.

## Options

### A. Host OS notification → open a host terminal *(chosen to try first)*

The host sends a desktop notification for each block, grouped per project and session. Clicking it opens a host terminal showing the session's blocks. The click only navigates; it never authorizes.

- **Pros**
  - Entirely host-side, so nothing the guest does can trigger approval.
  - Doesn't touch the attached terminal's input or output.
  - No guest or image changes; small trusted surface.
- **Cons**
  - Opening a *new terminal* from a click varies by platform. Linux has no standard way to launch the default terminal (the `xdg-terminal-exec` proposal isn't final), and on macOS a precise "open this command in a fresh window" needs testing.
  - macOS actionable notifications probably need an app/helper identity.
  - No signal over SSH or on a headless host.
  - Needs grouping so retry floods don't spam.

### B. Guest hint relayed by the agent

The guest learns a denial ID and is told the host command to run; the coding agent passes it on to the human.

- **Pros**
  - Works the same on desktop, SSH and headless.
  - Discovery happens where the failure is noticed.
  - No notification packaging.
- **Cons**
  - Needs a new host→guest denial channel; today a block is just NXDOMAIN or a dropped connection.
  - Depends on the agent noticing and relaying correctly.
  - Background blocks stay invisible.
- **Status:** telling the guest is acceptable when it improves the experience. A natural form is **plugins or hooks for common harnesses** (Claude Code, codex, …) that display blocks inside the agent's UI. That needs research.

### C. Host approvals console (`watch`)

A long-running host console lists every running session's blocks and takes decisions.

- **Pros**
  - One trusted place for discovery, decisions, inspection and revocation.
  - Maps directly onto a future GUI.
  - Good over SSH.
- **Cons**
  - Needs a live, cross-session denial event stream from the runtime.
  - Only useful if it's kept open.
- **Status:** feeds the separate CLI experience for acting on blocks.

### D. Native helper app with a confirmation dialog

An installed helper posts the notification, and its action opens a native dialog the helper owns.

- **Pros**
  - Most familiar experience, with rich, trustworthy context.
  - Closest to the future GUI.
- **Cons**
  - Heaviest packaging: a signed macOS bundle, Linux `.desktop` file and D-Bus activation, none validated.
  - Still needs a CLI fallback for headless use.
- **Status:** deferred to the GUI effort.

### E. Terminal notification sequence (OSC 9 / 777 / 99)

The launcher writes a notification escape sequence into the terminal stream, and the user's terminal shows a desktop banner.

- **Pros**
  - Works over SSH, reaching the user's *local* desktop.
  - No OS notification API or packaging needed.
- **Cons**
  - Support varies by terminal; macOS Terminal.app likely lacks it.
  - tmux and screen drop it without passthrough.
  - No action buttons.
  - The guest can send the same sequence, so banners can be faked unless the launcher filters guest output.
  - Writing it alongside the SDK's `attach` can corrupt the guest's escape sequences.
  - Terminal support is from memory and needs verification.
- **Status:** strong candidate for the SSH/headless gap that A leaves.

### F. Launcher-owned in-terminal prompt

The launcher replaces the SDK `attach` with its own terminal connection loop (`exec_stream_with(..).tty(true).stdin_pipe()`). A hotkey pauses guest output and shows a host-drawn prompt.

- **Pros**
  - Trusted, and works over SSH.
  - The guest can't draw over the prompt while it's open.
  - No new dependency.
  - Also enables filtering for E.
- **Cons**
  - We'd own raw mode, resize, signals, detach and exit codes.
  - Taking keyboard input, even only on a hotkey, partially reverses the "don't steal attached input" note.
  - Auto-pausing on each block would freeze unattended agents.
  - The redraw after the prompt relies on a resize trick.
  - Terminal replies arrive on the input stream and must not be read as the hotkey.
- **Status:** later option, opened by hotkey only, never automatically.

### G. zellij inside the guest

zellij wraps the tool in the guest and shows a non-focusing bar about blocks.

- **Pros**
  - Already in the standard images.
  - Can show a bar without taking focus.
- **Cons**
  - Guest-controlled, so display only; spoofable or suppressible.
  - Still needs the host→guest denial channel from B.
  - Costs: keybinding conflicts unless locked mode clears all bindings, it takes over scrollback and the mouse, and the clipboard and exit codes need workarounds.
  - Not required by the image contract.
  - A guest terminal notification (E) gives the same trust for less.
- **Status:** not pursued.

### H. zellij on the host, wrapping the launch

zellij runs on the host with the launch in its main pane; a host pane shows blocks or the approval prompt.

- **Pros**
  - Trusted panes, works over SSH.
  - The pane's socket and config are not mounted into the guest by default.
- **Cons**
  - Per source reading (untested), zellij 0.45.0 lets any pane's output move the user's focus with a nested-session escape sequence, so guest output could steer keystrokes into an approval pane. No setting disables it.
  - The guest can still fake an approval UI within its own pane.
  - Launching from `~` or a covering `--mount` exposes zellij's config and plugin permissions.
  - New host dependency, nesting problems for tmux/zellij users, and exit code and detach handling.
- **Status:** not pursued; F gives a trusted in-terminal surface without these risks.

## Follow-ups from this decision

- Try A on macOS and Linux and judge the experience. This includes the grouping rule and what the opened terminal shows.
- Design the agent-vm CLI experience for acting on blocks: listing, session/project allowance, the stale-session rule and revocation.
- Research displaying blocks inside the agent via harness plugins (B).
- Revisit E (and F) for the SSH/headless gap once A has been tried.
