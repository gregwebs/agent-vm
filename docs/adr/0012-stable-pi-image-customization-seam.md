# Keep a stable wrapper around image-installed Pi

The guest image installs Pi under `/opt/agent-vm/pi/`, stores repository- and image-owned Pi extensions under `/opt/agent-vm/pi-extensions/`, and exposes `/usr/local/bin/pi` as an agent-vm-owned wrapper that always loads the mandatory guest warning extension. Future agent layers may replace the Pi installation and customization layers may add image-owned extensions, but they must not replace the wrapper. This keeps Pi customizable without making the credential warning dependent on project state or a particular Pi installation layer.

## Status

Accepted. Decision for [agent-vm #95](https://github.com/gregwebs/agent-vm/issues/95). The mixed credential-ownership rationale the warning text summarises is [#94](https://github.com/gregwebs/agent-vm/issues/94).

## Decision

- **"Always loads" is an explicit `--extension` argument, not discovery.** `/usr/local/bin/pi` execs the entry point with `--extension /opt/agent-vm/pi-extensions/guest-credential-warning.js` ahead of the user's own argv. `--no-extensions` only stops *discovery*, so it cannot silence the mandatory file, and an explicit `--extension` path that is missing or throws is already fatal to Pi before session startup — the fail-closed half of the same seam.
- **A subcommand invocation is forwarded verbatim.** Pi dispatches a subcommand only as the *first* argument, so `pi list` must not become `pi --extension … list` — that would turn `list` into a prompt and run an agent turn. The wrapper's subcommand allowlist is checked against the real `pi --help` at image-build time, so a pin bump that adds or renames a subcommand fails the build instead of silently mis-dispatching.
- **The extension directory is a location convention, not an activation contract.** The wrapper loads exactly one named file (`guest-credential-warning.js`), not the directory. A customization layer that drops a second file into `/opt/agent-vm/pi-extensions/` must get it loaded itself — through a wrapper-compatible invocation or a deliberate change to this seam; adding the file alone does nothing.
- **A replacement Pi must keep the wrapper's interface.** Whatever installs `/opt/agent-vm/pi` must accept `--extension <path>` and preserve Pi's positional subcommand dispatch (`auth`, `config`, `install`, `list`, `remove`, `uninstall`, `update`). The default layer's build gate checks this against the real `pi --help`; that gate does not run on an arbitrary downstream replacement layer, so a replacement owns the compatibility.

## Consequences

- **The warning is advisory, not a boundary.** The microVM is the boundary: a guest that invokes `/opt/agent-vm/pi/node_modules/.bin/pi` directly, or overwrites `/usr/local/bin/pi` (for example with `npm install -g @earendil-works/pi-coding-agent`), gets no warning.
- **`pi update self` fails on the root-owned `/opt/agent-vm/pi`.** Correct: agent-vm owns Pi updates.
- **The wrapper is the stable seam; the installation and the extension directory are replaceable.** The replacement property is exercised by `script/test/pi-layer-runtime.sh`.
