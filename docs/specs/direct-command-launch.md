# Direct command launches

Status: partially implemented. #398 (`run` / top-level `--`, literal Unicode
argv without catalog selection or provisioning, and the 127/126/125 status
distinctions) landed in 0.7.3. The streamed-input implementation for #399
(stdin and EOF for a non-terminal launch) is included here; accepting it
requires the native checks below. Terminal policy (#400) and signals (#401)
remain separate and pending, so the sections below describe the whole
four-slice feature and are not all delivered yet.

## Purpose

Run an arbitrary guest executable without declaring a catalog tool or invoking
its shell-tool wrapper. Keep ordinary launch setup and sandbox protections.
Existing `shell` behavior is unchanged.

```sh
agent-vm [launch options] run PROGRAM [ARG…]
agent-vm [launch options] -- PROGRAM [ARG…]
```

These forms are equivalent. Neither looks up `PROGRAM` in the launch catalog.
For example, `agent-vm claude` selects the catalog tool; `agent-vm run claude`
executes the guest executable without that tool's defaults or provisioning.

```text
launch options → run / top-level -- → executable + argv
                         ↓
             shared guest setup + project hook
                         ↓
                   exec executable
```

## Command contract

- Launch options precede `run` or the top-level separator. Tokens after `run`
  are the command vector, including `--help` and literal `--`; there is no
  second separator consumed after `run`. Use `agent-vm help run` for runner help.
- Only the top-level `--` is consumed. Later `--` tokens are preserved.
- An absent or empty executable is a usage error before VM boot. Empty
  arguments after the executable are valid and preserved.
- Preserve accepted executable and argument strings exactly: no shell
  expansion, splitting, globbing, argument deduplication or catalog defaults.
  Support Unicode argv; clearly reject non-UTF-8 rather than replacing bytes.
- Resolve bare executable names through the guest's effective `PATH` after
  setup and hook exports. Paths name guest executables, never host commands.
- Shell syntax requires an explicit shell:

  ```sh
  agent-vm run printf '%s\n' '$HOME'          # prints literal $HOME
  agent-vm -- bash -c 'printf "%s\n" "$HOME"'
  ```

“Direct” does not mean Bash-free bootstrapping. Retain the shared guest setup
and optional project-root `.agent-vm.runtime.sh`, then exec the supplied
program. Hook failures abort the launch. Setup and hooks see EOF for
non-terminal input; reserve that input for the command. Interactive hooks
retain terminal input.

## Launch configuration and authority

- Reuse ordinary image selection, project working directory, guest identity,
  mounts, persistent HOME/state, networking and GitHub handling.
- Do not inherit a catalog tool's command, default arguments, environment,
  network requests, credential requests or provider/tool-state provisioning.
  Matching an executable name to a tool name grants nothing.
- No tool-provider provisioning by default. This is not a fresh or
  credential-free environment: existing guest-managed credentials and shared
  project state remain subject to ordinary launch behavior; GitHub handling
  remains independent of tool-provider provisioning.
- Invalid launch configuration blocks the launch, including errors in unused
  tool definitions. Do not bypass catalog validation for direct commands.
- Reserve `run` as a built-in name. Reject custom tool declarations using it
  with a diagnostic explaining that the tool must be renamed.

## Input and terminal behavior

Automatically select a PTY only when both host stdin and stdout are terminals.
Otherwise use streaming I/O, forwarding stdin and EOF and keeping guest stdout
and stderr separate. Launcher diagnostics must not contaminate guest stdout.

Direct launches accept these mutually exclusive launch options:

| Option | Behavior |
| --- | --- |
| `--tty`, `-t` | Force a PTY; reject non-terminal stdin before boot. |
| `--no-tty`, `-T` | Force streaming I/O, even from a terminal. |

These options precede `run` or top-level `--`. They do not change existing
`shell` behavior. PTY output has ordinary terminal semantics rather than
separate stdout/stderr streams. Forward terminal resizing. Ctrl-] is guest
input, not a detach escape. Direct launches have no background/detach mode.

Stdin forwarding must not delay observing command exit or hang when the guest
closes stdin early. Host EOF closes guest stdin.

## Lifetime and exit status

While the guest command runs, forward host SIGINT/SIGTERM to it. Allow five
seconds for exit before forced teardown; a second interrupt forces teardown
immediately. Tear down the launch's VM when the command ends or shutdown is
forced. The grace period is fixed in this feature.

| Outcome | Launcher exit status |
| --- | --- |
| Guest exits normally | Guest status, including nonzero statuses. |
| Executable missing | 127 |
| Executable exists but is not executable | 126 |
| Signal termination or forced shutdown following a signal | 128 + signal number |
| Launcher, transport or cleanup failure | 125 |

If a forwarded signal is handled and the guest exits normally within the grace
period, preserve that exit status. Cleanup failure takes precedence over an
otherwise available guest status. Do not treat stream loss as successful
command completion. These conventions apply to direct launches; leave existing
`shell` status behavior unchanged.

## Acceptance checks

- Both forms produce equivalent executable, argv and launch behavior.
- A same-named catalog tool cannot alter direct execution or provisioning.
- Preserve empty arguments, spaces, quotes, Unicode, shell metacharacters,
  `--help` and subsequent `--` tokens. Reject non-UTF-8 clearly.
- Missing/empty programs, conflicting terminal flags, forced PTY with
  non-terminal stdin, invalid configuration and reserved-name declarations
  fail before boot with useful diagnostics.
- `printf hello | agent-vm run cat` outputs exactly `hello` and terminates on
  EOF. A hook attempting to read does not consume command input.
- Large/binary stdin streams and a guest that exits without reading do not
  deadlock. Stream mode keeps stdout and stderr distinct.
- Verify automatic PTY selection, both overrides, resizing and Ctrl-]
  passthrough with a real terminal.
- Verify hook exports and failure propagation, post-hook executable lookup,
  missing/non-executable status distinctions, guest exit propagation, signal
  handling, grace expiry, repeated interrupts and VM cleanup.
- Verify no automatic tool-provider capture, injection or tool-specific state
  provisioning, while ordinary project state and GitHub handling remain.
- Existing shell and catalog-tool launch behavior remains unchanged.

## References

- [Domain vocabulary](../../CONTEXT.md#direct-command)
- [Launch option boundary](../adr/0042-launch-options-before-the-tool-verb.md)
- [Provider provisioning](../adr/0017-tool-declared-provisioning.md)
- [Boot image ownership and contract](../adr/0035-consume-user-owned-boot-images.md)

Implementation planning must identify any required runtime changes and add
native evidence for stream/PTY/signal behavior; parser tests alone do not
establish those properties.
