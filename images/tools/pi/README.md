# The `pi` tool layer

Installs the pinned [Pi coding agent](https://www.npmjs.com/package/@earendil-works/pi-coding-agent)
behind an agent-vm-owned wrapper. [`../README.md`](../README.md) has the full
design: the lockfile pin, the integrity refill, the bridge packages, and cache
ordering. This file covers the one routine task: **upgrading Pi**.

## Upgrading Pi

```bash
bash images/tools/pi/upgrade-pi.sh           # pin the registry's `latest`
bash images/tools/pi/upgrade-pi.sh 0.87.1    # or an exact version
```

The script requires `jq` and `npm` on the host. Run it with `bash`, because it
is committed without the execute bit like every file under `images/tools/`. It
then:

1. writes the exact version into `package.json`, the pin
   `verify-pi.sh` checks `pi --version` against;
2. regenerates `package-lock.json` from scratch
   (`npm install --ignore-scripts --package-lock-only`);
3. refills the `integrity` hashes of the five `@earendil-works` siblings
   (`chord`, `pi-agent-core`, `pi-ai`, `pi-telemetry`, `pi-tui`) from the
   registry's `dist.integrity`. npm leaves these out because Pi's published
   shrinkwrap omits them, and `install-pi.sh` checks them at build time;
4. runs the same checks as the `cargo test` guards before writing anything.
   If they fail, the working tree is left untouched.

Running it on the current version is a no-op, which makes it a quick way to
check that the committed lock is still reproducible.

If the script reports an entry with no integrity that is **not** one of those
five, Pi's dependency layout has changed. `install-pi.sh`'s sibling verifier and
the `tool_layer.rs` guards need to be reviewed before the bump can land.

Afterwards:

```bash
cargo test -p agent-vm tool_layer
git diff images/tools/pi/package.json images/tools/pi/package-lock.json
```

This bumps only Pi. The `pi-claude-bridge` extension in `bridge/` has its own
pin and flow; see [`../README.md`](../README.md#the-bridge-packages-imagestoolspibridge).

## Using the new version

A launch with the default tool set boots the published template as-is, so a
local pin bump has no effect until you build the layers yourself. Use one of
these options:

- **Compose locally with the launcher.** The `agent-vm` binary embeds
  `images/tools/` at compile time, so rebuild it first (e.g.
  `./script/build/macos.sh`). Then force local composition:

  ```bash
  agent-vm shell --base-image ghcr.io/wirenboard/agent-vm-base:latest -- bash -c 'pi --version'
  ```

  This rebuilds `pi` and every layer stacked above it (codex, opencode, claude,
  copilot). The result is hash-cached for later launches.

- **Build the template with Docker** and boot it with `--image`. No binary
  rebuild is needed. See
  [macos-build.md](../../../macos-build.md#composing-from-a-local-tool-free-base---base-image),
  or `images/build.sh` behind a TLS-intercept proxy.

Use `bash -c`, not `bash -lc`, for in-guest commands: a login shell resets
`PATH` and hides the agent CLIs.

Once the bump is merged, CI rebuilds the published template and a default
launch picks it up with no local build.
