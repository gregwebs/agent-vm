# The `pi` tool layer

Installs the pinned [Pi coding agent](https://www.npmjs.com/package/@earendil-works/pi-coding-agent)
behind an agent-vm-owned wrapper. [`../README.md`](../README.md) has the full
design: the lockfile pin, the integrity refill, the bridge packages, and cache
ordering. This file covers the one routine task: **upgrading Pi**.

## Upgrading Pi

```bash
bash images/tools/pi/upgrade-pi.sh           # pin the registry's `latest`
bash images/tools/pi/upgrade-pi.sh 0.87.1    # or an exact version
bash images/tools/pi/upgrade-pi.sh next      # or any dist-tag
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
pin and script (`bash images/tools/pi/bridge/upgrade-bridge.sh [VERSION]`).
[`../README.md`](../README.md#upgrading-a-tool) covers upgrading every tool
layer and how to run a new version before CI publishes it.
