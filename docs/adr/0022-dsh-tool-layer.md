# ADR-0022: The DeepSeek Harness (`dsh`) tool layer

## Status

Accepted. Implementation decision for [agent-vm #149](https://github.com/gregwebs/agent-vm/issues/149).
Extends [ADR-0003](0003-project-tooling-layers.md) (layer chains and the layer
image contract) and [ADR-0019](0019-tool-free-base-and-per-tool-layers.md)
(the tool-free base plus per-tool layers). Follows
[ADR-0021](0021-project-scoped-pi-home-and-wrapper-parity.md) for the
"credential-free multi-provider agent" shape.

## Context

DeepSeek Harness ships one CLI, `dsh`, whose entry modes are profiles rather
than flags: `dsh web` (a browser UI, the alias the issue names), plus
`headless`, `acp`, `sdk` and a plugin manager, `dsh plugin --profile … add …`,
which forwards to pnpm. All user state — profiles, sessions, and the
`~/.dsh/.credentials.yaml` document — lives under `$DSH_HOME`, `~/.dsh` by
default.

Two facts force design choices the other agent layers did not face:

- **`npm install -g @deepseek-ai/dsh` is not a reliable install.** The app at
  the `latest` dist-tag (0.1.5-rc.2) depends on `@deepseek-ai/dsh-base` through
  a caret range that resolves to 0.1.5-rc.3, and npm may then nest
  `dsh-sandbox-local` under `dsh-base/node_modules`. dsh's plugin loader cannot
  resolve that package from the app root, so `dsh web` aborts at boot. The
  working layout (the package under the app's own `node_modules`) is not
  guaranteed by a floating install.
- **`dsh` exits 0 with no output on an old Node.** It dispatches on
  `import.meta.main`, undefined below Node 22.19, so an exit-code-only
  `--version` check — and `agent-vm setup`'s probe — accepts a completely
  non-functional binary.

## Decision

### 1. `dsh` is a shipped tool layer with argv `web` and `persist = [".dsh"]`

`crates/agent-vm/src/default-tools.toml` declares
`command = "dsh"`, `args = ["web"]`, `layer = { builtin = "dsh" }`,
`persist = [".dsh"]`. The guest reaches the web UI through the launcher's
existing `--publish` / `--auto-publish` inbound-port flags. Persisting the
whole home is what keeps a Models-UI API key across launches.

The layer is the chain's **first** step. Like `pi`, a committed lockfile makes
it large (~324 MiB installed tree, a ~360 MiB image layer) and rare to change;
the bottom is where the layer-ordering policy (ADR-0019, `images/tools/README.md`)
puts such a layer so it is not re-emitted on every codex/claude release above it.

### 2. Installed from a committed lockfile, not a floating installer

`images/tools/dsh/` commits a `package.json` + `package-lock.json` and runs
`npm ci --ignore-scripts` into `/opt/agent-vm/dsh`, linking `dsh` and the
lock-pinned `pnpm` onto `PATH`. The lock freezes the working dependency layout
*and* every transitive integrity hash. `verify-dsh.sh` asserts the binary's
`--version` equals the manifest pin and is non-empty, so the Node-22.19 trap is
a hard build failure rather than a silently broken agent. `--ignore-scripts`
matches `pi`: none of the five packages here that declare an install script
compiles anything for the Linux guest (node-pty and koffi ship prebuilds;
protobufjs writes a version file; `@google/genai`'s preinstall is a no-op;
`dsh-subprocess-local`'s postinstall only chmods node-pty's macOS helper), so
skipping them avoids running ~588 transitive packages' lifecycle code as root. This is deliberately not soft-failable — a partial
`node_modules` or an empty `--version` is a broken agent, not a missing one.

### 3. No credential provider; providers are configured in the guest

`dsh` declares no `credentials` and gains no `ProviderSpec`, for the same
reason as `pi`: it is a multi-provider harness that must start with none
configured and must not inherit a provider's pre-boot hard bail. Anthropic and
OpenAI support needs no plugin — `@deepseek-ai/dsh-base` already mounts the
`llm-pi-ai` multi-provider adapter dormant, so a user stores an API key
(`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `DEEPSEEK_API_KEY`, …) in
`~/.dsh/.credentials.yaml` or the environment and enables the provider in the
Models UI. Reusing agent-vm's captured OAuth subscriptions inside dsh would
require a reviewed adapter that reads the guest placeholder files; that is
follow-up work, not part of #149.

Community OAuth/subscription plugins are deliberately **not** baked in. They
are unreviewed third-party code that would hold the user's credentials in a
shipped image. `pnpm` is installed so a user who wants one can add it in the
guest with `dsh plugin`.

## Consequences

- The published default image grows by one ~360 MiB layer at its base. Every
  layer above it rebuilds when the dsh pin moves; a dsh bump is an explicit PR,
  not an hourly lookup, so that is bounded.
- A new agent joins the shipped catalog: `shell`'s wildcard now also provisions
  the `~/.dsh` persist link, and every count/order assertion and doc naming the
  shipped tools moves from six to seven.
- Subscribing dsh to agent-vm's host OAuth credentials is follow-up work.
