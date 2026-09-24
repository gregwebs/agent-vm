# ADR-0023: Image-owned Pi extension packages (`pi-claude-bridge`)

## Status

Accepted. Implementation decision for
[agent-vm #164](https://github.com/gregwebs/agent-vm/issues/164). Extends
[ADR-0012](0012-stable-pi-image-customization-seam.md), whose Decision names
"a deliberate change to this seam" as the way a customization layer may add an
image-owned extension, and [ADR-0021](0021-project-scoped-pi-home-and-wrapper-parity.md),
whose parity principle governs what the wrapper may do on Pi's behalf. Reuses
[ADR-0019](0019-tool-free-base-and-per-tool-layers.md)'s `seed.d/` first-boot
hook mechanism (D4) and [ADR-0017](0017-tool-declared-provisioning.md)'s
`tools` field, which supplies the credential. Builds on **Tool layer**,
**Credential shielding** and **Credential provider** in
[CONTEXT.md](../../CONTEXT.md).

## Context

Pi reaches model providers through **extensions**. The route this ADR installs
is [`pi-claude-bridge`](https://github.com/elidickinson/pi-claude-bridge): a Pi
extension that registers a `claude-bridge/*` provider and answers requests by
spawning **Claude Code** as a child process through the Claude Agent SDK.

Three facts force the design.

**1. The bridge needs Claude Code's credential, not Pi's.** It never reads Pi's
`~/.pi/agent/auth.json`; it needs `~/.claude/.credentials.json` (or
`ANTHROPIC_API_KEY`) and a writable `~/.claude`. That is the credential
agent-vm's existing `anthropic` provider already imports: on a launch that
provisions Anthropic, the guest holds only a fixed placeholder and the microVM
proxy substitutes the host's real bytes on the three Anthropic hosts. So
`crates/agent-vm/src/default-tools.toml` now gives `pi` the `tools = ["claude"]`
edge — ADR-0017 alternative 2, "a tool that connects to another tool
(`Pi` → `claude`)", which *provisions* Anthropic without *requiring* it, so a
user with no host Claude login still gets a `pi` launch.

**2. `pi install` cannot be used at build time.** `pi install npm:<pkg>` does
three things: `ensureNpmProject($HOME/.pi/agent/npm)`, `npm install --prefix
$HOME/.pi/agent/npm --legacy-peer-deps`, and append to the `packages` array of
`$HOME/.pi/agent/settings.json`. Both destinations are under `$HOME/.pi`, which
in the guest is `/agent-vm-state/pi` — per-project **guest state** under
ADR-0021, not the image. A build-time `pi install` would write into the
builder's `/root/.pi` and be shadowed at runtime; it is also a registry fetch
inside `RUN`.

**3. Every other Pi activation mechanism is guest state too.** Checked against
Pi 0.86.1's `dist/core/package-manager.js` and `dist/core/config.js`:

| mechanism | source of truth | image-ownable? |
|---|---|---|
| `packages` array | `$HOME/.pi/agent/settings.json` / `<project>/.pi/settings.json` | ✗ guest state |
| `extensions` array | the same settings files (a separate array) | ✗ guest state |
| auto-discovery | `$HOME/.pi/agent/extensions/*.{ts,js}`, `<project>/.pi/extensions/*` | ✗ guest state (and project-trust gated) |
| `PI_CODING_AGENT_DIR` | env; relocates the **whole** agent dir | ✗ would relocate auth and sessions, breaking ADR-0021's persistence mapping |
| explicit `--extension <path>` | argv | ✅ **this one** |

## Decision

### D1 — Image-owned Pi *packages* live under `/opt/agent-vm/pi-packages/`

A real npm project root, root-owned and `a+rX`, holding the committed
`package.json` + `package-lock.json` and the tree `npm ci` installs from them.
The bridge's extension file is
`/opt/agent-vm/pi-packages/node_modules/pi-claude-bridge/src/index.ts`.

`/opt/agent-vm/pi-extensions/` keeps its ADR-0012 meaning: bare,
dependency-free `.js` files loaded by absolute path. Two directories because the
two differ in **resolution**: the mandatory warning is a single file with no
`node_modules` anywhere near it, while the bridge is a package whose imports
must be able to walk up into a real npm tree.

### D2 — Activation is an explicit wrapper `--extension`

The Pi wrapper (`images/tools/pi/pi.sh`) execs Pi with the mandatory
`--extension` and, when the bridge is present, a second one. `--extension` is
documented as repeatable (`dist/cli/args.js`, "can be used multiple times") and
parsed with no arity limit.

This is the only activation path that does not mutate a user's Pi settings: D3's
table shows every alternative bottoms out in `$HOME/.pi`, which ADR-0021 makes
per-project guest state, and agent-vm should not be rewriting a user's Pi
settings to activate a package it ships. It is also the seam ADR-0012 already
owns, so the wrapper stays the one file that decides how Pi starts.

### D3 — The bridge `--extension` is existence-checked; the mandatory one is not

Asymmetric on purpose. The mandatory warning is agent-vm's own contract and must
fail closed — an `--extension` Pi cannot load is fatal before session startup,
which is exactly the behaviour ADR-0012 relies on. The bridge is a convenience:
its absence must cost the bridge, not `pi`. So the wrapper tests `-r` before
adding the flag, and a build that soft-failed its `npm ci` (the tree is deleted)
ships an image whose `pi` still runs and still warns.

`AGENT_VM_PI_NO_BRIDGE` (any non-empty value) is the opt-out. It exists because
pinned third-party code runs in-process in every non-subcommand invocation: a
bridge that throws, or the duplicate-install case below, must be escapable
without knowing the internal entry point ADR-0012 documents as the escape hatch.

This is not a property the `--extension` route uniquely imposes. Pi fails closed
for *discovered* extensions too: `dist/main.js` turns any diagnostic whose
message includes "Failed to load extension" into `process.exit(1)`. Seeding the
`extensions` array (D2's rejected alternative) would carry exactly the same
risk, which is why it buys less than it looks like.

### D4 — The pin is a committed lockfile; the Claude Code binary is the image's own

`images/tools/pi/bridge/package.json` pins `pi-claude-bridge` to an exact
version and `package-lock.json` is committed beside it; the layer runs `npm ci`
from them, so the build resolves nothing.

Two flags are mandatory, on **both** the lock generation and the `npm ci`:

- **`--legacy-peer-deps`.** The bridge declares `@earendil-works/pi-*` and
  `typebox` as peers. Pi's extension loader builds its jiti instance with an
  **alias map** covering all of them (`dist/core/extensions/loader.js`), so they
  must not be installed. Without the flag npm solves those ranges and drags in a
  **second, version-skewed `@earendil-works/pi-coding-agent`** beside the
  image's own Pi — and the generated lock then loses npm's `integrity` on the
  five shrinkwrapped siblings Pi ships. (This is the same policy Pi's own
  installer uses, for the same reason.)
- **`--omit=optional`.** `@anthropic-ai/claude-agent-sdk` has no `dependencies`;
  it has eight `optionalDependencies`, one per platform, each carrying a whole
  native Claude Code binary (~197 MiB for the `linux-arm64` package the guest
  uses; `linux-x64` is comparable). The image already
  ships `claude` at `/opt/agent/.local/bin/claude`, so the platform package is
  dropped and `seed.d/20-pi-claude-bridge` writes
  `provider.pathToClaudeCodeExecutable` into `~/.pi/agent/claude-bridge.json`
  on first boot — its one key, merged into whatever else the file holds.

`--ignore-scripts` matches `pi` and `dsh`: no upstream lifecycle script runs
during the image build. There is deliberately **no** bespoke integrity verifier
(contrast `install-pi.sh`): that one exists only because npm ignores our lock for
Pi's shrinkwrapped subtree, and this tree has no shrinkwrap anywhere in its
chain, so `npm ci` authenticates every tarball itself. A `cargo test` guard fails
the build if a regenerated lock ever loses that property.

An absent bridge is legal in exactly one *build* case — a soft-failed `npm ci`
— and the layer's `verify-pi.sh` gate enforces precisely that: a missing tree is
a hard failure unless `AGENT_INSTALL_SOFT_FAIL` is set, and every tree that
*did* ship is asserted world-readable (C7). (At runtime a user may remove the
tree; the wrapper's existence check degrades that to "no bridge", which
`script/test/pi-layer-runtime.sh` pins.)

## Consequences

- **`pi list` does not show the bridge, and `pi update` / `pi uninstall` cannot
  move it.** It is image-owned, not a Pi-managed package. The pin moves when
  this repo moves it, like every other agent in the image. `script/test/pi-layer-runtime.sh`
  runs the bridge as a non-root uid, exercises the degradation contract with the
  tree removed, and pins `pi list`'s unchanged output.
- **Pinned third-party extension code runs in-process in every non-subcommand
  `pi` invocation**, including a bare `pi` typed into `agent-vm shell`. The
  mitigations are the exact integrity-checked pin, a build gate that runs a real
  Pi session and fails the image unless the provider registers with a non-empty
  model catalog, a non-root runtime leg, the existence check (D3), and the
  opt-out. Residual risk: a runtime-only difference CI's amd64 leg does not
  reproduce.
- **A deliberate, narrow exception to ADR-0022's "no baked-in community
  plugins" rule.** That rule's stated objection (`default-tools.toml`'s `dsh`
  rationale) is *unreviewed third-party code that holds the user's credentials*.
  The bridge introduces **no new host-credential reader**: it never parses a
  host credential file, and on the OAuth path the guest holds only the proxy
  placeholder. It is **not** true that it cannot hold a credential: it copies
  the ambient environment into the SDK child, so a guest `ANTHROPIC_API_KEY`
  passes through it, and any in-process Pi code in a guest session can read any
  guest-readable credential file. The exception is therefore "pinned,
  version-reviewed, and no new host-credential surface" — not "harmless".
- **A user-installed second copy is not fully deduplicated.** The bridge skips
  re-registering the *provider* when a second module instance sees it already in
  the model registry, but both instances still register lifecycle and compaction
  handlers, so a user who also runs `pi install npm:pi-claude-bridge` can get
  duplicated compaction work — worse if the two versions differ. The supported
  resolutions are uninstalling the user copy or setting `AGENT_VM_PI_NO_BRIDGE`.
  This case is documented, not handled.
- **The `pi` verb now provisions the Anthropic credential**, so it inherits that
  provider's launch-time side effects: the onboarding/permission bypass configs
  (`claude/settings.json`, `claude.json`) are written even when no host
  credential was captured, an in-guest `claude login` can no longer complete when
  the host *does* have one (the intercept route answers refresh grants only), and
  a successful capture **overwrites** a guest-written
  `~/.claude/.credentials.json` with the placeholder. These are ADR-0017's
  existing provider semantics, not new logic; `USAGE.md` documents them.
- **The guest `ANTHROPIC_API_KEY` publication is out of scope here.** agent-vm
  publishes a host-set `ANTHROPIC_API_KEY` into the guest as the real value, and
  Claude Code prefers it over `~/.claude/.credentials.json`, silently bypassing
  the proxy. That is a pre-existing defect on `claude` and `shell` too, tracked
  as [#165](https://github.com/gregwebs/agent-vm/issues/165); this ADR extends
  the affected surface to a third verb rather than fixing it.
- **A custom catalog can ship the bridge without `claude`.** `declared_layers`
  composes the layers the *catalog* declares, so a config that declares `pi`
  with the built-in `layer` but no `claude` tool builds an image with the
  always-loaded bridge and no image Claude Code: the seed hook no-ops (its
  `-x` guard), the bridge still registers, and every turn fails at SDK spawn
  with "Native CLI binary … not found". A custom catalog that copies the new
  built-in `pi` definition *without* `claude` fails earlier and more clearly —
  `tools = ["claude"]` is a dangling reference and resolution hard-errors naming
  the declaring file.
- **~+31 MiB on the pi layer**, not +197 MiB. The pi layer is second from the
  bottom of the chain, so a bridge pin bump rebuilds the layers above it — the
  same accepted cost as a Pi pin bump. The bridge `RUN` sits *after* the Pi
  install so the two stay independently cacheable inside the layer.

## Alternatives

- **`pi install npm:pi-claude-bridge` in the layer's `RUN`.** Rejected: writes
  only into the builder's `$HOME/.pi` (Context 2), so the guest sees nothing;
  and it is a non-hermetic registry fetch in a `RUN`.
- **Ship the SDK's platform package instead of omitting it.** Rejected: +197 MiB
  on the second-from-bottom layer of every image and two Claude Code versions in
  one guest. Omitting it plus seeding the executable path reuses exactly the
  binary `agent-vm claude` uses.
- **Seed Pi's `settings.json` `extensions` array (or the `packages` array)
  instead of a wrapper `--extension`.** Rejected: it mutates a user's Pi
  settings to activate something agent-vm ships (a parity-principle smell
  ADR-0021 is careful about), needs a per-project seeded-once marker because
  "user removes it, next launch re-adds it" is otherwise a loop, and — D3 — buys
  no fail-open property, because a settings-listed extension that fails to load
  is fatal too.
- **Point `PI_CODING_AGENT_DIR` at an image-owned agent directory.** Rejected:
  it relocates auth, models and sessions as well, which is exactly the
  persistence ADR-0021 establishes. The variable cannot move the package tree
  alone.
- **Do not bake the bridge in; document `pi install` as the user's step.**
  Rejected: that is the status quo this ticket exists to replace, and it leaves
  the bridge's `pathToClaudeCodeExecutable` to the user (the SDK would otherwise
  throw "Native CLI binary … not found" against this image).
- **Bake in a *different* Anthropic route for Pi (native Pi auth).** Not an
  alternative this ADR weighs: the native route was the parked issue #94, since
  withdrawn as superseded by #164. It targets Pi's own `auth.json`, a
  different credential from the one the bridge needs, so it would not have
  removed the bridge's guest-login requirement.
