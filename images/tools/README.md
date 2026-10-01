# Tool layers

One standalone tooling layer per shipped agent CLI. Each directory holds a
`Dockerfile` that builds `FROM` the tool-free base
(`ghcr.io/wirenboard/agent-vm-base:latest`, produced by `images/Dockerfile`)
and installs **one exact, audited** selection of that agent, together with its
own copy of the small recipe/install contract. The directories are embedded
into the `agent-vm` binary at compile time
(`crates/agent-vm/src/tool_layer.rs`) so a launch whose configured tool set
differs from the shipped default can compose them locally without a repo
checkout.

## The layer image contract

The **normative** contract for tool images is
[ADR-0031](../../docs/adr/0031-tool-image-contract.md) (the T/S clauses). It
replaced ADR-0003's retired C1–C8 table. The legacy C1–C4 chain checks still run
on the ordered-build path in `crates/agent-vm/src/layer/contract.rs` (C5–C8 are
documented-only there); treat that as the historical implementation, not the
tool-image contract. The only tool-layer-specific legacy rule worth stating:
**C2 is satisfied by writing prefixes as `ENV PATH=<new>:${PATH}`**, so a layer
can never remove a directory the base put there.

## Inherited from the base — do not duplicate

A tool layer builds `FROM` `images/Dockerfile` and therefore inherits:

- the **host-CA shim**: the build-time CA (when `images/build.sh` detects a
  TLS-intercept proxy) is baked into the base rootfs, so every layer inherits
  host trust with no extra build arg. Do **not** thread `CA_SHIM_CACHEBUST`
  into a tool layer's Dockerfile.
- the **`/opt/agent` prefix** (`RUN mkdir -p /opt/agent && chmod 755 /opt/agent`)
  and the empty `/opt/agent-vm/seed.d/` hook directory.

The base still ships the legacy `/usr/local/bin/agent-vm-install` helper for
compatibility, but **no shipped recipe calls it**: its blanket soft-fail policy
is not this contract. Instead each recipe carries its own copy of the shared
mechanics under `images/tools/<tool>/contract/` (`run-install.sh`,
`download.sh`, `run-npm.sh`, `run-report.sh`, `check-tool-access.py`). The
canonical sources live in `images/recipe-contract/` and every copy is
byte-identical; edit the canonical file, run
`bash script/build/sync-recipe-contracts.sh --write`, and commit the copies.
`script/build/sync-recipe-contracts.sh --check` (run by ci-contracts) fails on
drift. The contract files are **bind-mounted** into a recipe's `RUN`
(`--mount=type=bind,…`), never `COPY`ed, so no helper becomes a shipped entry
point and the base gains no new prerequisite.

## Exact versions, explicit slots, soft-fail and status records

Every shipped recipe selects an **exact** version. There is no build-time
`latest`/dist-tag/channel lookup anywhere: an ordinary or release build consumes
the committed value, and an override must use the same exact spelling (a
floating/range/tag/URL value is rejected before any network call).

| Recipe | label suffix → build ARG | accepted spelling |
|---|---|---|
| `codex` | `codex` → `AGENT_VERSION_CODEX` | `rust-v<semver>` |
| `opencode` | `opencode` → `AGENT_VERSION_OPENCODE` | `v<semver>` |
| `claude` | `claude` → `AGENT_VERSION_CLAUDE` | `<semver>` |
| `copilot` | `copilot` → `AGENT_VERSION_COPILOT` | `<semver>` |
| `dsh` | `dsh` → `AGENT_VERSION_DSH` | `<semver>` |
| `dsh` | `pnpm` → `AGENT_VERSION_PNPM` | `<semver>` |
| `pi` | `pi` → `AGENT_VERSION_PI` | `<semver>` |
| `pi` | `pi-claude-bridge` → `AGENT_VERSION_PI_CLAUDE_BRIDGE` | `<semver>` |

The four single-slot recipes (`codex`, `opencode`, `claude`, `copilot`) commit
the exact default as the `ARG` value and label it. The two lockfile recipes
(`dsh`, `pi`) leave both `ARG`s **empty** so an omitted/empty slot reuses the
committed `package.json` + `package-lock.json` byte-for-byte with no registry
lookup; their `LABEL`s carry literal fallback mirrors of the committed pins
(Docker cannot run `jq` inside a `LABEL` and an empty `ARG` cannot expand to the
pin). `cargo test -p agent-vm --bin agent-vm tool_layer` fails if a fallback
lags its manifest.

**The labels are selection, not health.** `org.agent-vm.version.<suffix>`
records what the layer was asked to install; whether the command actually works
is the T5 audit's decision. To reuse them, read every
`org.agent-vm.version.*` label (`docker image inspect`) and pass the values back
as explicit ARGs — `script/test/shipped-tool-recipes.sh` replays a default/mixed
image's labels onto a second tool-free base and requires identical normalized
reports, labels and statuses plus the preserved base labels.

**Failure classification (installation time).** A recipe install hook runs
through `contract/run-install.sh NAME RESULT_FILE INTERPRETER SCRIPT [ARG …]`,
which reserves exit 75 plus a matching fresh transport receipt for a positively
classified transport failure (`download.sh` allowlists the curl transport codes,
`run-npm.sh` allowlists the npm `error.code`s). Only the owning hook may soften
that: with a nonempty `AGENT_INSTALL_SOFT_FAIL` it deletes the recipe's own
partial artifacts, writes `absent-transport CODE` to
`/opt/agent-vm/install-status/NAME`, and exits 0. A soft input never accepts
anything else — a checksum mismatch, `EINTEGRITY`, an unknown installer or npm
failure and a post-install nonzero are always **hard**, even with soft input.
`dsh` and `copilot` are never soft-failable: a partial tree is a broken agent,
not a missing one.

On success the owning `verify-<tool>.sh` gate runs a bounded, status-checked
version report, requires the exact expected format, audits T5
(`check-tool-access.py`), and only then writes `installed` to
`/opt/agent-vm/install-status/NAME`. `pi` writes both `pi` and
`pi-claude-bridge`; a bridge-only transport degradation leaves a working `pi`
`installed` and the bridge `absent-transport CODE` (never `installed`), and an
external audit rejects that state. External certification requires `installed`
for every requested slot plus the reports/T5 — a record alone is never proof.

## Declaration and cache ordering

The declaration order — and therefore the chain order, the order
`agent-vm doctor` lists the verbs in, and CI's build order — is
`dsh, pi, codex, opencode, claude, copilot`, matching
`crates/agent-vm/src/default-tools.toml`. That file is the single source of
truth: `config::shipped_tool_layers()` derives the launcher's order from it,
and `tool_layer::tests::tool_order_matches_the_ci_and_build_script_literals`
asserts both this directory's build order (`images/build.sh`) and CI's
(`.github/workflows/build-image.yml`) agree with it — including the chain
*edges*, so a step left building `FROM` the base digest instead of its
predecessor's cannot slip through.

The order is deliberate and is **not** by size. A change to any layer forces
every layer stacked above it to rebuild, so the **topmost** layer is re-emitted
on essentially every build that changes anything, while the **bottom** layer is
re-emitted only when it itself bumps. The agent that is both largest and least
frequently changed belongs at the bottom:

- `dsh` ~324 MiB (`node_modules`), only when this repo bumps the pin → bottom (first)
- `pi` ~150 MiB (`node_modules`), only when this repo bumps the pin → next
- `codex` ~95 MiB, multiple stable cuts/day → next
- `opencode` ~50 MiB, several per week → middle
- `claude` ~68 MiB, ~daily → middle
- `copilot` installed via npm from its committed exact version → top (last)

`dsh` and `pi` are the two "large and rarely changing" layers, and they sit
below every installer layer for the same reason: a **committed lockfile** is
their only input, so each is re-emitted only when its pin moves — never on the
daily claude/codex churn above it. `dsh` is the larger of the two (~324 MiB vs
~150 MiB) and so goes first; each pin bump rebuilds the layers above it, which
is the accepted cost of keeping ~324 MiB out of every unrelated rebuild.
Ordinary and release builds consume the committed exact defaults; they never
resolve an upstream version and never pass an empty `AGENT_VERSION_*` that would
erase a default. `script/build/agent-versions.sh --write` is the explicit
developer tool that bumps the four installer defaults (see *Upgrading a tool*).
The lockfile layers additionally key on their committed lockfile content.

## Upgrading a tool

How you upgrade depends on whether the layer pins a version in this repo:

| Layer | Version source | Upgrade |
|---|---|---|
| `pi` | committed lockfile | `bash images/tools/pi/upgrade-pi.sh [VERSION]` — see [`pi/README.md`](pi/README.md) |
| `pi-claude-bridge` (in `pi`) | committed lockfile | `bash images/tools/pi/bridge/upgrade-bridge.sh [VERSION]` |
| `dsh` (+ its `pnpm`) | committed lockfile | `bash images/tools/dsh/upgrade-dsh.sh [VERSION] [--pnpm VERSION]` |
| `codex`, `opencode`, `claude`, `copilot` | committed exact `ARG` | `bash script/build/agent-versions.sh --write`, then review the Dockerfile diff |

Each lockfile script defaults to the package's npm `latest` as the *developer
convenience* and accepts any `VERSION` that is an exact version or a dist-tag
(`latest`, `next`, …), which is resolved to an exact pin at the host seam. It
runs `npm` with `--ignore-scripts` in a scratch directory and checks the same
invariants as the `cargo test -p agent-vm tool_layer` guards, plus its layer's
own constraints (listed below). It writes `package.json`, `package-lock.json`
**and the owning `Dockerfile`'s literal `LABEL` fallback** only if every check
passes. Build mode never runs these scripts and never resolves a tag:
`prepare-lock.sh` only accepts exact slots. Run the scripts with `bash`: like
every file here they are committed without the execute bit. The Dockerfiles
never copy them, so they never reach an image. Afterwards, run
`cargo test -p agent-vm tool_layer` and review the diff.

- `pi` regenerates its lock from scratch, which is safe because Pi's shrinkwrap
  fixes every transitive version. It also refills the five sibling hashes
  described in *Bumping the `pi` pin*.
- `dsh` and the bridge update their locks **incrementally** from the committed
  one. Neither tree has a shrinkwrap, so a fresh resolve would move hundreds of
  unrelated transitive pins. The dsh script rejects a lock that nests
  `dsh-sandbox-local` under `dsh-base/node_modules`. The bridge script passes
  `--legacy-peer-deps` and rejects any package Pi's loader aliases.

Two pre-merge build gates cover the recipes: `.github/workflows/pi-layer.yml`
runs the deep pi runtime matrix, and `.github/workflows/shipped-tool-recipes.yml`
builds each recipe independently from the committed tool-free base, audits it as
a numeric uid, and replays its labels. `build-image.yml` runs **only after
merge**. Any recipe can also be built by hand:

```bash
docker buildx build --load --build-arg BASE_IMAGE=<a base image> images/tools/<tool>
```

### Picking up a new version

A default launch boots the published template as-is; a source build uses the
committed defaults. There is **no automatic upstream refresh**: a bumped
installer pin is an explicit, reviewed commit
(`script/build/agent-versions.sh --write` for codex/opencode/claude/copilot, the
lockfile upgrade scripts for dsh/pi), and CI no longer resolves a tool
`latest` — the hourly image cron rebuilds the committed sources only.

To run a bumped version before the template is rebuilt:

- **`images/build.sh`** builds the chain from the committed defaults (and the
  `BASE_IMAGE` it is given); it passes no `AGENT_VERSION_*`, so a version change
  must already be committed.
- **The manual Docker loop** in
  [macos-build.md](../../macos-build.md#composing-from-a-local-tool-free-base---base-image)
  builds from the committed defaults the same way.
- **The launcher's local compose** (`--base-image`, or a non-default tool set)
  embeds `images/tools/` at compile time, so a pin bump needs a rebuilt
  `agent-vm` binary. It passes no `AGENT_VERSION_*`, so installer agents stay
  frozen at their committed defaults
  ([ADR-0019](../../docs/adr/0019-tool-free-base-and-per-tool-layers.md) D8).
  Force composition from the published base and check a pinned agent:

  ```bash
  agent-vm shell --base-image ghcr.io/wirenboard/agent-vm-base:latest -- bash -c 'pi --version'
  ```

  Use `bash -c`, not `bash -lc`: a login shell resets `PATH` and hides the
  agent CLIs. The launcher's layer hash covers **every** file in the layer
  directory, so any edit here — including these upgrade scripts and READMEs —
  forces a rebuild of that layer and every layer above it the next time a
  local-compose user launches. CI is unaffected: BuildKit hashes only the files
  the Dockerfile references.

  A soft-degraded image is **not** proof a tool works: an `absent-transport`
  slot ships no command, so the external audit rejects the image.

## The pinned lockfile layers: `dsh` and `pi`

The four installer layers install an exact committed `ARG`; `dsh` and `pi`
install from a **committed** `package.json` + `package-lock.json`
(each beside its Dockerfile) and run `npm ci`, which by construction resolves
nothing. The build then asserts `dsh --version` / `pi --version` equals the pin,
so there is no moving-version lookup for either. An explicit
`AGENT_VERSION_DSH`/`AGENT_VERSION_PNPM` (or Pi/bridge) selects a different
exact version for that slot and prepares a build-local lock; the committed
lockers stay authoritative for empty/equal slots. `pi` additionally fronts the
install with an agent-vm-owned wrapper at `/usr/local/bin/pi` and a mandatory
warning extension — see
[ADR-0012](../../docs/adr/0012-stable-pi-image-customization-seam.md); `dsh`
needs no wrapper because its bin is linked straight onto `PATH`.

**Explicit slots and the location freeze.** A nonempty `AGENT_VERSION_DSH` /
`AGENT_VERSION_PNPM` (or `AGENT_VERSION_PI` / `AGENT_VERSION_PI_CLAUDE_BRIDGE`)
that differs from the committed pin is a *build-local* override. For `dsh`,
`prepare-lock.sh` rewrites only that slot's `dependencies` entry and
`check-lock-update.js` (`dsh` only) then freezes the rest — every lock record
outside the changed root's `node_modules/` prefix (including shared/hoisted
records) must be recursively identical, so an incompatible pair is rejected with
the moved paths rather than silently refreshing the empty slot. A changed Pi or
bridge project is instead regenerated from its exact manifest and re-validated
(pin/integrity/sibling and loader-alias invariants, with the five
shrinkwrap-only Pi sibling hashes refilled from the registry); it has no
location-freeze comparator. An omitted/empty or equal slot
reuses the committed bytes exactly (no npm call). A changed root may re-resolve
new exact transitives, so an override lock is exact for the *root* but is not
registry-independent byte-for-byte reproducible; committing a reviewed bump lock
is the reproducible default. Pi and the bridge are **separate** npm projects, so
bumping one never touches the other's lock.

For `dsh`, the lock is not merely reproducibility. `npm install -g
@deepseek-ai/dsh` resolves the app at whatever `latest` points to (at the time
of pinning, `0.1.5-rc.2`), whose `^0.1.5-rc.2` range pulls `dsh-base`
0.1.5-rc.3, and npm may then nest
`dsh-sandbox-local` under `dsh-base/node_modules`. dsh's plugin loader cannot
resolve that package from the app root, so `dsh web` aborts at boot. The lock
freezes the working layout — the package under the app's own `node_modules` —
as well as every transitive integrity hash. `images/tools/dsh/verify-dsh.sh`
is therefore stricter than a bare `--version`: dsh dispatches on
`import.meta.main`, undefined below Node 22.19, so on an old Node its CLI exits
0 having printed nothing — a broken agent that every exit-code-only check
(including `agent-vm setup`) would accept. The gate fails the build on empty
output and on a version that differs from the pin.

## Bumping the `pi` pin

`bash images/tools/pi/upgrade-pi.sh [VERSION]` automates every step below; see
[`pi/README.md`](pi/README.md). The manual flow it performs:

**Bumping the pin** means editing `package.json` and regenerating the lock:

```bash
cd images/tools/pi
npm install --ignore-scripts --package-lock-only --no-audit --no-fund
```

That regenerated lock has **5 entries with no `integrity`**: npm inherits Pi's
published `npm-shrinkwrap.json`, which omits the hashes for its five
`@earendil-works` siblings (`chord`, `pi-agent-core`, `pi-ai`, `pi-telemetry`,
`pi-tui`). Refill them from the registry's published `dist.integrity`:

```bash
pin=$(jq -r '.dependencies["@earendil-works/pi-coding-agent"]' images/tools/pi/package.json)
for p in chord pi-agent-core pi-ai pi-telemetry pi-tui; do
    printf '%s %s\n' "$p" "$(npm view "@earendil-works/$p@$pin" dist.integrity)"
done
```

Paste each value into its lock entry (only the five; no other hand-edit). This is
not decorative: npm ignores our lock for that subtree, so `install-pi.sh` enforces
the five itself — it re-fetches each tarball, compares the sha512 to the committed
`integrity`, and compares the extraction against what `npm ci` installed with a
plain `diff -r` — **no `-x node_modules`**, because that basename exclusion would
blind the check to a shadow `node_modules` planted at *any* depth (for example
`pi-ai/dist/node_modules/…`, which wins Node's resolution from inside `pi-ai/dist`).
The only tolerated difference is the sibling's own nested dependency directories
as the committed lock declares them (`pi-ai`'s
`node_modules/{agent-base,https-proxy-agent}`, derived from the lock, not
hard-coded), which npm itself authenticated because they carry `integrity` in
Pi's shrinkwrap and are folded wholesale from the installed tree. So for every
path **inside one of the five siblings' own trees** and outside the sibling's
lock-declared nested dependency directories, the bytes that ship are the bytes
the hash was reviewed against. There, a mismatch — an extra file, directory or
symlink, a tampered file, or a missing one — is a **hard** build failure that
`AGENT_INSTALL_SOFT_FAIL` may not downgrade. (A path placed *beside* one of the
five, anywhere under `node_modules/@earendil-works/`, is outside every compared
sibling tree and is not looked at; npm extracts each sibling into its own
directory, so the unauthenticated sibling fetch cannot create one.) Two
`cargo test` guards
(`every_locked_package_carries_integrity`,
`the_build_verified_sibling_set_is_exactly_the_five_nested_earendil_packages`)
fail loudly if a regenerated lock drops the hashes or the nested layout moves.

### The bridge packages: `images/tools/pi/bridge/`

The `pi` layer also ships **`pi-claude-bridge`**, a pinned Pi extension that
registers a `claude-bridge/*` provider and answers requests by spawning Claude
Code through the Claude Agent SDK. See
[ADR-0023](../../docs/adr/0023-image-owned-pi-extension-packages.md). It is a
**separate** npm project from the Pi install above — installed into
`/opt/agent-vm/pi-packages` — so bumping either pin does not re-emit the other's
tree. It is activated by the wrapper's second `--extension`, not by
`pi install`, because every one of Pi's own activation mechanisms (`packages`,
`extensions`, auto-discovery, `PI_CODING_AGENT_DIR`) writes into `$HOME/.pi`,
which in the guest is per-project state rather than the image.

**Bumping the pin** is `bash images/tools/pi/bridge/upgrade-bridge.sh [VERSION]`
(see *Upgrading a tool*). By hand, it is the same lockfile flow, with two flags
that are *not* optional:

```bash
cd images/tools/pi/bridge
npm install --ignore-scripts --package-lock-only --no-audit --no-fund --legacy-peer-deps
```

- **`--legacy-peer-deps` — on both the lock generation and the layer's
  `npm ci`.** The bridge declares `@earendil-works/pi-*` and `typebox` as peer
  dependencies, but Pi's extension loader aliases those imports to its own
  copies (`dist/core/extensions/loader.js`), so they must not be installed.
  Without the flag npm solves those ranges and drags in a **second,
  version-skewed `@earendil-works/pi-coding-agent`** beside the image's own Pi
  (plus the AWS SDK, `@google/genai`, `openai`, … — 338 lock entries instead of
  107), and the generated lock then loses npm's `integrity` on the five
  `@earendil-works` siblings Pi's published shrinkwrap covers. The `npm ci`
  refuses a lock generated without the flag (`EUSAGE … can only install packages
  when your package.json and package-lock.json are in sync`), which is how that
  mistake announces itself. This is the same policy Pi's own installer uses, for
  the same reason.
- **`--omit=optional` — on the layer's `npm ci`.**
  `@anthropic-ai/claude-agent-sdk` has no `dependencies`; it has eight
  `optionalDependencies`, one per platform, each carrying a whole native Claude
  Code binary (ADR-0023 sizes the guest-platform one). The image already ships
  `claude` at `/opt/agent/.local/bin/claude`, so the platform package is dropped
  and the layer's `seed.d/20-pi-claude-bridge` first-boot hook writes
  `provider.pathToClaudeCodeExecutable` into `~/.pi/agent/claude-bridge.json`.
  Without that hook every bridge turn fails at SDK spawn with `Native CLI binary
  … not found`.

Unlike the `pi` lock, **no hand-refilled hashes are needed here**: this tree has
no shrinkwrap anywhere in its chain, so `npm ci` authenticates every tarball
itself and `install-pi-packages.sh` needs no bespoke verifier. Four `cargo test`
guards keep that true — every entry carries `integrity`, the pin is exact and
agrees with the manifest, the lock installs none of the packages Pi's loader
aliases, and the layer's `npm ci` still carries `--omit=optional` and
`--legacy-peer-deps`.

`--ignore-scripts` matches `pi` and `dsh`: no upstream lifecycle script runs
during the build. The install adds ~31 MiB to the layer (not a whole second
Claude Code — see ADR-0023 for the platform-package size).

## The `dsh` layer: persistence and credentials

The tool definition (`crates/agent-vm/src/default-tools.toml`) gives `dsh` the
default argv `web` and `persist = [".dsh"]`. dsh keeps its entire user state —
profiles, sessions, and the `~/.dsh/.credentials.yaml` credentials document —
under its home, so persisting the tree is what makes an API key stored once in
the Models UI survive the next launch. That is the config-driven equivalent of
`pi`'s generic `.pi` link.

The layer also pins `pnpm` in the same lock and links it onto `PATH`, because
`dsh plugin --profile … add …` forwards to pnpm and the base image has none.
Pinning it there (rather than `npm install -g pnpm`) gives it the same
integrity-checked install as the rest of the tree.

Bumping the pin is `bash images/tools/dsh/upgrade-dsh.sh [VERSION]` (see
*Upgrading a tool*). By hand, it is the plain lockfile flow (dsh's tree has no
shrinkwrap integrity quirks, so no hand-editing), run with `--ignore-scripts`
exactly as the layer's `npm ci` is so regenerating never runs lifecycle scripts
either:

```bash
cd images/tools/dsh
npm install --ignore-scripts --package-lock-only --no-audit --no-fund
```

Like `pi`, `dsh` declares **no** `credentials`: it is a multi-provider harness
that must start with none configured. Community OAuth/subscription plugins are
deliberately **not** baked in; `dsh plugin` is available in-guest. See
[USAGE.md](../../USAGE.md#credential-free-agents-pi-dsh) and
[ADR-0022](../../docs/adr/0022-dsh-tool-layer.md). The `pi` layer's pinned
`pi-claude-bridge` is a deliberate exception to that rule, justified narrowly in
[ADR-0023](../../docs/adr/0023-image-owned-pi-extension-packages.md): it brings
no new host-credential reader, and it is pinned and version-reviewed.

