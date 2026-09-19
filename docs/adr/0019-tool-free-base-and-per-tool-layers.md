# ADR-0019: A tool-free base image plus per-tool layers

## Status

Accepted. Implementation decision for [agent-vm #84](https://github.com/gregwebs/agent-vm/issues/84), the image half of epic [#78](https://github.com/gregwebs/agent-vm/issues/78). Extends [ADR-0003](0003-project-tooling-layers.md) (layer chains and the layer image contract) and [ADR-0015](0015-config-driven-tools.md) (config-driven tools). Builds on **Chain root**, **Base image**, **Composed default image**, **Tool layer**, and **Tooling layer** in [CONTEXT.md](../../CONTEXT.md).

> The ticket for #84 says "extend the config-driven-tools ADR". This is a **new** ADR instead: ADR-0015 is about the CLI and already carries one amendment (#83); #84 is about the image. ADR-0015 still gets a substantive amendment for D10's narrowed `setup` severity (below), so the deviation is from the letter, not the intent.

## Context

[#80/#81](https://github.com/gregwebs/agent-vm/issues/80) made "which tools exist" a two-tier TOML config, [#82](https://github.com/gregwebs/agent-vm/issues/82) generated one CLI subcommand per resolved tool and gave each a declarative `layer` field, and [#79](https://github.com/gregwebs/agent-vm/issues/79) composed an ordered chain of project tooling layers. "Which tools exist" was user configuration everywhere *except* the artifact that boots: `ghcr.io/wirenboard/agent-vm-template` unconditionally contained codex, opencode, claude and copilot. So `tools = ["claude"]` produced a CLI with only `agent-vm claude` but a guest that still contained the other three.

## Decision

- **The image splits into a tool-free base plus one layer per tool.** `images/Dockerfile` becomes `ghcr.io/wirenboard/agent-vm-base`, carrying nothing tool-specific. `images/tools/{codex,opencode,claude,copilot}/Dockerfile` are one standalone layer each, obeying ADR-0003's contract. The claude layer owns the LSP-plugin install, the plugin stash, and the first-boot seed hook.
- **CI publishes, from one run, a base and a composed default.** `agent-vm-base` is the tool-free base; `agent-vm-template` is the base plus the four default tool layers chained in declaration order. Building both in the same run is what makes "the template is base + the four layers" provable, and a CI assertion checks the template's `rootfs.diff_ids` begin with the base's, in order.
- **A launch composes locally only when it must.** `tool_layer::chain_root` is pure and decides the root from `--image`, `--base-image`, and whether the catalog's declared layer sequence equals the shipped default. When it does and nothing else is given, the launch boots the published composed template **verbatim — zero docker calls**. Any other declared set composes from `agent-vm-base`; `--base-image` always composes; `--image` boots verbatim and composes no tool layers. `--image` and `--base-image` together is an error.
- **Builtin layers are embedded in the binary and materialised only on the compose path.** `include_dir!` snapshots `images/tools/` at compile time (agent-vm ships as prebuilt npm binaries with no checkout), and a test asserts the snapshot equals the on-disk sources CI builds from. `TempDir` handles are held for the whole of chain resolution and execution.

Column reference for the root decision:

| `--image` | `--base-image` | declared == shipped | root | tool steps |
|---|---|---|---|---|
| set | unset | — | that image, verbatim | none |
| set | set | — | error | — |
| unset | unset | yes | the composed template | none |
| unset | unset | no | the tool-free base | all declared |
| unset | set | — | the given base | all declared |

### Design decisions

**D1 — The chain root keys on the declared *layer sequence*, not the tool names.** A config that renames `claude` to `claude-yolo` but keeps `layer = { builtin = "claude" }`, with the other three untouched and in order, still boots the published template. Comparison is over the ordered, deduplicated `Vec<ToolLayer>` (tools with no `layer`, such as `shell`, contribute nothing) against the same projection of `default-tools.toml`. Strict ordered equality: being over-strict can only cost a build, never boot the wrong image.

**D2 — Builtin tool layers are materialised into a per-launch `TempDir`, and only on the compose path.** The ticket says "only when a rebuild is actually needed"; hashing also needs the bytes, so the honest rule is *only when composition is needed*. The template fast path creates no temp directory. Teaching `layer::canonical_stream` to hash an in-memory tree was rejected as a much larger change to the most safety-critical code in the repo. Materialisation writes every file mode `0o644` explicitly, with no per-filename cases: the hash folds a file's mode to one execute bit, so a byte-identical git checkout of the same sources must materialise identically. The execute bit a tool layer needs is granted by `COPY --chmod` inside its Dockerfile.

**D3 — `agent-vm-install` and `/opt/agent` stay in the base.** The helper names no tool; it is the repo's uniform "fetch-an-upstream-installer with a soft-fail policy" contract, and a build context cannot `COPY` from a sibling directory, so four copies would drift. The base documents it as a facility tool layers may use, along with the world-readable `/opt/agent` prefix (C7) and the host-CA shim (baked into the rootfs, so every layer inherits host trust with no extra build arg — `CA_SHIM_CACHEBUST` must not be threaded into a tool layer).

**D4 — The claude plugin seed becomes a generic image seed hook.** The launcher's prelude stops naming claude; it runs every executable under `/opt/agent-vm/seed.d/`, and the claude layer installs `10-claude-plugins` there. Gating on the launched tool's name would re-introduce the compiled-in tool knowledge epic #78 removes; gating on the provisioning set is incoherent because the `~/.claude` symlink is created for every launch unconditionally.

**D5 — `--base-image` always forces composition, even with the default tool set.** It is how a source-checkout user tests a locally built/imported base. `--image` (boot verbatim) and `--base-image` (configure composition) together is an error.

**D6 — `--update-check` probes the chain root and nothing else.** `Verbatim`, `Template` and `Base` are all published tags the user or the distribution named; `agent-vm-layer:<hash>` never is. This preserves ADR-0003's base-vs-derived split.

**D7 — `layer = { path = "…" }` anchors on the declaring config file's directory.** A user-tier config's cwd is arbitrary, so the only well-defined anchor is `dirname(<the file that declared it>)`; an absolute path is used as-is. A missing directory or a directory without a `Dockerfile` is a hard error naming the declaring tool.

**D8 — Locally composed tool layers freeze their agent version at build time.** The layer hash covers the layer directory, and `AGENT_VERSION_*` is empty on a local build, so a non-default tool set gets whatever upstream shipped the day it first built, until the base moves (which invalidates the whole chain). This is identical to how every `--layer` layer already behaves. Documented in USAGE.md; not fixed here.

**D9 — `MIN_SUPPORTED_IMAGE_API` stays 1; only `MAX` moves 2 → 3.** The new launcher must keep booting a cached, not-yet-repulled API-2 template. The base writes `3`; the composed template inherits it. D11 is the consequence.

**D10 — `setup`'s `required` severity is narrowed, not blanket-downgraded.** `setup` verifies *the published image this configuration would boot from*. With `tools = ["claude"]` that is the bare base, which does not carry `claude`, so a naive `required` would make a correct configuration fail. The fix narrows the rule: when the root is the base, a shipped command loses `required` **iff some declared tool layer in the composed chain supplies its command**. Everything else — including a config that redeclares `claude` without a `layer` field — stays fatal, so ADR-0015's anti-downgrade rule and its pinning test survive unchanged. The residual downgrade (a user *can* soften `claude` by attaching a `layer` to it) is acceptable because the claim is checkable — the layer must exist and build, or the launch fails loudly — and a config that can set `command`/`args` can already run arbitrary guest code.

**D11 — The generic seed prelude keeps a legacy fallback while `MIN_SUPPORTED_IMAGE_API < 3`.** Because `MIN` stays 1 (D9), a freshly upgraded launcher must keep working against an already-cached API-2 template, which ships `/opt/agent-vm/seed-claude-plugins.sh` and has no `seed.d/`. Emitting only the `seed.d` loop would turn plugin seeding into a silent no-op on every such image — a symptomless regression. The prelude runs `seed.d/*` **and** the legacy script when present; the const's doc comment ties the fallback's removal to the `MIN` bump. Rejected alternatives: bumping `MIN` to 3 (hard-fails every user whose cache holds today's template until they pull, for a plugin-seeding nicety); emitting only the loop (symptomless); detecting the image API and emitting one clause (the API is read after boot, the prelude is built before).

## Consequences

- **Two GHCR repositories are published.** A new package (`agent-vm-base`) is private by default; making it public is a one-time admin action the workflow cannot perform. Until it is public, a non-default-tool-set user gets an auth failure on the base pull. Release-checklist item.
- **A post-release window exists** in which a freshly installed launcher with a non-default tool set resolves an `agent-vm-base:latest` that does not exist yet (both `:latest` tags stay unpublished until the version that ships `DEFAULT_BASE_IMAGE_REF` is on npm). Mitigation: trigger `build-image` by `workflow_dispatch` immediately after the npm publish instead of waiting for the cron.
- **A locally composed non-default chain freezes its agent version** (D8) and rebuilds its own copy of the tool layers per project (the layer-hash slug is the project name) — both already true of project tooling layers under ADR-0003.
- **`setup` verifies the published root, not the composed image.** It does not build, and it reports a not-yet-composed layer-supplied command as a notice rather than verifying it.
- **`AGENT_INSTALL_SOFT_FAIL` is deliberately absent from the launcher's compose path.** The launcher passes exactly one build arg (`BASE_IMAGE=`). A soft-fail there would ship a silently cached "healthy-looking image missing its toolchain", which ADR-0003 exists to prevent. A source-checkout user behind a TLS-intercept proxy builds with `images/build.sh` (which sets the arg) and passes `--base-image`/`--layer`, or uses the published template.
- **Redeclaring a shipped tool now requires its `layer`.** While `layer` was metadata, a `[[tools]]` entry that copied `claude` to adjust its `args` worked without one. The field is now what composes the image, so such an entry must carry `layer = { builtin = … }` (or a `path`) or a non-default tool set boots a guest without that tool — a bare command-not-found in the guest, or a `setup` diagnostic naming the image it checked. Documented as an upgrade note in USAGE.md's config section.
- **No Verus contract is added.** ADR-0018 asks for one on a new *pure* function deciding a security boundary, a resource limit, or the parse of untrusted input. `chain_root` is pure and decides which image boots, but the trust boundary is unchanged (ADR-0003's `.agent-vm/`), and its domain is three `Option<String>`s compared against a compiled-in list; a machine-checked contract would restate the decision table the unit tests already enumerate exhaustively. Recorded so the absence is a decision rather than an oversight.
- **The CI intermediates are untagged digests.** They match no protected retention tag and are age-pruned. Each hourly run adds three of them (`codex`, `opencode`, `claude`) to `agent-vm-base` — ~1,000 at the 14-day horizon — so the `retain` job must stay comfortable paginating past a four-digit version count.
- **`images/build.sh` and the manual chain in `macos-build.md` need a `docker`-driver builder** (`--load`ed intermediates are only visible to the next step's `FROM` when the builder shares the daemon's image store). `images/build.sh` checks the driver up front; CI uses push-by-digest instead.

## Alternatives

- **One published tag with tools stripped locally.** Rejected: it would publish a base that no launcher can boot (the epic merged the image pair exactly to avoid this), and stripping layers from a published image is not something Docker does.
- **A generated composed Dockerfile in CI.** Rejected: a checked-in per-tool Dockerfile is reviewable and reusable as a worked example of the layer contract; generating it hides the contract from the reviewer.
- **Gating the claude seed on the launched tool name.** Rejected (D4): it re-introduces compiled-in tool knowledge.
- **Blanket `Base` downgrade in `setup`; `setup` builds the chain; `setup` refuses a non-default set.** Rejected (D10) — see that decision's table in the #84 plan.
- **Teaching `layer::canonical_stream` to hash in-memory trees.** Rejected (D2): too large a change to the safety-critical hashing code for a few KB of build context.
