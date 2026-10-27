# ADR-0017: Gate credential provisioning on the tools a tool declares

## Status

Accepted. Implementation decision for
[agent-vm #118](https://github.com/gregwebs/agent-vm/issues/118), a follow-up
split out of [#82](https://github.com/gregwebs/agent-vm/issues/82). Amends
[ADR-0015](0015-config-driven-tools.md) (which preserved the asymmetric legacy
gating) and [ADR-0016](0016-tool-declared-guest-env.md) (whose `CODEX_HOME`
rationale cited `shell`'s `credentials`). Builds on **Tool**, **Credential
provider**, **Provisioning set** and **Available tools** in
[CONTEXT.md](../../CONTEXT.md).

[ADR-0048](0048-named-mount-sets-and-tier-local-tool-references.md) amends this
record in two steps. **Tier-local tool references are implemented (#395):** every
`tools` reference — explicit name or `"*"` — resolves inside the one
configuration file that declares the tool, including definitions hidden from
launch-verb selection, so the explicit cross-file opt-in described below is gone.
**Tool mount inheritance through the same closure is implemented (#396)**: a full
user tool's `mounts` is a fourth facet of that closure, own plus inherited, and a
direct `run`/`--` target has an empty mount facet. Tool `env` and
`network_requests` were not folded and keep their own-only rule, and required
providers are still the launched tool's own.

## Context

#81/#82 preserved a deliberate asymmetry: `Anthropic`/`OpenAi` capture ran on
*every* launch regardless of the selected tool, and the claude/codex/opencode
bypass configs were written unconditionally. That asymmetry is a **capability
leak**, pinned today in `tests/fixtures/config-launch/codex.golden`: on
`agent-vm codex` the launch registers `MSB_AGENT_VM_ANTHROPIC_UNUSED` against
`api.anthropic.com` / `platform.claude.com` / `mcp-proxy.anthropic.com`,
registers an intercept rule for `POST platform.claude.com/v1/oauth/token`,
writes `claude/.credentials.json` holding the **refresh** placeholder into the
persistent project state dir, and leaves the host's real access token in
`<state>.secrets/anthropic`.

`intercept_hook::oauth_refresh` returns placeholders only, so there is no token
exfiltration — but a `codex` guest can spend the user's Anthropic plan through
the substitution entry, and can repeatedly drive host-side `claude` CLI runs
(the same route exists for `auth.openai.com`). A guest that never declared
Anthropic has no business holding either. Narrowing **capture** alone closes it,
because both the proxy secret and its route key off
`creds.token_file(provider)`.

#82 could not fix this: its headline criterion was that every default launch be
identical to the pre-#82 binary.

## Decision

- **`tools` names catalog tools, and resolution is the least fixed point of**

  ```
  provisioning(t) = credentials(t) ∪ ⋃ { provisioning(u) | u ∈ tools(t) }
  ```

  so a cycle is harmless rather than an error. `tools` names **tools**, never
  credential providers.
- **`"*"` must be the sole entry and is reserved as a tool name.** A reference
  resolves inside the declaring tool's **tool reference scope** — the one
  configuration file that declares it (`ToolOrigin` equality: variant *and*
  path, with `BuiltIn` meaning the embedded `default-tools.toml`) — and never
  across tiers (#395, ADR-0048). That scope is resolved over **every** retained
  definition, including a definition hidden from launch-verb selection by a
  whole-definition user-wins conflict: the user `pi` wins the verb `agent-vm
  pi`, while a project `helper` that names `pi` gets the *project* `pi`'s
  credentials and persisted paths. A name the scope does not declare is a config
  error, never an opt-in to crossing files, and every definition's references
  are validated even when no launch verb reaches that definition. Resolution
  happens *before* launch selection, so the facets (providers, credential
  names, `persist` paths, and — since #396 — user config mounts) can never be
  folded from a lossy merge. This is the
  user's binding amendment to the original specification, which said `"*"`
  meant every tool the catalog declares; the shipped default catalog's table is
  unchanged because every built-in tool shares `default-tools.toml`.
- **The synthesized `shell` fallback is a launch affordance, not a declaration
  in any file.** It is resolved from a scope holding only the one shipped `shell`
  definition, so under a custom catalog it closes over itself alone and
  provisions no provider, no requested name and no `persist` path. It is also not
  an explicit-reference target: a tool with `tools = ["shell"]` needs a local
  `shell` declaration or must drop that edge. Resolving the fallback out of a
  fully provisioned shipped catalog would instead restore the shipped agents'
  credentials and `.dsh` persistence into a catalog that declared none.
- **Omitted `tools` is `["*"]` for a tool named `shell` and `[]` for every other
  tool**, off one shared `SHELL_TOOL_NAME` const that the catalog's shell
  fallback also uses, so the two cannot drift.
- **`credentials` keeps exactly one extra job: the requirement set.** A launch
  still hard-fails before boot when a required provider yielded no usable
  credential. Named tools are *provisioned*, never *required* — a tool that
  connects to another through a bridge pulls in that tool's credential without
  inheriting its hard bail.
- **A direct command has no provisioning decision at all** (amended by #398,
  0.7.3). `agent-vm run PROGRAM` / `agent-vm -- PROGRAM` selects no catalog
  entry, so its requirement set, provisioning set, declared network requests
  and `persist` list are all empty: the launch requests no service name, which
  makes the resolver capture nothing and the network plan grant nothing. The
  empty set is supplied at one normalization point, not by substituting any
  entry — in particular not the `shell` fallback. Shared **image** furniture is
  not a grant: the image-capability Chrome DevTools MCP entry in `claude.json`
  is written from the image, not from a catalog declaration, and a direct
  launch keeps it.
- **One predicate gates every provider-owned facet**: host credential capture,
  the guest placeholder files, the proxy secret and its intercept route, the
  first-run bypass configs, and the provider guest env. `Scope`,
  `CaptureScope` and `proxy_requires_selection` are deleted.
- **`github_egress` stops feeding capture.** It stays orthogonal to the tool
  (`--no-git` / detected repos) and keeps its own wire slot.
- **The built-in `shell` stops declaring `credentials`.** It is not an agent and
  must not inherit any provider's hard bail; its omitted `tools` defaults to the
  wildcard, so it *provisions* every provider the catalog's tools declare
  without *requiring* any of them.
- **The launch catalog resolves the set once** (`CatalogEntry::provisioned`),
  and the whole entry is handed to dispatch and `run::launch`, so the tool and
  its provisioning set cannot be mismatched.

### The invariant

**A placeholder is never provisioned into the guest unless this launch
registers its substitution entry.** For `Anthropic`/`OpenAi`/`OpencodeStatic`
this holds by construction — their placeholders live in files written *by*
capture. `Copilot` is the exception: its placeholder lives in
`copilot/config.json`, a *config* file written by the pre-capture bypass pass.
Hence two fixes: the Copilot config write moves to **after** `refresh_copilot`,
and `COPILOT_GITHUB_TOKEN` is gated on **wiring** as well as on membership
(capture can fail — no device-flow cache, `--no-git` — while `shell` provisions
Copilot *without requiring* it, so the existing hard bail no longer papers over
it). A stale placeholder left by an earlier, successful launch is removed by a
unified, **content-scoped** clearer that covers `claude/.credentials.json`,
`codex/auth.json` and Copilot's `github_token` key — each removed only when it
holds *our* placeholder, never a real credential a guest wrote there — while
deliberately leaving OpenCode's merged `auth.json` alone (user-authored
provider rows live there, and `refresh_opencode_with_paths` already clears its
own synthetic row).

## Consequences

Per-verb effect under the shipped default catalog (see the #164 and #360
amendments below for `pi`'s two edges):

| verb | `credentials` (required) | provisioning set |
|---|---|---|
| `pi` | *(none)* | `{anthropic, openai}` |
| `codex` | `["openai"]` | `{openai}` |
| `opencode` | `["openai","opencode-static"]` | `{openai, opencode-static}` |
| `claude` | `["anthropic"]` | `{anthropic}` |
| `copilot` | `["copilot"]` | `{copilot}` |
| `shell` | *(none)* | `{anthropic, openai, opencode-static, copilot}` |

- **`agent-vm shell` provisions a *working* Copilot**: a substitution entry, a
  `copilot/config.json` placeholder and `COPILOT_GITHUB_TOKEN`, all together.
- **A config that declares tools but no `shell` gets a fallback shell that
  provisions nothing.** The fallback is resolved from a scope holding only the
  one shipped `shell` definition (#395), so its wildcard closes over itself
  alone: no provider, no requested credential name, no `persist` path, and no
  shipped agent restored. `USAGE.md` carries the resulting guidance.
- **A `tools` reference is tier-local and validated in every definition**
  (#395). The breaking part is explicit: a reference to a name another file
  declares is now a config error, and so is a dangling reference inside a
  definition hidden by a launch-name conflict — shadowing a name is no longer a
  way to ignore its local dependency graph. Migration is to copy or redeclare
  the referenced tool, and its transitive references, in the same file; see
  [USAGE.md](../../USAGE.md#tool-references-are-local-to-their-file).

> **Amended by [ADR-0036](0036-default-deny-launch-egress.md):** launch egress
> is default-deny; every tool launch installs an explicit policy, including
> zero-provisioning launches. Only the policy and `.network()` descriptions in
> the following two historical bullets no longer apply; the absence of a TLS
> overlay when `secrets` is empty remains true. Provisioning still grants no
> connection authority.

- **Network egress is not provider-scoped.** The policy is `default_egress:
  deny` plus a blanket `destination: { group: "public" }` allow, identical in
  all five goldens, so a `codex` guest can still *reach* `api.anthropic.com`; it
  simply has no token and no substitution entry, so every request 401s. That is
  the correct design — capture gating is the control — recorded so nobody reads
  "provisions `{openai}`" as "cannot talk to Anthropic".
- **A zero-provisioning launch** (a declared `shell` with
  `tools = []`) boots with **no TLS overlay**: `Plan::apply_to` returns the
  builder untouched when `secrets` is empty, so `tls_overlay(enabled(true))` is
  never set. It also carries no explicit `policy` subdocument — the launch never
  calls `.network()` at all — but an unset policy materializes to
  `NetworkPolicy::default()` (`default_egress: deny` plus the public-profile
  allow), i.e. the same restriction a wired launch's materialized policy has.
  Nothing leaks — there is nothing to substitute — but the shape is recorded and
  pinned by a test.
- **`doctor` now prints `provisions=`** next to `credentials=`, so a
  restriction is never invisible; the built-in shell row reads
  `credentials=none`.
- **Forward compatibility is not provided.** A config written with the new
  `tools` field hard-errors on an older binary (`RawTool` is
  `deny_unknown_fields`), the same as every field added since #80.

### Deliberately unchanged

- **`guest_home_links()` and `eager_state_dirs()` stay unconditional.** The
  whole state dir is already bind-mounted at `/agent-vm-state`, so a guest can
  read `/agent-vm-state/claude/.credentials.json` whether or not `~/.claude` is
  a symlink — what a guest can *use* is decided entirely by the
  placeholder/proxy gating. Narrowing the links would also introduce a real
  failure: an in-guest agent the tool did not declare would create a *real*
  `~/.claude` in the persistent `<state>/home`, and the next `agent-vm claude`
  would hard-bail in `force_symlink`.
- **`--no-git` / `gh` egress stays orthogonal** to the tool and keeps its own
  capture and wire slot.
- **`missing_credential_error`'s gate stays the launched tool's `credentials`.**
- **`layer` is untouched** ([#84](https://github.com/gregwebs/agent-vm/issues/84));
  the provisioning closure now also folds each visited tool's `persist` paths
  ([#83](https://github.com/gregwebs/agent-vm/issues/83)).

## Amendment: #164 exercises alternative 2 — `pi` provisions Anthropic

[agent-vm #164](https://github.com/gregwebs/agent-vm/issues/164) gives the
shipped `pi` the `tools = ["claude"]` edge, so **alternative 2 of this ADR** ("a
tool that connects to another tool (`Pi` → `claude`)") is now exercised in the
shipped catalog rather than only in a test. The motivation is in
[ADR-0023](0023-image-owned-pi-extension-packages.md): the image-owned
`pi-claude-bridge` extension spawns Claude Code as a child, and Claude Code
needs *its own* credential — the Anthropic provider's placeholder/proxy dance is
exactly that credential.

This is the shape the Decision above was written for, and it needs no new rule:

- **`pi` keeps `credentials = []`**, so it inherits no hard bail and still
  launches for a user with no host Claude login. It is the one shipped verb whose
  requirement set and provisioning set differ, which is the point of the
  `credentials` / `provisioned` split.
- **The inherited side effects are the Anthropic provider's, not `pi`'s.**
  `write_bypass_configs` follows the provisioning set, so a `pi` launch now
  writes `claude/settings.json` and `claude.json` even when capture failed; the
  stale-placeholder clearer no longer deletes a `shell`-written placeholder on
  the next `pi` launch (it is wired now); and when capture succeeds it overwrites
  a guest-authored `~/.claude/.credentials.json` with the placeholder. All three
  behaviours are pinned by `tests/config_launch_driven.rs`.
- **The guest-HOME links stay unconditional**, as the "Deliberately unchanged"
  section requires — nothing here narrows them.

One non-DR change is recorded for honesty: the `ANTHROPIC_API_KEY` publication
this ADR does not touch becomes reachable on a third verb. That pre-existing
defect is tracked separately as
[#165](https://github.com/gregwebs/agent-vm/issues/165). (Removed by #163.)

## Amendment: #360 — `pi` also provisions OpenAI

[agent-vm #360](https://github.com/gregwebs/agent-vm/issues/360) gives the
shipped `pi` a second edge, `tools = ["claude", "codex"]`. The rule is
unchanged: naming a tool provisions its provider without requiring it, so a
host with no Codex login still gets a `pi` launch. The second edge exists for
the same reason as the first — under ADR-0044's PR A contract, the image-owned
`agent-vm-codex` extension carries the guest `codex/auth.json` placeholder to
`chatgpt.com`, so it needs the `openai` provider's capture and proxy substitution rather than Pi's own
`auth.json`. See
[ADR-0044](0044-pi-reaches-host-codex-through-an-image-owned-provider.md) for
the transport (not yet present in the pinned v0.1.3 image) and
[ADR-0011](0011-pi-mixed-credential-ownership.md) for what the shared
`auth.openai.com` refresh route costs.

- **`pi` keeps `credentials = []`**, so it still inherits no hard bail. It
  remains the one shipped verb whose requirement and provisioning sets differ.
- **The inherited side effects are the `openai` provider's, not `pi`'s:**
  `codex/config.toml` is written on every `pi` launch, and a successful capture
  overwrites a guest-authored `codex/auth.json` with the placeholder. Both are
  pinned by `tests/config_launch_driven.rs`.
- **Tool `env` is still not inherited.** The extension reads the fixed
  `/agent-vm-state/codex/auth.json`, so `pi` gains no `CODEX_HOME`; the
  "Deliberately unchanged" note about `shell`'s explicit pair stands.

## Alternatives

1. **Keep `Scope::Always`** — the asymmetry as a design goal. Rejected: it leaks
   a capability, per *Context*.
2. **Gate on the launched tool's own `credentials` only, no `tools` field.**
   Rejected: `agent-vm shell` would lose in-shell access to every agent the
   config makes available, and a tool that connects to another tool (`Pi` →
   `claude`) would have no way to ask for it.
3. **Gate every launch on the catalog union.** Rejected: an agent verb would
   hold credentials it never declared.
4. **Make `shell` a kitchen sink through its `credentials` list.** Rejected: it
   inherits Anthropic's and Copilot's hard bails (so `agent-vm shell` would fail
   for any user without both logins), and it keeps the Anthropic capability on
   the most-run verb by design.
5. **An additive-dependency default** (omission means none, `shell` writes
   `["*"]` explicitly). Rejected: the default must stay broad; omission meaning
   "all available" is special to `shell`.
6. **`all_tools = true` as a second field, or a string-or-list `tools = "all"`.**
   Rejected: `RawLayer`'s comment records the preference for optional fields plus
   exhaustive validation over an untagged enum, and a second field needs a
   cross-field error for a contradictory config.
7. **Narrow the guest-HOME links and eager state dirs too.** Rejected: furniture
   is not a capability, the narrowing is nearly unobservable, and it introduces
   the real-directory collision described above.
8. **Keep Copilot's `WhenSelectedOrGithubEgress`.** Rejected: its only remaining
   consumer was a launch notice that then overstated what the guest could use.
9. **Keep the merged-catalog wildcard** (the specification's original model:
   `"*"` = every tool the catalog declares). Rejected by the user's amendment:
   it lets a **project-tier** tool widen the **user's** `shell` — a project can
   add `credentials = ["copilot"]` and `agent-vm shell` then captures the host
   Copilot token, registers a live substitution entry, writes
   `copilot/config.json` and exports `COPILOT_GITHUB_TOKEN` into a guest running
   that repo's code. The tier-local rule closes that path, and #395 closed the
   remaining explicit-name half of it.
10. **Retain the pre-merge tier vectors so `"*"` reads the declaring file's full
    declared set** — now **required and implemented** (#395, ADR-0048): a
    definition hidden by a launch-name conflict still supplies its own file's
    references, so the arena keeps every definition and only launch *selection*
    applies user-wins. What stays rejected is the other half of the earlier
    reading: **resurrecting the full shipped scope for a custom catalog's
    fallback.** The fallback resolves from a singleton shipped `shell`, not from
    `default-tools.toml`'s whole scope, because the latter would provision
    credentials and persisted paths for verbs the catalog does not offer.
