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
- **`"*"` must be the sole entry and is reserved as a tool name.** It closes
  over the tools declared in the **same configuration file** as the declaring
  tool — the tools whose `ToolOrigin` equals the declaring tool's — **not** the
  merged catalog. A tool declared in a *different* file (any tier, including the
  embedded built-in file) is reachable only by **naming it explicitly**; that
  name is the cross-file opt-in. This is the user's binding amendment to the
  original specification, which said `"*"` meant every tool the catalog
  declares. The shipped default catalog's table is unchanged because every
  built-in tool shares `default-tools.toml`; the difference is confined to a
  custom catalog (see Consequences).
- **Omitted `tools` is `["*"]` for a tool named `shell` and `[]` for every other
  tool**, off one shared `SHELL_TOOL_NAME` const that the catalog's shell
  fallback also uses, so the two cannot drift.
- **`credentials` keeps exactly one extra job: the requirement set.** A launch
  still hard-fails before boot when a required provider yielded no usable
  credential. Named tools are *provisioned*, never *required* — a tool that
  connects to another through a bridge pulls in that tool's credential without
  inheriting its hard bail.
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

Per-verb effect under the shipped default catalog:

| verb | `credentials` (required) | provisioning set | before |
|---|---|---|---|
| `codex` | `["openai"]` | `{openai}` | anthropic+openai+opencode-static |
| `opencode` | `["openai","opencode-static"]` | `{openai, opencode-static}` | same three |
| `claude` | `["anthropic"]` | `{anthropic}` | same three |
| `copilot` | `["copilot"]` | `{copilot}` | three + a *broken* copilot |
| `shell` | *(none)* | `{anthropic, openai, opencode-static, copilot}` | three, copilot **broken** |

- **`agent-vm shell` gains a *working* Copilot**: a substitution entry, a
  `copilot/config.json` placeholder and `COPILOT_GITHUB_TOKEN`, all together.
- **A config that declares tools but no `shell` gets a fallback shell that
  provisions nothing.** The appended fallback is `BuiltIn`, so its wildcard
  closes over `default-tools.toml`'s tools *present in the catalog* — and when a
  user config replaces the defaults, the only one present is `shell` itself.
  Today such a config gets the always-on `{anthropic, openai, opencode-static}`.
  This is a user-visible narrowing and `USAGE.md` carries an `Upgrading:` note.
- **Network egress is not provider-scoped.** The policy is `default_egress:
  deny` plus a blanket `destination: { group: "public" }` allow, identical in
  all five goldens, so a `codex` guest can still *reach* `api.anthropic.com`; it
  simply has no token and no substitution entry, so every request 401s. That is
  the correct design — capture gating is the control — recorded so nobody reads
  "provisions `{openai}`" as "cannot talk to Anthropic".
- **A zero-provisioning launch is newly reachable** (a declared `shell` with
  `tools = []`) and boots with **no TLS overlay**: `Plan::apply_to` returns the
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
- **`layer` and `persist` are untouched** ([#84](https://github.com/gregwebs/agent-vm/issues/84),
  [#83](https://github.com/gregwebs/agent-vm/issues/83)).

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
   that repo's code. The file-scoped rule closes that path.
10. **Read `"*"` as the declaring file's *full* declared set, retained across
    the merge** (so the built-in `shell` always closes over
    `default-tools.toml`'s four agents even when a user config replaces them).
    Rejected: it needs the pre-merge tier vectors retained and the built-ins
    re-parsed at resolution time, and it makes the fallback shell provision
    credentials for verbs not in the catalog. It is the natural first fallback if
    the chosen reading proves too narrow in practice; the change is confined to
    `resolve_provisioning` plus two tests.
