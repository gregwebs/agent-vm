# ADR-0075: Explicit tool authorization (`allow_tools`)

## Status

Accepted for [#735](https://github.com/gregwebs/agent-vm/issues/735), the third of
seven stacked children of
[#732](https://github.com/gregwebs/agent-vm/issues/732). Amends
[ADR-0018](0018-machine-checked-boundary-contracts.md) (the proved-kernel list
keeps one egress-prefix claim, and the grammar re-entry now serves an authorized
tool's requests),
[ADR-0036](0036-default-deny-launch-egress.md) (the default-deny boundary moves
to *authorization*, not launch),
[ADR-0039](0039-non-authoritative-tool-network-requests.md) (the unmet report now
belongs to the compiled-in defaults alone),
[ADR-0040](0040-persisted-user-network-authority.md) (a fifth authority trigger),
[ADR-0046](0046-verified-user-config-mounts.md) and
[ADR-0048](0048-named-mount-sets-and-tier-local-tool-references.md) (a tool's
`mounts` is one facet, authorized not tier-bound),
[ADR-0059](0059-user-tool-requests-as-egress-authority.md) (`tool:NAME` removed),
and [ADR-0074](0074-flat-config-sources.md) (an authorized source definition
outranks the `:trust` verb). Bumps the workspace version to **0.8.2** inside the
unreleased 0.8.x line.

## Context

A `[[tools]]` block *was* a launch verb. Three consequences:

- A `[[tools]]` block in a project or sourced file was refused outright, so a team
  could not share a tool definition (ADR-0074 added the read but not the verb).
- A tool's own `network_requests` were metadata: `agent-vm` printed what the
  launch did *not* grant, and the user had to repeat the same names in
  `[network] allow_egress` or as `tool:NAME` (ADR-0059).
- A tool's `mounts` was user-tier authority, refused by presence in both non-user
  tiers — a field-level rule, not a capability-level one.

Four constraints shape the answer:

- **Declaring is not authorizing.** Reading a repository's file must not change
  what a launch runs. Only a file the user writes may do that.
- **One trigger per authority.** ADR-0040's verified-read policy must remain the
  single gate for anything authority-bearing, and it must be *presence*-based so
  a crafted file cannot slip a field past it by making the value invalid.
- **ADR-0036's boundary is a design statement, not an accident.** A compiled-in
  default must not become real egress just because it names a hostname.
- **The removal must be clean.** `tool:NAME` was the only way to convert a tool's
  requests into allowances. If authorizing a tool converts them instead, the
  reference form has no remaining job and must go, not linger as a second path.

## Decision 1: `allow_tools` is the verb list, and it is a parser of its own

A top-level `allow_tools = ["…"]` decides which `[[tools]]` declarations become
launch verbs. It is parsed by a pure module (`config_allow_tools.rs`) with no
filesystem access, `:` is refused in `[[tools]]` names so `<alias>:<name>` is
unambiguous, wildcards are refused, and every diagnostic is value-safe
(`config: "<file>": allow_tools[N]: …`, never echoing the entry).

Two entry forms: unqualified (`<name>`) resolves against **this file's** own
`[[tools]]`; qualified (`<alias>:<name>`) is project-only and resolves against the
file bound to `<alias>`.

```text
[[tools]] declarations ─────┐
  user · project · sourced  │
                            ├─ allow_tools ─→ verbs, in authorization order
:trust file's own list ─────┘                        │
                                                     ▼
         command · args · interactive_shell · env · persist · credentials
                       · mounts · network_requests → tcp://HOST:PORT

An unauthorized declaration is inert data: no verb, no mounts, no grants.
```

`allow_tools` joins `config::TOP_LEVEL_FIELDS`, so both set tables refuse a set
named `allow_tools`.

## Decision 2: `:trust` inheritance, and the project outranks the `:trust` verb

A `:trust` file's own `allow_tools` is inherited automatically. The project
config's authorization *overrides* an inherited verb in place (same position,
same order), because the project is the more specific declaration — the same
precedence ADR-0074 Decision 5 gives the project image. An overridden definition
stays resolvable inside its own file, so the trusted file's other tools still
reference their own sibling. Two different origins claiming one verb inside the
project's own `allow_tools` is a hard error.

## Decision 3: compiled-in defaults keep ADR-0036, and `uses_defaults` is exact

`uses_defaults` is true iff no tier declares a tool *and* no tier declares
`allow_tools`. Declaring `[[tools]]` without `allow_tools` (or `allow_tools = []`)
authorizes nothing and registers only the synthesized `shell` fallback. A
compiled-in default's `network_requests` stay non-authoritative metadata under
default-deny.

## Decision 4: `allow_tools` is ADR-0040's fifth trigger, by presence

`AuthorityTriggers` grows to `{ network, mounts, mount_sets, egress_sets,
allow_tools }`, and `authority_required` gains the operand (Verus-proved, with a
32-row truth table). Presence, not contents: `allow_tools = []` and
`allow_tools = 123` both require the verified read, so a symlinked,
group-writable or hard-linked user config that declares the field is refused
before its value is even type-checked.

The `:trust` file's list reaches `authorize_tools` only through a token demanding
constructor, so a lost presence measurement is a load refusal
(`allow_tools: authority was not measured`) instead of silent inheritance.

**Separate verdict for cross-file authorization.** A tools-only dotfile symlink
declares none of the five triggers and loads through ADR-0040's compatibility
rule. The project's `allow_tools = ["home:x"]` therefore needs *that file's*
verdict: `ReferenceTrust::require_for_trusted_tool()` reads the stored
measurement of the same read and attributes a refusal to the selected definition
(`AuthoritySubject::TrustedTool`), not to a list the file may not have.

## Decision 5: authorizing a tool activates every one of its fields

Launching an authorized tool activates its `command`, `args`, `interactive_shell`,
`env`, `persist`, `credentials`, `mounts` and `network_requests` — including from a
non-`:trust` source. There is no per-field authorization and no partial
activation: an entry is either a verb or inert data.

`[mounts]` consequences:

- A project or sourced tool's `mounts` is **legal and inert** until authorized; it
  is validated (syntax, per-tool conflicts) with zero host I/O and charged to the
  load's one counter. The compiled-in defaults are the only tier that may not
  carry one, because a shipped definition is not something a launch can authorize.
- One `MountExpansionWork` spans the whole load — project, each source, the user
  file — and is then *moved* into catalog construction. No tier, adapter or
  catalog build mints a counter of its own.
- `MountOrigin::UserTool` becomes `MountOrigin::Tool`, and a launch's mount sources
  may be two files (the defaults file and the tool's declaring file).

## Decision 6: an authorized tool's `network_requests` are real egress

`ToolEgress` has exactly two cases, named so a call site cannot grant without
knowing which it is in:

- **`Authorized`** (an `allow_tools` entry, or `:trust` inheritance): the tool's own
  requests expand (through `egress_reference::expand`, preserving ADR-0018's
  grammar re-entry) into exact `tcp://HOST:PORT` hostname allowances in this
  launch's configured authority, attributed per hostname with `via: <tool>`,
  rendered as a `(tool <name>)` notice tag, and listed by `access egress` as
  `authorized tool`.
- **`UnmetOnly`** (a compiled-in default): non-authoritative, and the only case
  that prints ADR-0039's unmet report.

A tool's requests remain its **own**: `tools = ["*"]` does not fold a sibling's
requests in, so authorizing `shell` cannot grant another tool's destinations.

## Decision 7: `tool:NAME` is removed from every egress grammar

With Decision 6 there is nothing left for it to do. `tool:NAME`, its `Target`,
`Bound::Tool`, `EgressNamespace.requests`, `tool_expansion` and the tool-only
`EntryError` variants are deleted. `set:` is the only egress reference.

The removal is a **breaking config change**: a persisted `tool:codex` entry now
fails in `Allowance::parse` (`port must be a decimal number 1-65535`), and a
numeric `tool:443` reverts to the literal hostname `tcp://tool:443`.
`USAGE.md` carries the migration note.

## Decision 8: the closure of a sourced tool must be authorized too

A tool authorized from a non-`:trust` file does not implicitly authorize the
tools its own `tools = [...]` reaches — explicit, `["*"]`, a declared `shell`'s
omitted wildcard, or transitively. Every member must be listed. Exact
`DefinitionId`s, so a same-named authorized tool in another file never satisfies
an edge. The refusal names the launching tool and file, the unauthorized
referent, and the one-entry fix.

## Consequences

- A repository can share tool definitions, and a launch still only runs what a
  file the user writes authorizes.
- A tool's declared destinations are granted on launch without a second
  declaration, and `tool:NAME` no longer exists to be written by mistake.
- **A `:` in a tool name is now a load error.** A `[[tools]] name` containing
  one is refused with `name must not contain ':' (':' separates a source alias
  from a tool name)`, because `<alias>:<name>` has to be unambiguous. A config
  that declared such a name and loaded before this release now fails at load;
  rename the tool.
- **A tool's ported request widens every other bare grant.** Each request is its
  own exact `tcp://HOST:PORT`, so the tool's own names are never widened — but
  its ports join the launch's intercepted ports, so a `HOST:8443` request puts
  every bare hostname grant from a flag or the persisted table on 8443 as well.
- One verified-read trigger and one mount-visit counter, so the cost of a crafted
  file is bounded by one policy and one budget.
- `--help`, `doctor` and `tools print` speak of *authorized* tools; `tools print`
  output is inert until the reader adds the `allow_tools` line its own header
  names.

## Accepted gaps

- **Until [#736](https://github.com/gregwebs/agent-vm/issues/736)**, authorizing
  `repo:<tool>` delegates that definition's fields — `mounts` and
  `network_requests` included — to an *unpinned* repository file. The closure rule
  and the read seam are structured so pinning tightens them without rework.
- **`[mount_sets]` / `[egress_sets]` in a sourced or project file, `set:<alias>:NAME`
  and `./` mount paths** arrive with
  [#738](https://github.com/gregwebs/agent-vm/issues/738). A declared tool's
  `mounts` in those tiers accepts absolute and `~/` paths only.
- **Multi-`:trust` sourcing** (ADR-0074 G5) is unchanged: `:trust` is the user
  config only.
- **ADR-0040's ancestor gap** is unchanged: the immediate directory is measured,
  not every ancestor.

## Alternatives rejected

- **Keep `[[tools]]` as an implicit verb and add a deny list.** Inverts the
  trust boundary: reading a file would grant, and no deny list can enumerate what
  an unread file will declare.
- **Authorize per field** (`allow_tools`, `allow_mounts`, …). Multiplies the
  triggers and the diagnostics, and makes "is this tool real?" depend on which
  field you asked about.
- **Keep `tool:NAME` as a synonym for an authorized tool's egress.** Two paths to
  the same grant, one of them persisting in `[network]` where it outlives the
  authorization it depended on.
- **Treat a project/sourced tool's `mounts` as authority (the pre-#735 rule).**
  Made a declaration file unable to state a tool's own facets, and forced a
  per-field refusal order instead of one authorization decision.
- **Refuse `allow_tools` in the user config when the project also declares it.**
  A list is additive by nature; refusal would make the two tiers unable to
  co-exist at all.
