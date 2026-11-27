# ADR-0079: The declaration is the launch authority

## Status

Accepted for [#749](https://github.com/gregwebs/agent-vm/issues/749). Release:
**0.8.6**. Supersedes
[ADR-0075](0075-explicit-tool-authorization.md) (the `allow_tools` verb list)
and the `allow_tools` halves of
[ADR-0076](0076-sources-tables-trust-and-allow.md);
amends [ADR-0015](0015-config-driven-tools.md),
[ADR-0016](0016-tool-declared-guest-env.md),
[ADR-0017](0017-tool-declared-provisioning.md),
[ADR-0018](0018-machine-checked-boundary-contracts.md) (the fifth authority
trigger is `default_tools`),
[ADR-0022](0022-dsh-tool-layer.md),
[ADR-0039](0039-non-authoritative-tool-network-requests.md),
[ADR-0040](0040-persisted-user-network-authority.md),
[ADR-0046](0046-verified-user-config-mounts.md),
[ADR-0048](0048-named-mount-sets-and-tier-local-tool-references.md),
[ADR-0059](0059-user-tool-requests-as-egress-authority.md),
[ADR-0073](0073-host-managed-project-config.md) and
[ADR-0074](0074-flat-config-sources.md).

## Context

ADR-0075 made `allow_tools` the verb list and called a `[[tools]]` block a
declaration. Two things followed that the stack could not carry:

- Every authority statement lived twice: the block said what a launch would use,
  the list said whether it existed. A declared-but-unlisted tool was inert data,
  so a source could contribute a definition that nothing could launch, and the
  only way to correct a typo in a list was to edit the list.
- A source's declarations were invisible until the *project* named them, while
  the project's own `default_tools` had no way to say which of two same-named
  declarations it meant.

At the same time, `default_tools` (the key that replaces the retired one) had to
answer the one question `allow_tools` never did: what is provisioned
automatically, for the shell and for a direct command? Folding only some facets
over that closure would let a launch carry a credential whose destination it
cannot reach.

## Decision

1. **Every declaration is a launch verb.** `[[tools]]` is authority: the
   declaration in the user, project or a source file activates its own
   `command`, `args`, `interactive_shell`, `env`, `credentials`, `persist`,
   `mounts` and `network_requests`, whether or not another key mentions it. Each
   definition gets one **bare** spelling when it wins the name and, for a user or
   sourced definition, the qualified `<alias>:<tool>` spelling always.

2. **The bare name is resolved, not assumed.** A project declaration (or the
   shipped catalog) outranks a user or sourced one for the bare spelling. Among
   the remaining rank, one claimant takes the bare name; two or more leave it
   **in conflict**, with every candidate still launchable as `<alias>:<tool>` and
   the bare launch refused naming both. So an unqualified verb works whenever the
   name is unique (a sourced tool included) and never guesses when it is not:

   ```text
   config: "<project>": "pi" is declared by user config "<home>" and source repo
   "<repo>"; launch one as "home:pi" or "repo:pi", or rename one definition
   ```

3. **The authority moved from the key to the declaration, and the launch reads
   the verdict.** A tools-only default user config that fails ADR-0040's verified
   read still loads — the load is not where a file that declares no authority
   field is refused — but the measured verdict is carried to
   every definition it declares and **refuses that launch**
   (`an_unverified_user_configs_tool_cannot_launch`). A source is different: its
   read must pass before its bytes are parsed at all, and an unapproved pinned
   source cannot launch until its bytes are approved.

4. **`allow_tools` is retired, refused at every readable site.** Presence alone
   refuses it, after the document parses and the route/pin gates pass and before
   any typed decode, so a malformed value is not reported as a schema error. One
   sentence states the ordered migration — delete the key or set `allow = false`;
   move automatic grants to `default_tools`; settle a two-source name with
   `use_tools`; launch one file's tool as `<alias>:<tool>`; reapprove an edited
   pinned source — and every site prints that same sentence.

5. **`default_tools` grants the effective closure.** A root-only list, accepted
   from the user config, the project config and every allowed source. Its union
   is the project's own list first, then each `allow = true` source's in
   `[[sources]]` order (the user config is the implicit `home` source). A project
   entry resolves **project-local first**, then the project's `use_tools` choice,
   then the one other file that declares the name, and otherwise refuses naming
   both candidates; the user config's own list and a source's list resolve
   **inside that file** and may name only a tool it declares. The grant is one
   closure fold over six facets — providers,
   requested credentials, `persist`, `mounts`, `env` and `network_requests` — so
   the facets cannot disagree about what the grant covers.

6. **`use_tools` settles a bare default, not a verb.** The project config, and
   only the project config, may write `use_tools = ["<alias>:<tool>"]`. Each
   entry picks which declaration a bare `default_tools` entry means; one tool
   name may be chosen once; a choice that names no tool its source declares is a
   config error, whether or not a `default_tools` entry consumes it. The launch
   verb remains the qualified spelling.

   A project `default_tools` entry may also name its source explicitly, as
   `<alias>:<tool>`. That entry resolves against the named source only and
   refuses a source that does not declare the tool; no project-local shadow,
   bare-name rank or `use_tools` choice is consulted. Only the project config
   may write either spelling: a source's own list is bare, because a source
   grants only what it declares.

7. **The wildcard is retired, and so is the shell's implicit one.** `tools =
   ["*"]` is refused with the replacement: write the names, or move automatic
   provisioning to `default_tools`. An omitted list is now `[]` for every tool,
   `shell` included — so omission no longer means "everything in my file".

8. **The shipped catalog is the shell fallback, and nothing else.** Declaring any
   tool still replaces the whole compiled-in catalog (all-or-nothing, not
   per-name). What remains reachable from it is the `shell` affordance: appended
   when no retained definition claims the bare `shell` route, resolved from a
   scope holding only that one shipped definition, so it provisions nothing
   beyond what `default_tools` grants it. Under the compiled-in catalog the
   shipped compatibility list (every shipped definition but `shell`) is that
   grant, and it never becomes an authored contribution. **#750 handover:** that
   compiled-in compatibility list is exactly what #750 removes, so removing it
   must not silently change the executable behind a familiar verb — the shell
   route then depends only on declarations and `default_tools`.

9. **The bare `shell` route belongs to a project entry or that fallback.** A user
   or sourced `shell` keeps only `home:shell`/`repo:shell`, even when it is the
   unique declaration of the name. The affordance is selected by **route**, never
   by name, so approving a source can never replace the normal shell route or
   hand a source the effective default closure.

10. **`env` and `network_requests` fold over the whole closure.** A named tool's
    launch folds the same visited mask the other facets use (`pi` therefore
    inherits `codex`'s `CODEX_HOME`), and the effective `default_tools` grant
    folds over each contributor's closure, not just the roots. A built-in
    contributor's `network_requests` stay report metadata: only a
    configuration-declared contributor makes the grant authoritative egress.

## Alternatives rejected

- **Keep an `allow_tools` allow list.** Two statements of one authority: a
  declaration that nothing lists is inert, so "is this tool real?" depends on a
  second key, a source cannot contribute a launchable definition alone, and the
  parser needs a migration for every list spelling a user may have written.
  Accepting the key as an alias would keep that second authority alive forever.
- **Per-name shipped fallbacks that could satisfy a bare verb.** A repository
  could then declare `pi` and silently inherit the shipped `pi`'s facets, mixing
  one file's definition with definitions it never saw. Declaring any tool
  replaces the catalog; the only shipped definition that crosses into a custom
  catalog is the `shell` affordance, which has a route of its own.
- **Folding `env` and `network_requests` from roots only.** A closure that
  provisions a child's credential but not its env or requests is a launch that
  can hold a destination it cannot reach — V25 asserted exactly that exclusion
  before it was corrected. One visited mask for all six facets is the only rule
  that cannot drift.
- **Selecting the shell affordance by tool name.** A uniquely declared sourced
  `shell` would then take the effective grant, so approving a source could
  replace the user's normal shell and hand the source's process the user's whole
  default closure. Route (bare, non-source) keeps the affordance with the file
  the user launched from.
- **Letting `use_tools` settle the bare launch verb.** A verb list that changes
  which declaration a typed word means makes `agent-vm pi` depend on a second
  file's key; a bare conflict is a refusal, and the qualified spelling is the
  launch.

## Accepted limits and consequences

- **A bare name two files declare is not launchable bare**, and `use_tools` does
  not change that: it settles `default_tools`, so the shell's grant is
  deterministic while the verb needs `<alias>:<tool>` or a rename.
- **An authored list names only tools its file declares**, except a project
  entry, which may fall back to the one other file that declares the name. So
  `default_tools = ["pi"]` in the user config requires that config to declare
  `pi`; it does not reach a source or the shipped catalog.
- **A user or sourced `shell` never receives the effective defaults.** With no
  project or built-in `shell`, `agent-vm shell` is the shipped fallback even
  when the user declared a `shell`; the declared one is `home:shell`. The
  affordance is a route, and a route cannot belong to two files.
- **`default_tools` is not a capability list.** It grants provisioning and
  facets to the shell and to a direct command only when a readable config wrote
  the key; every other launch gets its own closure. A direct command never
  receives the shipped compatibility list, and the shipped list's requests never
  become authority.
- **A disallowed source's `default_tools` is inert**, not an error, exactly like
  its other top-level keys; a `trust = false` source's grant needs its pin
  approved first, and the grant carries the contributor's measured verdict so a
  blocked contributor refuses the shell launch rather than shrinking the grant.
- **Project-local first is a shadow, not a merge.** A project declaration of a
  name is what the project's `default_tools` entry means, even when the user or a
  source also declares it; the other definition stays launchable by its qualified
  spelling.
- **Closure folding is linear in a size-capped input, and that is the bound.**
  The fold is a least fixed point over one visited mask, so every definition is
  visited once and every reference walked once; the input is already capped by
  `MAX_DECLARED_SOURCES` and `MAX_SOURCE_BYTES_TOTAL`, so there is no separate
  work budget, no eager per-tool pruning, and no refusal for a large but
  legitimate chain — 400 tools fold in 0.85 s on the development host. A
  pathological config that is legal under those caps and still slow would be a
  latency defect to measure then, not a reason to refuse real work now. This
  supersedes the earlier plan's per-load edge cap, which would have refused the
  363-tool chain #749 must keep usable.
- **The shipped catalog's `network_requests` remain report-only.** The compiled-in
  definitions are not authority, so a shell launch under the shipped catalog
  grants no egress request from them; only an authored contributor does.
