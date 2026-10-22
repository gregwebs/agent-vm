# User-owned configured mounts

Status: Accepted design. Not implemented.

Mount declarations and named **mount sets** belong only to user configuration;
project configuration cannot declare or select them, including through empty
mount fields or tables. Optional **default mounts**
apply to every launch. A tool's mounts follow its transitive `tools` references,
including `shell`'s wildcard; `--no-config-mounts` suppresses all configuration-
selected mounts but preserves explicit CLI selections.

To prevent a project from activating user mounts indirectly, `tools` references
will be scoped to their configuration tier, for credentials and persistence as
well as mounts. The shared launch-verb catalog and whole-definition user-wins
merge remain. Tool references resolve within their own tier before launch verbs
are merged: a project tool may reference its tier's `pi` even when a user `pi`
hides that project's launch verb. Hidden definitions remain available to their
own tier's references. This changes [ADR-0017](0017-tool-declared-provisioning.md),
which resolves explicit tool references through the merged catalog and permits
cross-tier references.

A `mounts` list accepts direct mount specifications and mount-set names;
`[mount_sets]` declares the named lists. Top-level `mounts` selects defaults,
while tool-level `mounts` selects that tool's mounts. `--mount agent` selects
the named set without selecting any tool or credentials. Configured host paths
accept absolute paths and `~/` expansion, not other relative paths or environment
variable expansion. Sets may reference other sets; unknown names and set-reference
cycles are errors. Identical selected mounts are deduplicated; conflicting mounts
at the same guest path are errors, including CLI versus config conflicts.
Parent/child directory mounts remain allowed. Existing mount modes and protection
rules still apply. Missing sources fail only launches selecting them, subject to
existing initialized-fork reuse; unused sets do not require their sources to exist.
A set reference is a bare name: `agent:ro` and other set-level mode modifiers
are refused. Modes belong to the individual path declarations.

`--no-config-mounts` skips configuration-selected mount preparation, not schema,
reference, cycle, or authority validation. Explicit CLI paths and named sets still
apply. Unknown set names never fall back to relative host paths. `~/` expansion
uses the host user's home; guest destinations retain the existing absolute-path
rules. Moving an equivalent declaration from CLI to config must preserve fork
identity: tool names, set names, and configuration provenance do not enter its key.

Mount-bearing user configuration uses the verified-file authority checks of
[ADR-0040](0040-persisted-user-network-authority.md), including when declarations
are empty. The file and immediate parent must satisfy ownership and mode checks;
the file must be regular, singly linked, and not itself a symlink. Existing
accepted gaps in those checks remain; this feature does not strengthen them.

Mount customization does not introduce partial tool overrides or mounts-only
attachments. Full tool definitions remain required, and declaring any tools still
replaces the shipped tool list. Custom catalogs must explicitly declare a shell
referencing their agents if shell should inherit those agents' mounts; the
existing fallback shell does not gain user-tool references.

These choices keep reusable host-filesystem access user-owned rather than
letting a repository request it through either a mount field or a tool edge.
User-wide defaults are deliberate access for every launch, including project
tools. Shell launches may inherit agent mounts; this revises the initial desire
to keep ordinary shells free of those mounts.

```text
User defaults ─────────────────────────┐
Launched tool → tier-local tool closure ├→ expand sets → validate/deduplicate → mount
Explicit CLI paths and sets ───────────┘

--no-config-mounts removes the first two inputs, not the explicit CLI input.
Project tool closures contain no mount declarations.
```

## Example selections

This is a configuration excerpt, not a complete replacement tool catalog. Copy
and retain the desired full definitions from
[`default-tools.toml`](../../crates/agent-vm/src/default-tools.toml), then add:

```toml
# Before any table: optional defaults, including for project tools and shell.
mounts = []

[mount_sets]
agent = [
  "~/.agents/skills:ro",
  "~/.agents",
  "~/.config/github-app:ro",
]

# In the full pi tool definition:
# mounts = ["agent", "~/.pi:fork"]

# In other agent tool definitions:
# mounts = ["agent"]
```

A user-declared shell whose omitted `tools` defaults to `["*"]` inherits the
agent mounts and Pi fork from its own tier. Explicit `--mount agent` selects
only that set, not the Pi fork or any tool's credentials:

```sh
agent-vm pi
agent-vm --mount agent shell
agent-vm --no-config-mounts --mount agent shell
```

The second command still receives shell's configured/inherited mounts; the third
receives only `agent` plus the launcher's ordinary project/state mounts.
`--no-config-mounts` does not disable credential provisioning or persisted paths.
Repeated selection of the same mount, including through several tools, is
deduplicated.
