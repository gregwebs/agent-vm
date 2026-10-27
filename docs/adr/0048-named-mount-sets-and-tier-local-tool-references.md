# ADR-0048: Named mount sets and tier-local tool references

## Status

Accepted design, implemented in part. The named-mount-set half — `[mount_sets]`
and `--mount SET` selection — is implemented and carries native guest-marker
evidence. Tool-level `mounts` fields remain **not implemented**, so this ADR
stays partial.
[ADR-0046](0046-verified-user-config-mounts.md) has since landed the top-level
user `mounts` defaults this design assumed.

**Implemented:**

- **Tier-local tool reference scopes** ([#395](https://github.com/gregwebs/agent-vm/issues/395)):
  tool references resolve within their configuration tier before launch verbs are
  merged, so credentials, named credential requests, tool availability and
  persisted paths all follow one tier-local closure.
- **Named mount sets and `--mount SET` selection** ([#397](https://github.com/gregwebs/agent-vm/issues/397)):
  a user-only `[mount_sets]` table whose bare, exact names the top-level `mounts`
  defaults and `--mount` may select, with nesting, forward references, iterative
  cycle rejection, per-set closure validation at load under a global expansion
  budget (decisions A2/R1 in [USAGE](../../USAGE.md#named-mount-sets-user-config)),
  `--no-config-mounts` withholding the defaults only, and unchanged fork
  identity. Evidence is boot-free — unit, CLI and launch tests — and native: the
  guest-marker rows **CM-S1–S4** passed, with the ten [#394](https://github.com/gregwebs/agent-vm/issues/394)
  rows, on candidate `8e24b2c` against a digest-pinned image, 18/18. See
  [Native evidence](#native-evidence) below.

**Not implemented:** tool-level `mounts`, partial tool overrides, cross-tier
tool references, per-set mode overrides and new mount modes. Every `mounts = [...]`
line *inside a `[[tools]]` table* in the examples below is still future design;
only the top-level `mounts` list and `--mount` select anything.

## Context

Mount declarations and named **mount sets** belong only to user configuration;
project configuration cannot declare or select them, including through empty
mount fields or tables. A tool's mounts follow its transitive `tools`
references, including `shell`'s wildcard; `--no-config-mounts` suppresses all
configuration-selected mounts but preserves explicit CLI selections.

To prevent a project from activating user mounts indirectly, `tools` references
are scoped to their configuration tier, for credentials and persistence as well
as mounts. The shared launch-verb catalog and whole-definition user-wins merge
remain. Tool references resolve within their own tier before launch verbs are
merged: a project tool may reference its tier's `pi` even when a user `pi` hides
that project's launch verb. Hidden definitions remain available to their own
tier's references. This amends [ADR-0017](0017-tool-declared-provisioning.md),
which resolved explicit tool references through the merged catalog and permitted
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
existing fallback shell does not gain user-tool references. (The fallback's
reference scope is a singleton holding only the shipped `shell` definition, so
this holds for credentials and persisted paths too — implemented in #395.)

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

### Working example: user defaults and named sets (shipped)

This part is implemented. It is the whole supported surface today: the top-level
defaults list and `--mount NAME`.

```toml
# Before any table: optional defaults, including for project tools and shell.
mounts = ["agent"]

[mount_sets]
agent = [
  "~/.agents/skills:ro",
  "~/.agents",
  "~/.config/github-app:ro",
]
pi-agent = ["agent", "~/.pi:fork"]
```

```sh
agent-vm pi
agent-vm --mount agent shell
agent-vm --no-config-mounts --mount pi-agent shell
```

The second command selects only that set — not the Pi fork and not any tool's
credentials. The third suppresses the defaults and keeps the explicit set: a
launch still receives `pi-agent` plus the launcher's ordinary project/state
mounts, and `--no-config-mounts` disables neither credential provisioning nor
persisted paths. Repeated selection of the same mount, including through several
nested sets, is deduplicated. See
[USAGE](../../USAGE.md#named-mount-sets-user-config) for names, nesting,
validation, the expansion budget and the conflict rules.

### Future design: tool-level mounts (not implemented)

**Design example — no build supports a `mounts` field inside a `[[tools]]`
table.** It is recorded here because the mount half's selector and expansion path
is meant to absorb it without a second resolver, not because it ships.

This is a configuration excerpt, not a complete replacement tool catalog. Copy
and retain the desired full definitions from
[`default-tools.toml`](../../crates/agent-vm/src/default-tools.toml), then add:

```toml
# Future design: a per-tool list, resolved through the tool's tier-local closure.
# In the full pi tool definition:
# mounts = ["agent", "~/.pi:fork"]

# In other agent tool definitions:
# mounts = ["agent"]
```

Once tool-level `mounts` exist, a user-declared shell whose omitted `tools`
defaults to `["*"]` would inherit the agent mounts and Pi fork from its own tier.
Today the same commands show the shipped half of that behaviour: `--mount agent`
selects only that set, and `--no-config-mounts --mount agent` removes the
top-level defaults while keeping the explicit set. Neither changes credential
provisioning or persisted paths, and repeated selection of the same mount across
nested sets is deduplicated.

## Native evidence

The four named-set rows (CM-S1–S4) and the ten #394 rows (CM-N1…N5 with their
host oracles) ran together, on one candidate, and all passed:

| fact | value |
|---|---|
| command | `AGENT_VM_BIN="$PWD/target/macos-dev/bin/agent-vm" AGENT_VM_LIVE_TEST_IMAGE='localhost:32937/agent-vm-base@sha256:dfff451d…' bash script/test/config-mounts-live.sh` |
| candidate | `target/macos-dev/bin/agent-vm`, `agent-vm 0.7.13 (8e24b2cfc57a0c53e434261ccc741d3fd6202a44)` — this ADR's HEAD, self-reported clean, provenance gate passed |
| runtime | the bundle's own `msb 0.7.4` and `../lib/libkrunfw.5.dylib` (not the Homebrew `msb 0.6.8`, which is the wrong runtime for this tree) |
| image | `localhost:32937/agent-vm-base@sha256:dfff451db9182c3c5d30798d65c52e5cf1f21639720cf1988e8f4079a81b15f2` — the local `registry:3`'s own `Docker-Content-Digest` for the arm64 manifest of a byte-identical push of this host's `agent-vm-base:local` (that push's index digest: `sha256:ad149d54…`) |
| rows | **18/18 PASS**, `errors.json` `[]`, every launch with `cleanup_errors: []` and `observation_errors: []` |
| evidence directory | `/tmp/avm-397-native/evidence-run2` (76 files: `summary.tsv`, `totals.json`, `image-pins.json`, `candidate.txt`, `runtime.txt`, `S{1..4}-*`, `owned.jsonl`, `harness.sha256`, …) |

The guest prints the whole expected line, and the driver compares it byte for
byte, so a partial mount cannot pass:

| row | guest-printed line | what it settles |
|---|---|---|
| CM-S1 | `CM-S ro=absent rw=absent fork=absent project=present` | a `[mount_sets]` table with no `mounts` list mounts nothing |
| CM-S2 | `CM-S access ro=seed-ro ro-write=denied rw=wrote fork=guest-fork project=present` | `mounts = ["all-set"]` selects the set's leaves with their declared modes |
| CM-S3 | `CM-S ro=absent rw=absent fork=absent project=present` | `--no-config-mounts` withholds the defaults |
| CM-S4 | `CM-S access ro=seed-ro ro-write=denied rw=wrote fork=guest-fork project=present` | `--no-config-mounts --mount all-set` still selects the named set |

After cleanup, the host oracles confirm what the guest saw: `CM-S-host-ro` —
the read-only tree's digest is unchanged; `CM-S-host-rw` — the host holds
`set-rw`; `CM-S-host-fork` — the host still holds `host-later`, so the fork did
not synchronize; `CM-S-host-fork-identity` — one fork directory with an
unchanged manifest digest before and after, so nothing reseeded.

Two facts about how this evidence was obtained are recorded rather than smoothed
over:

- **A first attempt failed on a harness observation race, not on the product.**
  `script/test/lib/egress-fixtures.py::_catalog_query` reads the private MSB
  catalog every 50 ms and treats a database whose tables are not yet migrated as
  `RuntimeError("private catalog schema mismatch: sandbox")`; the measured window
  on a fresh private state's first launch is ~3.4 ms. The identical command,
  re-run unchanged, passed every row. The failed attempt is retained at
  `/tmp/avm-397-native/evidence`; the flake is a harness candidate ticket, not a
  product defect and not evidence against the feature.
- **The prerequisites earlier reported as blocking were each solvable here, not
  absent.** `vendor/microsandbox/build/agentd` was stale only by mtime (rebuilt
  with `just --unstable build-agentd`; `build/` is gitignored inside the vendored
  submodule), the `--dev` bundle builds, and the digest-pinned image came from a
  local registry, the precedent `script/test/e2e.sh` already sets. The Homebrew
  `msb 0.6.8` on `PATH` is the wrong runtime for this tree and was not used.

What these rows show is bind semantics **observed in a guest**: a selected set's
paths appear with their declared modes, definitions alone mount nothing, the
opt-out removes only the defaults, and an explicit `--mount NAME` still selects.
They do not show general mount safety: a read-only child under a writable parent
still leaves a writable alias through the parent, the ADR-0038/0040 ancestor and
replacement gaps are unchanged, and tool-level `mounts` has no row because it
has no implementation.
