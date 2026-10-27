# ADR-0048: Named mount sets and tier-local tool references

## Status

Accepted design, **implemented**. All three halves have landed: tier-local tool
reference scopes (#395), named mount sets and `--mount SET` selection (#397), and
full **user** tool `mounts` lists inherited through that same tier-local closure
(#396, the design sketched below as future work).
[ADR-0046](0046-verified-user-config-mounts.md) supplies the verified read and the
top-level defaults all of this builds on.

Implementation is one thing; native evidence is another. Two recorded runs cover
this ADR: the #397 rows (CM-S1–S4, with the ten #394 rows), and a later run of the
#396 rows (CM-T1…T11 with their host oracles) over its own synthetic topology.
The two runs share no row and neither is rewritten to claim the other's scope; see
[Native evidence](#native-evidence).

**Implemented:**

- **Tier-local tool reference scopes** ([#395](https://github.com/gregwebs/agent-vm/issues/395)):
  tool references resolve within their configuration tier before launch verbs are
  merged, so credentials, named credential requests, tool availability and
  persisted paths all follow one tier-local closure.
- **Full user tool `mounts` inherited through the tier-local closure**
  ([#396](https://github.com/gregwebs/agent-vm/issues/396)): a full user
  `[[tools]]` may declare `mounts`; a launch selects its own list plus those of
  every definition in its transitive same-file `tools` closure, through the one
  selector and the one compiled set-closure interface the defaults list uses, and
  under one continued leaf-visit budget that also covers catalog construction.
  Project and built-in tool fields are refused by presence; `--no-config-mounts`
  suppresses every automatic input; a declared `shell`'s omitted `tools` inherits
  those mounts deliberately. Retained lists hold shared leaf handles, so a
  catalog entry inherits one handle per leaf rather than a payload. Canonical
  guidance: [USAGE](../../USAGE.md#tool-specific-config-mounts).
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

**Not implemented, deliberately:** partial tool overrides, mounts-only
attachments to shipped tools, cross-tier tool references, project or built-in
mount authority of any kind, per-set mode/guest/exclusion overrides and new mount
modes. Inheritance covers mounts only — not `env`, `network_requests` or
required-provider facts.

**Resource limit, accepted:** this design bounds mount-leaf expansion and the
retained lists during load and catalog construction. It does **not** bound
launch-time preparation adjudication: the quadratic phases in `mount::prepare`
(`validate_plan`'s dedup and candidate-kind scans, followed-target lookup and
fork reconciliation) remain, and they pre-exist for an equivalent top-level
`mounts` list. #396 indexed only the guest-path lookup in `mount::claim`, which is
a local improvement certified by an independent vector oracle; the wider
preparation work belongs to the follow-up issue.

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

One supported selection pattern: the top-level defaults list and `--mount NAME`.
A full user `[[tools]]` list is the other, and the two compose.

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

### Tool-level mounts (implemented, #396)

The design sketched here originally as future work shipped as drawn: a per-tool
list resolved through the tool's tier-local closure, absorbed by the same selector
and expansion path rather than by a second resolver.

The canonical, complete replacement catalog is in
[USAGE → Tool-specific config mounts](../../USAGE.md#tool-specific-config-mounts);
it retains every shipped definition and adds one `[mount_sets]` entry plus the
per-tool selections. A user-declared shell whose omitted `tools` defaults to
`["*"]` now inherits the agent mounts and Pi fork from its own tier — that is the
deliberate revision recorded in #396, and the reason USAGE warns about it.
`tools = []` stops the inheritance but keeps the shell's own list and the
user-wide defaults, and the built-in fallback inherits nothing. `--mount agent`
selects only that set, and `--no-config-mounts --mount agent` removes every
automatic input while keeping the explicit set. Neither changes credential
provisioning or persisted paths, and repeated selection of the same mount across
tools or nested sets is deduplicated by the shared claim.

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
replacement gaps are unchanged, and tool-level `mounts` has no row in the #397
run — it was not implemented then. Its own rows are CM-T1…T11 with the
CM-T9-control positive control, recorded separately; that run is never rewritten
to claim it tested tool mounts.

### #396 tool-mount rows (CM-T1…T11 plus CM-T9-control), a separate later run

The tool-mount rows are their own topology — a Pi home whose protected files are
sentinels, an agent parent with a read-only child, a declared shell's own leaf and
a user-wide default — and their own recorded runs: the same 46 rows passed twice,
first on a pre-squash commit and then on the squashed commit that shipped. The
pre-squash receipt comes first and is retained unchanged:

| fact | value |
|---|---|
| command | `AGENT_VM_BIN="$PWD/target/macos-dev/bin/agent-vm" AGENT_VM_LIVE_TEST_IMAGE='localhost:33917/agent-vm-base@sha256:ad149d54…' AGENT_VM_CM_EVIDENCE="$(mktemp -d /tmp/avm-396-native/evidence-run.XXXXXX)" bash script/test/config-mounts-live.sh` |
| candidate | `target/macos-dev/bin/agent-vm`, `agent-vm 0.7.15 (7bccc2b72dc1699d68e2dc4ec2d8f8f1ed468b7a)` — the run's HEAD, provenance gate `provenance: clean binary matches source HEAD`, empty tracked status, SHA-256 `9055706406cbd367cdb909c7bbdf1808c859a1026b03b319179652d7aad064fd` |
| runtime | the bundle's own `msb 0.7.4` (SHA-256 `82269f92170d07de8d873cc1f024f32b764c2bda0a8f81cecba38a77ebda7b2d`) and `../lib/libkrunfw.5.dylib` (SHA-256 `ad7263ef96aa2bbb4d5bb2dcedf19303ad718c662ae53aa967af5d728084f8bd`), built by `./script/build/macos.sh --dev` from this commit (23 s) |
| image | `localhost:33917/agent-vm-base@sha256:ad149d5419a79dd17d2157f92e62aaa996b148f0453fb12b4eb3bc2c391e1b90` — the digit-for-digit reference the earlier pass used. This host's `agent-vm-base:local` tag was rebuilt at 09:26; the run therefore pushed the *older image content* (still present locally) into the local `registry:2`, which returned exactly that digest, so the base image is the same bytes as the recorded pass and the only variable is the candidate. The launch's own pin records the reference with the arm64 manifest digest `sha256:dfff451db9182c3c5d30798d65c52e5cf1f21639720cf1988e8f4079a81b15f2` |
| rows | **46/46 PASS** — 18 #394/#397 observations (10 guest rows — six CM-N and four CM-S — and 8 host oracles — four CM-N and four CM-S) plus 28 #396 observations: 14 guest rows (CM-T1…T7, CM-T8 on both routes, CM-T9, CM-T9-control, CM-T10, CM-T11 on both routes) and the same 14 host oracles; `totals.json` `{"rows": 46, "passed": 46, "failed": []}`, `errors.json` `[]`, 201 owned-launch records with zero cleanup and zero observation errors |
| evidence directory | `/tmp/avm-396-native/evidence-run.oLuXzv` (`summary.tsv` SHA-256 `36403f372824ae23f8f97ee9b98ed504526cba09e5058ac02738b465793c28fd`, `totals.json` `2fb7fd8b8901346cdfa9109e2d03050ef8b4a4bbdcdd129a116fd7bafdc814a2`, plus `image-pins.json`, `candidate.txt`, `runtime.txt`, `provenance-check.txt`, `owned.jsonl`, per-row config/command/before/after receipts and logs) |
| superseded | two earlier 45/45 passes, on `0.7.15 (5778128b…)` at `evidence-run.ZPqZ6U` and `0.7.15 (e564b4d6…)` at `evidence-run.auic4J`, used the *first* tool-mount fixture set. Its oracle was not discriminating — Pi declared the set it was meant to inherit, CM-T8's shell had `tools = []`, and CM-T9's catalog had no tool named `agent` while never probing the `readonly` leaf — so those receipts establish exactly the observations they recorded and not the wider prose. They are retained unchanged. |
| not a pass | `evidence-run.Qh8fa1` holds one receipt, `rejected: AGENT_VM_BIN must be an absolute path to an executable`. It recorded no row and no `totals.json`; it is a different failure from the earlier firmware-build disk-space block (`/tmp/avm-396/build3.log`), which also recorded no row |
| platform | macOS arm64. Linux/amd64 native coverage remains outstanding and is not implied |

The branch was then squashed onto `origin/main` `241e27a` as `8cdfe71`, and the
same driver was run again on that commit. That run is the shipped receipt; the
table above was not rewritten to become it. Both are kept, and every attempt had
its own `mktemp -d` evidence directory:

| fact | value |
|---|---|
| command | `AGENT_VM_BIN="$PWD/target/macos-dev/bin/agent-vm" AGENT_VM_LIVE_TEST_IMAGE='127.0.0.1:33931/agent-vm-base@sha256:ad149d54…' AGENT_VM_CM_EVIDENCE="$(mktemp -d /tmp/avm-396-native/evidence-run.XXXXXX)" bash script/test/config-mounts-live.sh` |
| candidate | `target/macos-dev/bin/agent-vm`, `agent-vm 0.7.15 (8cdfe71afa45de40a6386abd1ce682c071c6fa7c)` — the squashed commit, rebuilt with `./script/build/macos.sh --dev` (13 s) because the existing dev bundle still reported the previous head; `agent-vm --version` was checked against `8cdfe71…` before the run, provenance gate `provenance: clean binary matches source HEAD`, empty tracked status, SHA-256 `fabd8d3ebd31b6328339d4d3fd4f0c561e413d68e78fd9df447323dc4dfc3547` |
| runtime | the bundle's own `msb 0.7.4` (SHA-256 `82269f92170d07de8d873cc1f024f32b764c2bda0a8f81cecba38a77ebda7b2d`) and `../lib/libkrunfw.5.dylib` (SHA-256 `ad7263ef96aa2bbb4d5bb2dcedf19303ad718c662ae53aa967af5d728084f8bd`) — by SHA-256 the same two binaries as the receipt above, not the Homebrew `msb` on `PATH` |
| image | `127.0.0.1:33931/agent-vm-base@sha256:ad149d5419a79dd17d2157f92e62aaa996b148f0453fb12b4eb3bc2c391e1b90` — a fresh digest-pinned `registry:3` on port 33931 whose `Docker-Content-Digest` for the pushed bytes came back digit for digit, so this is the same image content as the receipt above; the launch's own pin records the reference with the arm64 manifest digest `sha256:dfff451db9182c3c5d30798d65c52e5cf1f21639720cf1988e8f4079a81b15f2` |
| rows | **46/46 PASS**, the same 46 rows in the same order as the receipt above — 18 #394/#397 observations (10 guest, 8 host oracles) plus 28 #396 observations (14 guest, 14 host oracles) — so the arithmetic holds for both: `totals.json` `{"rows": 46, "passed": 46, "failed": []}`, `errors.json` `[]`, 201 owned-launch records with zero cleanup and zero observation errors |
| evidence directory | `/tmp/avm-396-native/evidence-run.v5BZpU` (`summary.tsv` SHA-256 `6074915b45b2890f8cbaf70eb6b1ca951da3381888724621c2049bdfd983ab21`, `totals.json` `2fb7fd8b8901346cdfa9109e2d03050ef8b4a4bbdcdd129a116fd7bafdc814a2`, plus `image-pins.json`, `candidate.txt`, `runtime.txt`, `provenance-check.txt`, `owned.jsonl`, per-row config/command/before/after receipts and logs) |
| what distinguishes the two | the shipped commit is a squash: `8cdfe71` sits directly on `origin/main` `241e27a`, while the receipt above ran on `7bccc2b`, a pre-squash commit of the same branch work. Their trees differ in four files — `USAGE.md`, this ADR, `crates/agent-vm/tests/config_mounts.rs` and `script/test/config-mounts-contract.sh` — and in none that the live driver reads: `script/test/config-mounts-live.sh`, `script/test/lib/config-mounts.py` and `script/test/fixtures/config-mounts/guest-cm-probe.sh` hash identically in both runs' `harness.sha256`, whose single differing line is the boot-free companion (`2c2cd73a…` → `509f44f2…`) that this driver never executes. The candidate identity differs because the commit is compiled into the binary |
| platform | macOS arm64, as above. Linux/amd64 native coverage remains outstanding and is not implied |

Every row is one whole guest-printed line compared byte for byte, and the probe
renders its row even when a read or write fails, so a partial mount cannot pass:

| row | guest-printed line | what it settles |
|---|---|---|
| CM-T1 | `CM-T1 agent=absent skills=absent readonly=absent pi=absent project=present` | a tool that declares and references nothing mounts nothing, and no Pi fork exists |
| CM-T2 | `CM-T2 agent=agent-seed agent-write=wrote skills=skills-seed skills-write=denied readonly=readonly-seed readonly-write=denied pi=absent` | a tool's own `mounts = ["agent"]` gives a writable parent and two read-only trees |
| CM-T3 | `CM-T3 agent=agent-seed skills=skills-seed readonly=readonly-seed pi=pi-seed pi-write=wrote auth=absent models=absent guest-file=wrote` | the same topology *inherited* through `tools` — `pi` declares the fork only, so `agent` can arrive no other way — plus a `:fork` that reads the seed, keeps the guest's write, omits `auth.json`/`models.json`, and takes a guest-only file |
| CM-T4 | `CM-T4 pi=pi-guest guest-file=present` | after a host-only source change to `pi-host-later`, the inherited fork still reads `pi-guest` and its own file |
| CM-T5 | `CM-T5 agent=agent-seed skills=skills-seed ro-write=denied pi=pi-guest project=present` | a declared `shell`'s omitted `tools` wildcard inherits the fork and the agent topology |
| CM-T6 | `CM-T6 agent=absent skills=absent readonly=absent pi=absent shell-own=shell-own shell-own-write=denied default=default default-write=denied` | `tools = []` drops inheritance while the shell's own list and the user-wide default stay, both read-only |
| CM-T7 | `CM-T7 agent=absent skills=absent pi=absent shell-own=absent default=default default-write=denied project=present` | with no declared shell the built-in fallback references no user tool but still receives the user-wide default |
| CM-T8 | `CM-T8 agent=absent skills=absent readonly=absent pi=absent shell-own=absent default=absent project=present` | `--no-config-mounts` removes defaults, own list and inheritance on **both** a tool and the declared shell; the shell is a *wildcard* one, so its inherited facet is non-empty before the opt-out suppresses it |
| CM-T9 | `CM-T9 agent=agent-seed agent-write=wrote skills=skills-seed ro-write=denied readonly=readonly-seed readonly-write=denied pi=absent default=absent agent-tool=absent agent-tool-state=absent` | `--no-config-mounts --mount agent` returns exactly the explicit set with its modes — both read-only leaves probed — and selecting a set provisions no tool: the catalog has a tool named `agent`, and its own leaf and `persist` link stay absent |
| CM-T9-control | `CM-T9-control agent-tool=agent-tool-seed agent-tool-state=present` | the positive control for the two observables above: launching the same-named tool itself shows its own leaf and its persist link, so their absence under `--mount agent` is a measurement |
| CM-T10 | `CM-T10 pi=pi-guest guest-file=present agent=absent` | an absolute `--mount …:fork` of the same source reuses the inherited fork's committed copy |
| CM-T11 | `CM-T11 pi=pi-guest guest-file=present agent=absent` | the same declaration selected as a top-level default and through a nested set reseeds nothing |

The host oracles read only after each launch's cleanup proved absence:
`CM-T1-host []` (no Pi-lineage fork), `CM-T2-host` (the parent write reached the
host, both read-only digests unchanged), `CM-T3-host` (`pi-seed` still on the
host, protected files `unchanged`, guest-only file `absent` on the host, the
parent write present) with `CM-T3-host-identity` exactly one Pi fork,
`CM-T4-host`/`CM-T10-host`/`CM-T11-host-*` (identity unchanged, host source still
`pi-host-later`, so no reseed and no host→fork sync), and the closing
`CM-T-host-ro`/`CM-T-host-protected`/`CM-T-host-fork-identity`. Fork identity is
compared **within the Pi lineage** — manifests whose guest destination ends in
`/.pi` — so the #394/#397 fork in the same state root neither weakens nor is
weakened by this run.

What these rows do not show: general isolation from a writable ancestor (the
read-only child's assertions are about operations at that mounted destination;
this ADR's alias/rename caveat stands), that a project can acquire mount
authority (unit and CLI refusals own that), or preparation cost. The boot-free
budget and storage rows own **load/catalog expansion and retention only**; the
quadratic phases in `mount::prepare` are the follow-up issue's, and no receipt
here is a preparation-scaling measurement.

Recording the prerequisite honestly: the first attempt at this run was blocked
before any row — `./script/build/macos.sh --dev` failed in
`build_firmware_if_missing` with `Transaction failed: Rpm transaction failed. -
installing package java-25-openjdk-headless-… needs 109MB more space on the /
filesystem`, because the Docker VM's filesystem was 97% full. That attempt is
retained at `/tmp/avm-396/build3.log`. The operator then reclaimed space (45%,
51.2 GB free); the identical build succeeded (`/tmp/avm-396/build4.log`,
`EXIT:0`, 1006 s) and the pre-squash receipt above is from the resulting bundle.
No row was recorded from the blocked attempt, and the squashed-commit run was
rebuilt later from committed source in 13 s with the firmware already cached, so
that block did not recur.
