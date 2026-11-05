# ADR-0040: Persisted user network authority

## Status

Accepted for [#305](https://github.com/gregwebs/agent-vm/issues/305), the authority
half of #302 A2. Builds on the shipped [ADR-0038](0038-config-dir-exposure-guard.md)
guard; amends ADR-0036, ADR-0038 and ADR-0018. Additive release: **0.3.2**.

## Context

A guest in project P1 can plant a user-owned `0644` file for project P2. Owner
and mode checks cannot recognize guest authorship. The exposing launch must be
refused, not merely P2's read:

```text
P1 → writable config-directory bind → plant authority → P2 reads
     ↑ ADR-0038 refuses P1
P1 → writable dotfile target ← config.toml symlink → P2 reads
                              ↑ read-time refusal
```

| Route | Boundary |
|---|---|
| Writable bind contains the config directory or an ancestor | Shipped ADR-0038 exposure guard |
| Symlink in the directory route | ADR-0038 resolution walk |
| Another hard link to `config.toml` | Launch-time and read-time one-name rule |
| `config.toml` itself is a symlink into a writable project | Read-time refusal when `[network]` exists |
| `~/.config/agent-vm` (the immediate parent directory) is itself a symlink | Followed: accepted under the stable-route assumption; ADR-0038 still gates guest exposure |
| Foreign owner or group/other-writable file/immediate directory | Read-time owner/mode checks |
| Writable ancestor controlled by another local user | Accepted gap below |

## Decision 1: User-tier schema

Only `~/.config/agent-vm/config.toml` accepts `[network]`. The project and built-in
tiers still refuse it, including an empty table. The four settings are
`allow_internet_egress`, `allow_lan`, `allow_host` (booleans), and `allow_egress`
(an array of strings). Unknown settings fail. Errors name supported settings
and zero-based `network.allow_egress[N]`, never values or unknown keys.

The allowance grammar is `Allowance::parse`: numeric **and hostname** allowances.
This is an interpretation of #305's literal `EgressAllowance::parse`, not use
of that named parser. #302 says protected user configuration can express the
same authority; #306 says it depends on A2 if hostnames are accepted from user
config. The existing hostname grammar and restrictions apply unchanged.
There is no allowance-count cap; the bounded config-file read remains the limit.

## Decision 2: Verified read when authority is present

One `O_NOFOLLOW` open supplies both bytes and descriptor `fstat` facts. On
`ELOOP`, the existing following read supplies bytes tagged `ThroughSymlink`.
TOML is parsed from those bytes, not reopened after verification. Only a
present user `[network]` table invokes authority checks:

1. Immediate parent is a directory, owned by the effective user, not `go-w`.
2. File was reached directly, is regular, owned by that user, not `go-w`, and
   has exactly one hard link.

Directory refusals precede file refusals; file owner precedes mode, then links.
`config_authority::authority_refusal` uses ADR-0038's proved
`authority_file_singly_linked` and its shared spec, not a duplicate link rule.

A symlinked dotfile config **without** `[network]` still works for tools/image.
It cannot carry network authority. To opt in, replace the link with the file
itself, but only after reviewing the `[network]` table: the link target (and so
the bytes) may have been written by a guest or project. A mode or link change
does not establish authorship. Empty `[network]` is verified even though it
grants nothing.

The two symlink cases differ, and deliberately so. A symlink in the **final
component** (`config.toml` itself is a link) is refused: the `O_NOFOLLOW` first
open reports `ELOOP`, bytes are read through the following reader tagged
`ThroughSymlink`, and a present `[network]` is refused. A symlink that **is the
immediate parent directory** (`~/.config/agent-vm` is a link to another
directory) is followed: the final component is still a regular file, and the
parent check resolves by path to a directory that must be owned by the
effective user and not `go-w`. A user-owned, non-`go-w` directory holding a
user-owned, singly-linked `[network]` file is therefore **accepted** under the
stable-route assumption — the same residual as any writable ancestor, and still
gated by ADR-0038 at the exposing launch that could plant the link. Only the
file's own final component is refused by `O_NOFOLLOW`.

## Decision 3: Per-launch resolution

`resolve_grant` proves this precedence independently for each group:

| CLI | User | Effective/source |
|---|---|---|
| `Some(c)` | any | `c`, CLI |
| absent | `Some(u)` | `u`, user config |
| absent | absent | false, default |

In particular, explicit `=false` overrides saved true. Allowances form a
user-first, canonical-value-deduplicated union with CLI allowances; flags do
not subtract saved allowances. No setting is written back.

With a user table, notices name its file, allowance membership (user, CLI or
both), group sources and each DNS contributor. Canonical membership supplies
provenance; it is not an index-aligned parallel list. Without a user table,
legacy notice bytes are unchanged. All-denied and TLS-interception lines grant
nothing and keep their existing text.

## Guard: no new mechanism

ADR-0038 refuses exposing launches unconditionally, even without `[network]`.
Its **Known cost** remains accepted: launches from `$HOME` are refused for
everyone. This change does not soften, duplicate or condition that guard.

## Trusted versus proved

[ADR-0018](0018-machine-checked-boundary-contracts.md) records the two kernels:
`config_authority::authority_refusal` proves acceptance and refusal precedence from
measured facts, sharing ADR-0038's executable and spec one-name rule;
`resolve_grant` proves value and source precedence. Syscalls,
TOML parsing, mode conversion, canonical union, notices and runtime policy
assembly are trusted adapters tested independently. Neither proofs nor
boot-free tests establish native runtime enforcement; only the native
PN4-A/B/PN4c rows do, run per
[CONTRIBUTING](../../CONTRIBUTING.md#persisted-network-live-check).

## Accepted gaps

**Parent and ancestors (A2, stable-route assumption).** The immediate parent is checked by path, after
the read, as a separate observation from the file open. Ancestors are not
checked. The check is meaningful only under the stable-route assumption. With
a writable ancestor, another local user can redirect the route to a user-owned
directory holding a user-owned, singly linked file; one example is a project
directory a guest wrote into. `credentials.yaml` has the same gap. ADR-0038
keeps guests out of ancestors, within #321/#322.

- ACLs are not checked. Credentials-file hard links (#319), nested mount
  aliases (#321), runtime replacement races (#322), and a third home directory
  remain outside this change.
- `setup`'s optional verification guest ignores `[network]` (#303). #389 removes
  the temporary acquisition guest: `image refresh` uses native registry access,
  not a guest or the tool-launch network policy.
- Saved hostnames with a selected ambient host HTTP proxy refuse every launch
  until the proxy or saved hostname is removed. `--allow-*=false` does not
  clear `allow_egress`; adding a numeric allowance does not bypass the refusal,
  which keys on any hostname authority. See [USAGE](../../USAGE.md#persisted-grants-user-config).
- Native macOS evidence does not certify Linux/KVM; capability admission and
  combined platform evidence remain #308.

## Alternatives rejected or deferred

- A guard keyed on `[network]`: a guest can add it; ADR-0038 already rejected it.
- Verifying every user config: breaks tools/image-only dotfile symlinks.
- Following then verifying in a second read: bytes and facts can differ.
- Typed serde `RawNetwork`: dependency errors can echo values.
- CLI wins only when true: cannot turn saved true off.
- **Descriptor-anchored parent** (`open(parent, O_DIRECTORY)`, `fstat`, then
  `openat(..., O_NOFOLLOW)`): rejected because it does not shrink the residual
  threat set, **not** because of cost. It could run only for authority, and
  Linux `O_PATH` needs no read permission. Actors who can make the separate
  observations disagree can write an ancestor; they can also redirect the
  anchored parent open to a directory passing the checks.
- **Ancestor walk**: deferred. An OpenSSH `StrictModes`-style user/root-owned,
  non-`go-w` check of every resolved directory would shrink the residual. #305
  asks for the immediate parent; credentials should change with it. Root-owned
  and sticky directories, symlink routes and macOS `/private` need policy
  decisions that can refuse working setups. Propose this as follow-up work,
  without filing an issue unless requested.

## Verification

The independent authority/source oracles, properties, literal policy expectations,
CLI tests and mutation controls exercise the trusted seam. The host-only
companion cannot certify guest authorship or enforcement. Native commands and
PN row requirements are in [CONTRIBUTING](../../CONTRIBUTING.md#persisted-network-live-check).

## Amendment: grouped hostname notices

Decision 3's "without a user table, legacy notice bytes are unchanged" still
holds for the all-denied line, the TLS-interception line, numeric grants, group
grants and DNS lines. It no longer holds for hostname grants: names with identical
effective ports and hostname sources now share one `allowing TLS to …` line,
followed once by `hostname allowances are TLS-only (SNI and DNS verified; no
plain HTTP)`. Provenance is unchanged — canonical hostname membership across all
of a name's entries, the `(persisted grants)` / `(--allow-egress)` /
`(persisted grants and --allow-egress)` tags, and no tag without a user table —
and the notices describe exactly the same rules. The rendering contract is
[USAGE](../../USAGE.md#hostname-allowance-grammar).

## Amendment: mounts share the verified read (ADR-0046)

#394 adds a second authority-bearing user field, a top-level `mounts` list
([ADR-0046](0046-verified-user-config-mounts.md)), and it uses Decision 2's read
unchanged. Nothing in this ADR's threat model, rule sequence or accepted gaps
changes; what changes is the name of the gate and the set of fields that reach
it.

- The decision moved to `config_authority::authority_refusal` — `user_network`'s
  copy is gone — with its contract and executable body unchanged.
  `protected_config_dir::authority_file_singly_linked`'s one-name rule is still
  *shared*, in both its executable and spec form, not duplicated.
- `config_authority::verify` is now the only producer of the authorized-read
  token, and every authority-bearing parser takes that token. A new proved
  kernel decides whether the check runs at all:
  `authority_required({network, mounts}) == (network || mounts)`. Presence, not
  contents, is still the rule — for both fields.
- Decision 2's "only a present user `[network]` table invokes authority checks"
  now reads "a present `[network]` **or** `mounts`", and one file declaring both
  is verified once.
- Diagnostics name the field(s) that made the file authority-bearing:
  `[network]`, `mounts`, or `[network] and mounts`. The per-variant sentences are
  templated from those three subjects; the `[network]`-only bytes are unchanged,
  pinned by the existing tests and the PN4B/PN5 joins.
- The gaps are unchanged, and now cover mounts too: mode `0600` is still not
  required, an immediate parent that is a symlink is still followed, and
  ancestors, ACLs and replacement races are still accepted.

## Amendment: `[mount_sets]` joins the shared gate (ADR-0048, #397)

#397 adds a third authority-bearing user field, the `[mount_sets]` table
([ADR-0048](0048-named-mount-sets-and-tier-local-tool-references.md)), and it
reaches Decision 2's read unchanged. Nothing in this ADR's threat model, rule
sequence or accepted gaps changes; the fields that reach the gate, and the
sentences that name them, grow from two to three.

- `authority_required({network, mounts, mount_sets}) ==
  (network || mounts || mount_sets)` — the same kernel, extended from a two-field
  to a three-field disjunction and still total over every combination.
- **#396 aggregate:** the `mounts` fact is itself a disjunction of the two places
  a user file may declare a mount selection,
  `mounts == (top_level_mounts || tool_mounts)`, decided by one OR kernel before
  any mount text is parsed. The trigger count stays three and `authority_required`
  is unchanged; only what counts as "a mounts field" widened. A refusal caused by
  a full tool's field with no top-level list is prefixed with that field's numeric
  site (`tools[N].mounts: `), and a file whose only authority field is
  `[network]` prints its previous bytes unchanged. One verified read still covers
  the whole file, and the accepted trust gaps above are unchanged.
- Decision 2's "a present user `[network]` table invokes authority checks" now
  reads "a present `[network]` **or** `mounts` **or** `[mount_sets]`", and one file
  declaring any subset is verified once.
- Diagnostics name the field(s) that made the file authority-bearing, over all
  seven nonempty combinations: `[network]`, `mounts`, `[mount_sets]`,
  `[network] and mounts`, `[network] and [mount_sets]`,
  `mounts and [mount_sets]`, `[network], mounts and [mount_sets]`. The
  `[network]`-only and `mounts`-only bytes are unchanged, pinned by whole-sentence
  literals in `config_authority`'s test oracle.
- A file that declares `mount_sets` without `mounts` is authority-bearing *and*
  verifies, so "a symlinked config without `mounts` still works" is not a
  statement that such a file is safe — the aside names the field that is absent.
- The gaps are unchanged and now cover mount sets too: mode `0600` is not
  required, an immediate parent that is a symlink is followed, and ancestors,
  ACLs and replacement races remain accepted.

## Amendment: CLI egress references keep the verified read's verdict (ADR-0059, #506)

`--allow-egress tool:NAME` is a grant decided from the user file, but it is only
known **after** argv is parsed, which is after `config::load` has dropped its
`VerifiedRead`. Re-reading or re-measuring at launch would decide from a second
observation, which Decision 2 rejects, and would run after the credential
preflight. Pre-scanning argv would duplicate clap's parsing. So the read is
measured whether or not an authority-bearing field is present, and its verdict is
kept.

- **Measurement runs on every user read.** `verify` no longer returns before
  measuring. The cost is one extra `stat` of the immediate parent per user-config
  load.
- **Load-time refusal is still decided by presence, and only by presence.**
  `authorized` is `Some` iff an authority-bearing field is present *and* the file
  passed, exactly as before, and a refusal is returned only in that case. A
  tools/image-only config therefore keeps loading — and keeping working through a
  dotfile symlink — no matter what its facts are.
- **The verdict is returned beside the token.** `Verification { authorized,
  references }`, where `ReferenceTrust` owns the read's path and its
  `Result<(), UntrustedConfig>`. Private fields, minted only by `verify`; the
  test constructor is `#[cfg(test)]`. `config::read_file_tier` stores it on the
  user tier's `TierContents` and `ConfigReport` exposes it as
  `user_tool_requests()`, which the launch carries to `network::Plan::from_args`.
- **A new subject.** `AuthoritySubject::EgressReference`, with label
  `an egress reference`, object `[[tools]] network_requests`, and `without`
  `an egress reference`. `AuthoritySubject::of` never returns it: a flag is not a
  file field, so a presence trigger cannot be about one. The sentences come from
  the unchanged `write_refusal`, so a symlinked tools-only file tells the reader:
  *an egress reference requires config.toml to be a regular file, but it is
  reached through a symbolic link; … review the [[tools]] network_requests before
  trusting the file (a symlinked config without an egress reference still
  works)*.
- **One contract change in a test.** `verify_measures_nothing_without_triggers`
  becomes `verify_never_refuses_without_triggers_and_keeps_the_reference_verdict`:
  a world-writable directory that refuses still yields `Ok`, `authorized == None`,
  and a retained `Refused { DirWritable, EgressReference }`. That is the new
  contract, and it is the whole compatibility claim.

| Association | Enforced by |
|---|---|
| A *successful* verdict exists only if `authority_refusal` passed on some read | **Types**: private fields; only `verify` mints one |
| The verdict's file is the path of the read it measured | **Types**: set from `read.path()` inside `verify` |
| A namespace holds only tools whose origin file equals the verdict's file | **Runtime filter** in `egress_reference::UserToolRequests::new` |
| The tools came from the **same read** (bytes) as the verdict (facts) | **Single construction site only**: `read_file_tier`'s user arm builds both from one `VerifiedRead` and drops it. Two reads of one path carry equal `PathBuf`s, so types cannot tell them apart. This rests on review and on the `UserToolRequests::new` doc comment. |
| Resolution never re-measures or re-reads | **Structure plus tests.** `UserToolRequests` is owned data and `egress_reference::resolve` does no I/O; the load-then-change tests fail if anyone re-measures or re-reads. Three facts are changed after the load, one per test: the reference's own path (symlink replaced by a regular `0600` file), the file's bytes (requests rewritten), and the directory's mode **in both directions** (private→world-writable must keep resolving; world-writable→private must keep refusing). A re-measure of only the directory is what the last one exists to catch. |

**Persisted references cannot bypass trust.** They exist only inside `[network]`,
which triggers verification: a file that fails is refused at load, and a file that
passes carries `verdict: Ok(())`. `resolve` still runs the check — one path, no
special case.

## Amendment: `[egress_sets]` joins the shared gate (#511)

#511 adds a fourth authority-bearing user field, the `[egress_sets]` table, and it
reaches Decision 2's read unchanged. Nothing in this ADR's threat model, rule
sequence or accepted gaps changes; the fields that reach the gate, and the
sentences that name them, grow from three to four.

- `authority_required({network, mounts, mount_sets, egress_sets}) ==
  (network || mounts || mount_sets || egress_sets)` — the same kernel, extended to
  four fields and still total over all sixteen combinations (fifteen true).
- Decision 2's rule now reads "a present `[network]`, `mounts`, `[mount_sets]`
  **or** `[egress_sets]`", and one file declaring any subset is verified once.
  Presence is still the whole trigger — the *field is written*, empty table,
  wrong type or populated table alike, which is what makes the verified read run.
  What follows that read depends on the file, and the two outcomes are different:
  an **unsafe** file is refused before any schema parsing, so a symlinked empty
  `[egress_sets]` table and a symlinked `egress_sets = 7` both fail with the
  `[egress_sets]` authority sentence; a **trusted** file proceeds to its own
  schema errors, so `egress_sets = 7` reports
  `egress_sets: must be a table of named arrays of egress allowances and
  references` and a trusted empty table is accepted (declaring a set grants
  nothing). Presence triggers verification; it does not by itself refuse.
- **The sentences are data now, and the old bytes are pinned.** Sixteen subjects
  is three tables of sixteen arms plus sixteen literal rows, and a subject that
  folded `[egress_sets]` into `[network]` would tell the reader to review a table
  the file lacks — the exact failure #397's amendment forbids. `AuthoritySubject`
  therefore holds the four presence bits and composes its three slots from one
  fixed phrase table (`[network]`, `mounts`, `[mount_sets]`, `[egress_sets]`, in
  that order) with the grammar the slots already shared: `a`, `a and b`,
  `a, b and c`, `a, b, c and d`, and `or` in the "without" aside. Every
  pre-#511 sentence is byte-identical, pinned by whole-sentence literals for the
  `[network]`-only subject and by fifteen literal slot rows; the eight new
  subjects have their own literal rows, never composed from the phrase table.
- The unreachable all-false input is **normalized** to the `[network]`-only
  subject rather than copied, so no slot can render empty. #511 is the first
  change that made the empty set representable at all, so this row is new.
- The refusal order is unchanged and extended: `[network]`, `mounts`,
  `[mount_sets]`, `[egress_sets]`, then the first tool's `mounts`.
- The gaps are unchanged and now cover egress sets too: mode `0600` is not
  required, an immediate parent that is a symlink is followed, and ancestors,
  ACLs and replacement races remain accepted.
