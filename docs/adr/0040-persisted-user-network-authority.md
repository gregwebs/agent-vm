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
`network_authority_refusal` uses ADR-0038's proved
`authority_file_singly_linked`, not a duplicate link rule.

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
`network_authority_refusal` proves acceptance and refusal precedence from
measured facts; `resolve_grant` proves value and source precedence. Syscalls,
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
- `setup`/`pull` temporary guests ignore `[network]` (#303).
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
