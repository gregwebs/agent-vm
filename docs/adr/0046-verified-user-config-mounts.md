# ADR-0046: Verified user config mounts

## Status

Accepted for [#394](https://github.com/gregwebs/agent-vm/issues/394).
**Reconstructed from that issue**: the approved conversation's working-tree
Markdown was never committed, so this file records the decisions the issue
carries, checked against the implementation that landed. It builds on
[ADR-0040](0040-persisted-user-network-authority.md)'s verified read, extends
[ADR-0038](0038-config-dir-exposure-guard.md)'s exposure guard, and adds rows to
[ADR-0018](0018-machine-checked-boundary-contracts.md). Additive release:
**0.7.4**.

## Context

ADR-0040 made one user-tier field authoritative: `[network]`. A user asked for
the same thing for mounts — defaults that apply to every tool launch, without
repeating `--mount`.

The planting threat is the same shape and **worse in one dimension**. A planted
`[network]` table widens egress for later launches. A planted `mounts` list hands
host files to a guest: the attacker chooses which host directory appears inside
*every project the victim launches afterwards*, with the mode that suits them.
With `:rw` it is a write primitive against the victim's home; with `:ro` it is
disclosure of anything readable by the user — including repositories and
credentials the launch's own project never had access to. The blast radius is
every later project, and the effect is not confined to the network.

So the design constraint is the one ADR-0040 already accepted, applied to a
field whose contents *are filesystem access*:

```text
P1 (untrusted repo) → writable bind on ~/.config/agent-vm      → plant mounts
P1 → symlink ~/.config/agent-vm/config.toml → project-writable target
P1 → hard link to config.toml
        ↓ at the next launch, in project P2
every declared host path is bound into P2's guest
```

| Route | Boundary |
|---|---|
| Writable bind contains the config directory or an ancestor | ADR-0038 exposure guard (unchanged) |
| The final `config.toml` component is a symlink | Read-time refusal, because `mounts` is present |
| Another hard link to `config.toml` | Read-time one-name rule and ADR-0038's launch-time linkcount check |
| Foreign owner, or group/other-writable file or immediate directory | Read-time owner/mode checks |
| Project or built-in tier declares `mounts` | Refused at config load, empty list included |
| Writable ancestor controlled by another local user | Accepted gap, inherited unchanged from ADR-0040 |

## Decision 1: One top-level user-tier list

Only `~/.config/agent-vm/config.toml` accepts a top-level `mounts` array of
strings. The project tier and the built-in catalog refuse the key **including
`mounts = []`**: presence, not contents, is what asks for authority, and an
empty list is the cheapest thing to plant.

This release accepts direct path specifications only. Named mount sets and
per-tool `mounts` fields are out of scope; the schema is one array, so adding
selectors later is an additive field rather than a reinterpretation.

TOML assigns a key to the most recent `[table]` header, and that is a real
hazard here, so the behaviour is characterized rather than left to be
discovered:

| File text | Result |
|---|---|
| `mounts = [...]` before any header | top-level, verified, selected |
| `[network]` then `mounts = [...]` | lands in the network table; refused with `[network]: mounts is not a network setting; a top-level mounts list must be written before the first table header` (`[network]` presence has already asked for verification) |
| `[[tools]]` … then `mounts = [...]` | strict tool schema: the fixed schema-repair paragraph (serde's own text is dropped, because a wrong-type message can echo a value), with the line and column and the "before the first table header" sentence |
| `[tools.env]` with `mounts = "~/private:ro"` | **accepted**: an ordinary environment variable named `mounts`. It is not a mount list and does not ask for authority |
| `[mounts]` (table form) | top-level and present, so verified, then `mounts: must be an array of strings` |

The `[tools.env]` row is deliberately not banned. It cannot be an authority
bypass, because nothing in it reaches the mount planner, and refusing it would
break a legitimate variable name.

## Decision 2: The ADR-0040 verified read, one gate per file

`mounts` is authority-bearing exactly like `[network]`, so it reuses ADR-0040's
read: one `O_NOFOLLOW` open supplies both the bytes and the descriptor `fstat`
facts, and a present authority field must show a regular file, reached directly,
with one hard link, owned by the effective user, not group/other-writable, in an
immediate directory owned by that user and not group/other-writable.

The decision was extracted, not copied. `config_authority::verify` is the only
producer of the `AuthorizedConfig` token, and every authority-bearing parser
takes that token as an argument, so a second, laxer read cannot appear without
contradicting the module. `authority_required` decides **whether the check runs
at all**, from presence alone:

```text
authority_required({network, mounts}) == (network || mounts)
```

One gate per file, not one per field: a file declaring both `[network]` and
`mounts` is verified once, and the refusal names the fields that are present.

What is deliberately **not** claimed, unchanged from ADR-0040:

- mode `0600` is not required (`0644` is fine; group/other-*writable* is not);
- an immediate parent directory that is itself a symlink is followed — only the
  file's own final component is refused;
- ancestors, ACLs, replacement races and a nested host mount alias below an
  existing bind root are not checked.

A tools/image-only symlinked config keeps working; adding `mounts` to it stops
working until the link is replaced with the file itself, after reviewing its
contents.

## Decision 3: Host spelling is HOME text, and it is preserved

The declaration grammar is `--mount`'s: `HOST[:GUEST][:MODE]...`, the same modes
(`ro`, `rw`, `fork`, `follow-links`, fork-only `exclude=REL`), the same
guest-path rules (absolute, not `/`, no `..`, `:`, `;`, `,` or control bytes),
and the same downstream checks.

Only `HOST` gains one form:

| Config text | Accepted | `source_spelling` |
|---|---|---|
| `~/ref` | yes | `$HOME` bytes + `/ref` |
| `~/` | yes | `$HOME` + `/` |
| `/abs/$HOME/x` | yes, literally | `/abs/$HOME/x` |
| `/abs/ref/` | yes | unchanged, trailing `/` kept |
| `~`, `~user/x`, `rel`, `./x`, `$HOME/x`, `${HOME}/x` | **no** | — |

`~/` is replaced by the `$HOME` **text**, byte for byte, which is exactly what an
unquoted `--mount ~/ref` expands to in `bash`/`zsh`. That is why a config entry
and the equivalent CLI entry are the *same* declaration: identical
`source_spelling` means the same `same_declaration` verdict and the same
`fork_id`, so one fork serves both. A `$HOME` ending in `/` therefore produces
`//`, as the shell does.

Nothing canonicalizes the spelling. `source_spelling` is identity, manifest text
and diagnostic text; live-bind sources are canonicalized later for the bind
alone, as they are for `--mount`. Rewriting it here would silently give a config
entry a different fork from the CLI entry it means to match.

## Decision 4: One selection seam, one claim rule, no override

A launch has two declaration sources: the verified user config's `mounts`
(file order), then argv `--mount` (argv order). `mount_selection::select` is the
only place that decides which sources a launch asks for. It performs no I/O:
whether a selected source exists is a launch-time question, which is what lets an
unselected declaration name a missing path without blocking a launch, `doctor`
or `--help`.

The claim rule is the one `--mount` already had (`claim_decision`), now
adjudicating across sources:

| Same normalized guest path | Outcome |
|---|---|
| identical declarations (spelling, host, `ro`, `follow`, `fork`, exclusions) | merged, first origin kept |
| different declarations | **refused**, naming both origins |
| different guest paths (including parent and child) | distinct claims, both prepared |

There is no last-wins and no CLI-override mode. A differing pair is refused
whatever its sources — config/config at load, config/CLI and CLI/CLI at launch —
so a repository cannot replace the user's declaration by declaring the same
guest path. Guest spellings are normalized before the comparison
(`/g//./x` is `/g/x`); host spellings are not, so `~/ref` and `~/ref/` at one
guest path conflict exactly as two such `--mount` arguments do today. The seam is
one function and a typed request list: nothing is pre-built for named mount sets
or per-tool selections, and both can be added as further sources to the same
claim.

## Decision 5: `--no-config-mounts` suppresses selection only

`--no-config-mounts` is a launch option, so it precedes the route
(`agent-vm --no-config-mounts shell`); after the tool verb it is a forwarded
tool argument. It disables automatic mount selection and preparation, and
nothing else:

- explicit `--mount` is still parsed, claimed and prepared;
- credentials, `persist` paths, agent-vm's own project/state/home mounts,
  protected-file protections and `[network]` authority are unchanged;
- every load-time check still runs — a broken or untrusted `mounts` config fails
  the launch before the flag can be consulted, because that failure is a
  `config::load` error;
- it is a usage error on a built-in verb, like every other launch option.

Without a config `mounts` the flag is a no-op and prints nothing.

## Decision 6: Preflight boundaries

Two boundaries, and the split is what makes the flag safe:

| Check | Where | Relative to effects |
|---|---|---|
| `mounts` presence → verified read | `config::load` → `config_authority::verify` | before credential capture, runtime identity and all of `run::launch` |
| `mounts` schema, entry grammar, `~/` expansion, guest normalization, intra-config claim | `config::load` (`config_mounts`) | same; no mount-source access |
| project/built-in `mounts` refusal | `config::load` | same |
| argv `--mount` grammar | `mount_selection::select` | unchanged position (after credential capture and runtime identity) |
| config-vs-CLI claim, core collision, Pi/config-directory protections, source kind, file read-write rule, follow-links, fork preflight, `validate_plan` | `mount::prepare` | before fork publication and all launch state |
| persisted guest-HOME collision | `mount::prepare`, after `validate_plan` | **moved here** so it precedes `prepare_forks` |

The last row is a correction the review found, not new behaviour: the check used
to run in `run.rs` *after* `prepare` returned, so a `persist` path shadowed by a
mount could be refused only once a fork had already been published. It now runs
inside `prepare` over the complete normalized core + explicit + followed
destinations, for config **and** CLI declarations, with its message bytes and its
unwrapped error unchanged.

## Trusted versus proved

[ADR-0018](0018-machine-checked-boundary-contracts.md) records the new and moved
decisions as contracts: `config_authority::authority_refusal` (moved and renamed,
body unchanged), `authority_required`, `mount::host_spelling`,
`mount::declarations_equivalent` and `claim_decision`, and
`mount_selection::config_mounts_selected`. What stays trusted is the usual shell:
the `O_NOFOLLOW`/`fstat` measurement, `$HOME` capture, `str`/`Path` splitting and
formatting, `normalize_guest`, `same_declaration`'s field reads, notices, and all
filesystem, sandbox and runtime behaviour. Neither the proofs nor the boot-free
tests establish that a VM enforces a bind mode; only the native CM rows do, run
per [CONTRIBUTING](../../CONTRIBUTING.md#config-mounts-live-check).

## Accepted gaps

- **Every-project exposure is the feature.** A config mount reaches repositories
  you have not read, which is why `:ro`/`:fork` are preferred and why the
  verified-file rule exists at all. There is no per-project opt-out besides
  `--no-config-mounts` on that launch.
- **Repo-scan parity.** A mounted root's git remotes widen the GitHub allow-list
  for that launch exactly as `--mount`'s do. That is deliberate consistency, and
  it also means a config mount contributes to the allow-list of every project.
- **Parent and ancestor assumptions** are ADR-0040's, unchanged: the immediate
  parent is checked by path after the read, ancestors are not, ACLs are not, and
  the check is meaningful only under the stable-route assumption. ADR-0038 still
  refuses the exposing launch.
- **No mount-source inspection at load.** A config can name a path that does not
  exist; the launch that selects it fails, an opt-out launch does not.
- `setup`'s verification guest ignores config mounts (as it ignores `[network]`
  grants, #303), and `image refresh` boots no guest.

## Alternatives rejected or deferred

- **Last-wins or CLI-overrides-config.** Rejected: a silent override is exactly
  how an ambient declaration loses its meaning without a word, and it would let a
  config entry appear to work while an argv entry replaced it. Refusing names
  both origins instead.
- **Verify every user config.** Rejected for ADR-0040's reason: it breaks the
  tools/image-only dotfile symlink that is a supported setup today. Presence of
  `mounts` is the trigger.
- **Environment expansion (`$HOME/x`, `${HOME}/x`).** Rejected: a config file
  with variable interpolation has an implicit evaluation context, and its bytes
  would no longer match the shell-expanded CLI spelling that fork identity
  depends on.
- **Canonicalize the host path.** Rejected: it changes `source_spelling`, which
  is fork identity, and would make a config entry and its equivalent `--mount`
  two different forks.
- **Per-tool `mounts` or named sets now.** Deferred: the spec explicitly scopes
  them out, and selection is a seam so they can be added without a second claim
  rule.
- **A positional ban on `mounts` keys** (refuse the *file* if `mounts` appears
  under any table). Rejected: `[tools.env]` may legitimately declare a variable
  named `mounts`, and the table-scoped failures above are already diagnosed by
  the schema and the `[network]` key check with actionable text.

## Verification

The verified-file policy, the presence-not-contents rule, the `~/` spelling, the
claim rule and the selection decision are pinned by unit tables, integration
tests through the real CLI and prepared sandbox volumes, and mutation controls
(`config-mounts-*`); the authority kernels carry ADR-0018 contracts. Native
enforcement is the CM row set in
[CONTRIBUTING](../../CONTRIBUTING.md#config-mounts-live-check); boot-free
fake-`msb` runs are never counted as that evidence.
