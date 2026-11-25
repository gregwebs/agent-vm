# ADR-0076: `[[sources]]` tables with independent `trust` and `allow`

## Status

Accepted for [#748](https://github.com/gregwebs/agent-vm/issues/748), the fourth of
ten stacked children of [#732](https://github.com/gregwebs/agent-vm/issues/732).
**Supersedes** [ADR-0074](0074-flat-config-sources.md) Decisions 1, 3 and 4 (the
`"<alias>[:trust] <path>"` string syntax, `:trust` being the user config only,
and every other source being declarations-only) and amends its Decisions 2, 5
and 7. Amends [ADR-0035](0035-consume-user-owned-boot-images.md) (the fallback
image is now the first `allow = true` source, not the user config),
[ADR-0068](0068-active-image-set.md),
[ADR-0073](0073-host-managed-project-config.md) (the project config may now
declare its own top-level `mounts` and `[network]`),
[ADR-0075](0075-explicit-tool-authorization.md) (`allow_tools` is inherited from
every `allow = true` source and inert in an `allow = false` one), and
[ADR-0038](0038-config-dir-exposure-guard.md)'s guest-write coverage is
extended from the one user config to every trusted source route. Bumps the workspace version to **0.8.3** inside the unreleased 0.8.x line.

Amended by [ADR-0077](0077-pinned-config-sources.md): every `trust = false`
source is now content-pinned before decoding, regardless of `allow`.

## Context

ADR-0074 gave the project config a flat `sources = ["<alias>[:trust] <path>"]`
list with one overloaded qualifier:

- `:trust` did two unrelated things. It selected the strict, ADR-0040-verified
  read **and** exempted the file from #736's content pinning. Since only the user
  config could carry it, a team file outside the repository could not be trusted
  at all, and a trusted file gained no way to say which of its top-level keys the
  project wanted.
- Everything else was "declarations only", so a file that *did* declare `mounts`,
  `[network]` or `allow_tools` was refused by presence. That made those keys
  unsafe to leave in a shared file, even when the project simply wanted to select
  one tool from it.
- The syntax was a string with an embedded space and a `:` qualifier, which TOML
  could not validate and the reader had to split by hand.

Pinning (#736), set selectors (#738) and `default_tools` (#749) all need a source
entry that says, per file and explicitly, *how it is read* and *what the project
does with its top-level keys*.

## Decision 1: pure-TOML `[[sources]]` tables, string syntax refused

```toml
# Top-level keys MUST precede the first [[sources]] or [table] header.
image = "repo:image"
allow_tools = ["repo:lint"]
mounts = ["~/notes:/notes:ro"]

[[sources]]
name = "home"
path = "~/.config/agent-vm/config.toml"
trust = true
allow = true

[[sources]]
name = "repo"
path = "./conf/agent-vm.toml"
```

`name` (`[a-z][a-z0-9_-]{0,31}`, unique) and `path` are required; `trust` and
`allow` are optional booleans defaulting to `false`. Unknown keys, duplicate
keys, a non-table element, a missing or malformed field, a duplicate name, a
duplicate lexical path, and a lexical self-source each fail with a value-free,
actionable diagnostic that names the escaped project config path and the
zero-based `sources[N]`.

The old string form is **deliberately broken**: every string element reports the
`[[sources]]` migration instead of being parsed. A silent upgrade would have to
guess whether a former `:trust` source also wanted `allow`, and guessing wrong is
either an ambient-authority grant or a silently inert file.

An omitted `sources` key still means the single implicit entry
`{ name = "home", path = "~/.config/agent-vm/config.toml", trust = true,
allow = true }`; `sources = []` sources nothing.

The list is **bounded**: at most 32 entries, and at most 4 MiB read from all of
them together. Both are cross-entry bounds rather than per-file limits, which no
single file's own size check can enforce: without them a sub-megabyte project
config could declare thousands of sources and turn every launch into thousands
of opens, and duplicate detection would be quadratic in the entry count. The
count is validated with one lookup per entry, and both refusals are value-free.

Because a `[[sources]]` table is a table, top-level keys written after it are
scoped into it by TOML. That is reported as a scoping hint naming the canonical
field, so `image` written below the first `[[sources]]` cannot silently vanish.

## Decision 2: `trust` is the read path and the pinning bypass

`trust = true` means "this file's pathname was chosen by the user, outside
anything a repository controls, and its bytes need not be pinned":

1. **Any out-of-checkout path is eligible.** ADR-0074's user-config-only
   restriction is gone.
2. **The whole route is walked first.** From `/`, with a synchronized directory
   descriptor stack: every component is opened `O_DIRECTORY | O_NOFOLLOW` and
   judged from the descriptor's own `fstat`; `..` pops the stack; an absolute
   symlink target resets it. A component inside the active checkout **or any
   enclosing Git worktree** (up to `/`, no `$HOME/.git` exception), an untrusted
   or writable ancestor, a foreign-owned link, and a symlink hop overrun are all
   refused before any byte is read. A final symlink whose target resolves inside
   the checkout is refused with the route wording.
3. **The read is verified unconditionally** through the proved
   `authority_refusal` kernel (`verify_trusted_source_at`): owner, mode, link
   count and the immediate directory, whatever the file declares — an image-only
   or tools-only file is measured too. Passing mints both the adoption token and
   a `ReferenceTrust`.
4. **The default user config keeps its own branch.** `~/.config/agent-vm/config.toml`
   is recognised **lexically** (never by canonical equality, which would upgrade a
   differently spelled path into default-user privilege) and keeps ADR-0040's
   presence-triggered verification and dotfile symlink compatibility.
5. **Content pinning is exempt**, which is exactly what `#736` needs to not do for
   this file.

`trust = false` is a descriptor-anchored source read: its final symlink is
resolved by that route walk only while the route remains admissible, and in-repo
paths such as `./conf/agent-vm.toml` are legal. Its exact bounded bytes are
content-pinned before parsing under [ADR-0077](0077-pinned-config-sources.md).

## Decision 3: `allow` decides adoption, and inert is not refused

`trust` and `allow` are independent; all four combinations are legal.

| `trust` | `allow` | read | top-level `image`, `mounts`, `[network]`, `allow_tools` |
|---|---|---|---|
| `true` | `true` | route check + verified read | adopted |
| `true` | `false` | route check + verified read | inert |
| `false` | `true` | bounded read, then content pin | adopted after approval |
| `false` | `false` | bounded read, then content pin | inert after approval |

- **Inert is not refused.** An `allow = false` source's `mounts`, `[network]` and
  `allow_tools` are recorded by presence (value-free) for `doctor` and dropped
  before any typed validation, so a malformed inert value (`network = 42`) cannot
  fail a load it grants nothing in. Its `image` is validated (an explicit
  `image = "NAME:image"` still works) but never becomes the automatic fallback,
  and is reported inert unless the project selects it.
- **Every `trust = false` source is refused before decoding until its bytes are
  approved**, whether `allow` is true or false. [ADR-0077](0077-pinned-config-sources.md)
  supplies the hash-checking policy. The check runs on the exact bounded bytes
  before UTF-8 or TOML decoding, so an unapproved file cannot reach a validator,
  inert recorder or adoption. Its approval token binds the project, lexical path
  and exact bytes, so a second read can never inherit an approval.

## Decision 4: multi-source adoption order

The project config always outranks what it sourced; among sources, `[[sources]]`
declaration order is the priority order.

- **`image`** — first `allow = true` source in order that declares one is the
  fallback, so appending a source at the bottom never hijacks an earlier one's
  boot image. `image = "NAME:image"` selects any declared source's image
  regardless of `trust`/`allow`. A non-default-user-config fallback is minted as
  `ImageSource::AllowedSource` (an explicit configured tier; it never writes a
  project default), while the default user config keeps `ImageSource::UserConfig`
  so existing output is unchanged.
- **`mounts`** — each `allow = true` source's list in order, then the project
  config's, merged through the same claim rule `--mount` uses: identical
  declarations at one guest path deduplicate first-seen, differing ones are a
  hard load error naming both files and both sites. Every contributing file is
  kept for `--no-config-mounts` and notices.
- **`[network]`** — `allow_egress` unions in the same order (deduplicated by
  canonical value, `set:` attributions preserved); group booleans OR-union across
  the sources and an explicit project boolean overrides them. `set:NAME` stays
  the default user config's alone until #738.
- **`allow_tools`** — Step A inherits each `allow = true` source's list in
  order; Step B applies the project's list, where repeating an inherited target
  is idempotent and naming a different definition for an inherited verb replaces
  it in place (the losing definition stays in the arena for its own file's
  `tools` references and is excluded from the authorized set); Step C refuses a
  verb inherited from two sources with no project override, naming both and
  advising `"<alias>:<verb>"` or `allow = false`; Step D authorizes exactly the
  winning definitions. The #735 closure rule applies to `trust = false` sources
  only — a verified trusted source is as authoritative as the user config.

The compiled-in defaults apply iff no `allow = true` source and neither the user
nor the project config declares a tool **and** none of them writes `allow_tools`.

## Decision 5: the project config adopts its own authority fields

ADR-0073's verified project config now accepts top-level `mounts`
(`AbsoluteOrHome` entries) and `[network]` (literal allowances and group
booleans) through its own verification — it is the root of the project's trust,
so nothing further gates them. `[mount_sets]`/`[egress_sets]` remain refused by
presence in the project config and every non-default source until #738, which
owns `set:` selectors and multi-source namespaces.

The compiled-in `default-tools.toml` still refuses `[network]`, `mounts`,
`[mount_sets]`, `[egress_sets]`, a tool's `mounts`, `allow_tools` and `sources` by
presence.

## Decision 6: a source that is really the project config is refused by identity

Every source read compares the opened descriptor's `(dev, ino)` — including after
a followed symlink and for hard links — against the verified project config's
identity, before content approval or parsing, and reports
`the project config cannot source itself`. The lexical check in
`config_sources::DeclaredSources::parse` stays as the fast, spelling-level
diagnostic; flat sourcing stays as the independent backstop for genuinely
different files.

## Decision 7: diagnostics

- `doctor` renders each source as
  `name path (found, N tools) [trust=…, allow=…; pin=approved sha256:<hex>; inert: …]`
  when a source has an approved pin, with the inert list in the fixed order
  `image, mounts, [network], allow_tools` and value-free. Implicit sourcing
  prints no `sources:` block at all, so pre-#748 output is byte-identical.
- `doctor`'s boot-image section keeps the `user:`/`project:` rows, reports the
  winning fallback (`selected fallback; allow = true`), a project override, an
  earlier source's override, and each inert `allow = false` image with the exact
  sentence that would select it.
- `agent-vm image show` reports `Source: source <alias> (allow = true)` and
  `File: <path>` for a non-user-config fallback.

## Accepted gaps and explicit policies

- **Closed by ADR-0077:** every `trust = false` source is SHA-256-pinned before
  decoding, and an approved `allow = true` source may adopt its fields. The
  `allow = false` case is pinned too, while remaining inert.
- **`CheckoutBoundary` unions every enclosing `.git` worktree up to `/`**, with
  no `$HOME/.git` exception: a file inside a dotfiles repository is
  repository-controlled and is not eligible for a non-default `trust = true`
  source. The isolated `~/.config/agent-vm/config.toml` branch keeps its own
  compatibility. The route enforces the full host-controlled descriptor-stack
  ancestry policy rather than ADR-0040's immediate-directory-and-parent rule.
- **The ADR-0038 guest-write guard now covers every trusted source route**, in
  this project and in every other project's registered sources. Registering one
  is a review step: **quiesce first** — stop any running guest that holds a
  writable bind over the route before you review and add `trust = true`. A
  launch from before the registration cannot be audited retroactively. The
  sibling measurement uses the same symlink-resolving walk as this project's own
  trusted read, so a route reached through an owner-controlled symlink records
  the target's ancestry: a bind over the real target overlaps it, not just a
  bind over the link's spelling.
- **`[mount_sets]` and `[egress_sets]` remain default-user-config-only** until
  #738.
- **`allow_tools` becomes `default_tools` in #749**, which also owns launch-target
  tool authorization; #748 keeps the key isolated in `config_allow_tools` and
  `SourceEntry`.
- **A lexical self-source is caught before any read**, but two spellings of the
  same *different* file (a symlink and its target) are still separate sources;
  identity is only used to refuse the project config itself.

## Consequences

- A shared team file outside the repository can be trusted and adopted by writing
  two booleans, and a file whose top-level keys the project does not want can be
  sourced without stripping them first.
- The `sources` syntax is a breaking config change: string lists are refused with
  a migration error rather than silently reinterpreted.
- Adoption order is now a multi-file, declaration-ordered merge. It is
  deterministic and covered by named tests, because "which file supplied the
  boot image / this mount / this verb" is exactly the question a reader will ask.
- The trusted read path is one route walk and one verified read per trusted
  source, so a project with several trusted sources pays for each of them before
  any of their bytes are decoded.
