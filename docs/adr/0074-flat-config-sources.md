# ADR-0074: Flat config sources

## Status

Accepted for [#734](https://github.com/gregwebs/agent-vm/issues/734), the second
of seven stacked children of
[#732](https://github.com/gregwebs/agent-vm/issues/732). Amends
[ADR-0073](0073-host-managed-project-config.md) (the project config may now
source other files) and [ADR-0035](0035-consume-user-owned-boot-images.md) (the
project image outranks the user image). Amended by nothing yet. Bumps the
workspace version to **0.8.1** inside the unreleased 0.8.x line.

## Context

After [ADR-0073](0073-host-managed-project-config.md) agent-vm reads one
host-managed project config and one user config. A team that wants shared tool
definitions has no way to point a project at a file: committing
`<project>/.agent-vm/config.toml` does nothing, and copying the user's whole
config into the project file would duplicate it per project.

Two constraints shape the answer:

- **A repository must not be able to widen what a launch reads.** After ADR-0073
  the set of files read is decided by files only the user writes.
- **Some of what a project wants to read is authority-bearing.** The user config
  may declare `[network]`, `mounts`, `[mount_sets]` and `[egress_sets]`
  (ADR-0040/0046/0048). A repository file must never be able to.

So the project config names the files, and each entry declares whether it is read
*as the user tier* (`:trust`) or as declarations only.

```text
~/.config/agent-vm/projects/<id>/config.toml      ← only the user writes this
  sources = [
    "home:trust ~/.config/agent-vm/config.toml",  ← read as the user tier
    "repo ./.agent-vm/config.toml",               ← declarations only
  ]
  image = "repo:image"                            ← authorizes the repo's image
```

## Decision 1: `<alias>[:trust] <path>`, resolved lexically

An entry is split at its **first** space into `ALIAS` or `ALIAS:trust`, then the
path. An alias matches `[a-z][a-z0-9_-]{0,31}`, so it is safe to print raw. The
path may not be empty, may not start or end with whitespace and may not contain a
control character.

| Spelling | Resolves to |
|---|---|
| `~/REST` | `$HOME/REST`, using the `$HOME` the project config path was derived from |
| `/ABS` | used as is |
| anything else (`x`, `./x`, `../x`) | the captured `ProjectDir` joined with the spelling |

Resolution is **lexical and never canonicalizes**. `.` components are dropped and
`..` is kept uncollapsed, so `..` is resolved by the OS — through a symlink if the
spelling crosses one — instead of this module silently choosing a different file.
`~` alone and `~user/…` are refused: the only expansion is `~/`.

Entry-set rules: aliases are unique, resolved paths are unique (lexical `Path`
equality), no entry may resolve to the project config's own path, and `:trust` is
accepted only for the user config path (Decision 3). `sources = []` is valid and
sources nothing.

Diagnostics name the project config and `sources[N]` (zero-based) and never echo
the entry text, matching the module's value-safety rule: an alias that fails the
grammar is unvalidated bytes.

## Decision 2: an omitted key means the implicit `home:trust` default

A project config with **no** `sources` key behaves exactly as if it declared
`sources = ["home:trust ~/.config/agent-vm/config.toml"]`, which is what
ADR-0073's two-tier load already did. An explicit list — `sources = []`
included — replaces it, so the user config is read only when a `:trust` entry
names it, and "home is not read" is always something the user wrote.

The alternative — an omitted key meaning "source nothing" — was rejected because
#737's `image set-default` creates a one-line project config when none exists.
Under "nothing", that one line would silently drop the user's whole configuration.

A missing `:trust` file stays **absent**, not an error: a host without
`~/.config/agent-vm/config.toml` is normal. A missing *untrusted* source is an
error, because the user explicitly named it and an empty source would hide a typo.

## Decision 3: `:trust` is the user config, verified by route

`:trust` is accepted only when the resolved path lexically equals the discovered
user config path. That is ADR-0038's guarded file, and the user tier's authority
namespaces (`user_network`, `user_mounts`, `user_tools` for `tool:NAME` /
`set:NAME`) are single-namespace — a second trusted file needs
`set:<alias>:NAME` qualification, which is #738.

Trust is a property of the **route**, not of the path spelling. Both the implicit
entry and an explicit `<alias>:trust ~/.config/agent-vm/config.toml` are read from
the discovered path, never from the entry's spelling, and the read is checked
before any byte is opened:

1. **Parent/ancestor route.** `~/.config` or `~/.config/agent-vm` canonicalized
   inside the active checkout (and not the unaliased `$HOME` layout) refuses the
   launch. The rule is the one `check_store_route` already uses, shared as
   `project_config::resolves_inside_project`.
2. **Final component.** The file is opened with `O_NOFOLLOW`. A symbolic link is
   canonicalized before its target is opened: a dangling or looping link fails
   closed, and a target inside the checkout is refused. An outside-checkout
   dotfile symlink (`~/.config/agent-vm/config.toml -> ~/dotfiles/config.toml`,
   `~/.config/agent-vm -> ~/realcfg`) keeps ADR-0040's behaviour, so existing
   setups keep working **while the working directory is not an ancestor of the
   link target**; authority fields still refuse a `ThroughSymlink` read.

That ancestor test is the accepted limitation of both checks: a stow-style
`~/.config/agent-vm/config.toml -> ~/dotfiles/config.toml` is refused when agent-vm
runs from `$HOME`, because the route check cannot tell it from a checkout alias.
The cost is real — `doctor`, `image show` and the verb list fail to *load*, not
merely fail to boot, where ADR-0038's launch guard used to refuse only the launch —
so U1/U2 name the cause (the working directory is an ancestor of the target) and
the remedy (run from a directory that does not contain it, or replace the link
with a regular file).

Running from `$HOME`, `$HOME/.config` or `/` stays allowed exactly while the
layout is unaliased — the same rule ADR-0073 Decision 3 applies to the project
store. Concurrent host-side directory swaps remain out of scope, as they are for
ADR-0040.

Lexical admission and canonical comparison are deliberately separate:
canonical equality is used **only** for `doctor`'s legacy-notice suppression, so
`~/../home/.config/agent-vm/config.toml` cannot name its way into trust.

## Decision 4: every other source is declarations-only and unpinned

A non-`:trust` source is read through the pre-ADR-0073 project read: the final
symlink is followed (repository files are commonly symlinked) and the read is
bounded. It may add tools and declare an `image`. It may not declare `[network]`,
`mounts`, `[mount_sets]`, `[egress_sets]` or a tool's `mounts` — refused by
presence, in the order the project tier already refuses them, worded "by a source
without `:trust`".

Its tools get `ToolOrigin::Source { alias, file }`: provenance renders as
`source repo <path>`, `doctor` prints `source=sourced:repo:<path>`, and the alias
is the qualifier #735's `allow_tools` will use. Each source is its own
tool-reference scope, exactly like the project file.

**Unpinned until #736.** Nothing measures the bytes, so a branch switch changes a
source's tools and declared image at the next launch. Bounding that with
content-hash pins and approval is #736's job; `read_source_tier` is the seam.

## Decision 5: images are declared and authorized, and the project outranks the user

Any file may **declare** an `image`. The boot image is **authorized** by the
project config, either as its own `OCI_REF` or as `ALIAS:image`, which selects a
declared source's image. The `:trust` source's `image` is the fallback when the
project config sets none. Every unselected untrusted source image is recorded as
**inert** and shown by `doctor` with the line that would select it.

Precedence, first present wins:

```text
--dockerfile > --image > AGENT_VM_IMAGE_TAG
  > project config (OCI_REF, or ALIAS:image)
  > the :trust source's image
  > default slot
```

This **reverses ADR-0035's** `user config image > project config image`, which is
required by the "`:trust` passes its image through when the project sets none"
criterion. The flip is safe because the project file is host-managed (ADR-0073):
ADR-0035's objection to a repository choosing a clone's image was that the
repository chose it, and now the user does — a direct `OCI_REF` outright, and with
`ALIAS:image` the alias, leaving the reference itself delegated (Decision 5).

In the project config **only**, an `image` value shaped exactly `ALIAS:image` is a
selection, whether or not that alias is declared. Falling back to OCI for an
undeclared alias would turn the typo `image = "rpeo:image"` into a pull of
`docker.io/library/rpeo:image`; the error instead tells the user to spell an
image tagged `image` with its registry. In sourced files `image` is always an OCI
reference, as before.

Declaring and authorizing stay distinguishable: `image show` prints
`Source: project config (repo:image)` and `File: <declaring source>`, and
`doctor` prints `REF [repo:image <declaring source>]`. `ImageSource::SourcedConfig`
is never a default-tier source, so it establishes no project default (ADR-0067).

What `ALIAS:image` delegates is the **choice of reference**, not the bytes. ADR-0063
pins the first use of any new OCI reference cache-first, with **no prompt**, and
commits before create, so until #736 pins the sourced file, a branch switch that
repoints the repository's `image` at another registry boots that image at the next
launch. The one thing consent still bounds today is a **moved tag on an
already-pinned reference** (ADR-0063); a different reference is a first pin, not a
changed one. Reviewing a file before sourcing it — as `USAGE.md` says — is
therefore the whole of the boundary until #736.

## Decision 6: a project-side tool collision is an error

Two project-side files (the project config and any untrusted source) may not
declare the same tool name. With one file that could not happen — duplicate names
in one file are rejected — and with N files there is no ordering that would not
invent the precedence #735 is about to redesign with qualified names. The error
names both files.

User-versus-project shadowing is unchanged: the whole user definition wins as the
launch verb, and the loser stays resolvable from its own file (#395). A conflict
warning names the user file and the losing project-side file.

## Decision 7: flat sourcing, `doctor` rows, and the legacy notice

Only the project config may declare `sources`. Any other tier that carries the
key is refused by presence, `sources = []` included — a sourced file cannot source
another file. Within one file the existing error order stands: the verified-read
verdict first, then this refusal, then any authority-field refusal, so a file that
carries both `sources` and `[network]` is reported as the former.

`==> tool configuration` gains a `sources:` block only when the project config
listed entries, renders an unsourced user tier as
`<path> (not sourced by the project config)`, and labels a source's tools
`source=sourced:<alias>:<path>`. `==> boot image` moves
`(overridden by the project image)` to the losing **user** row and prints one
`source <alias>:` row per inert image. With implicit sourcing the section is
byte-identical to ADR-0073's except in the three places where the two tiers can
disagree: the selected image and its override row flip when both declare one, the
project config's error is reported first when both are broken, and U1/U2 refuse a
dotfile layout the working directory is an ancestor of.

`doctor`'s in-repo legacy note is suppressed only when a **successfully loaded,
explicitly listed** source names `<project>/.agent-vm/config.toml` — lexically
first, then by canonical equality when the list is non-empty. Implicit
`home:trust` passes no list, so a legacy entry that happens to be a symlink to
the user config never hides the note.

## Consequences

- A team can keep its tool definitions in the repository and a host-level project
  config can source them with one line, without granting them authority.
- A project can select a repository-declared image. The host-managed project
  config authorizes the selection, but `ALIAS:image` hands the **choice of
  reference** to the sourced file until #736 pins it, and ADR-0063 pins a new
  reference without a prompt. So the host authorizes "this alias" today, not the
  bytes; only a moved tag on an already-pinned reference prompts.
- `sources` becomes a reserved top-level field, and therefore a reserved
  `[mount_sets]` / `[egress_sets]` name (the same rule as `egress_sets` in #511).
- Image precedence changes for a project config that also has a user image: the
  project image now wins. That is a behaviour change inside the unreleased 0.8.x
  line, hence a patch bump.
- Load order changes: the project config is read first, because it decides which
  files are read at all. A configuration with errors in both tiers now reports the
  project's error first.
- One `lstat` and one bounded read per source per launch.

## Accepted gaps

- **G1. Untrusted sources are unpinned.** A branch switch changes their tools and
  declared image at the next launch. They can grant no network, mount, mount-set
  or egress-set authority, and their image, once the project config selects it,
  is pinned by ADR-0063 **without a prompt** — the delegation is the alias, not
  the ref. Content-hash pinning is #736.
- **G2. Source identity is the lexical path.** Two spellings through a symlink are
  not detected as duplicates, and `..` is not collapsed for comparison.
- **G3. The legacy note still prints when the configuration fails to load**, even
  if the file is sourced: `doctor` cannot know the sources of a load that failed.
  The `error:` body names the failing file.
- **G4. With `home` unsourced, a CLI `tool:NAME` / `set:NAME` reports the existing
  "no user config file was found".** The wording is accurate in effect and
  imprecise in cause; #738's selector work owns it.
- **G5. `:trust` is user-config-only.** Generalising it needs per-source guard
  coverage, source-qualified authority namespaces and provenance (#738).
- **G6. A source's tools can request credentials and reuse a familiar verb name.**
  A non-`:trust` source's tools carry the `credentials`/`provisions` requests,
  `env` and `persist` declarations any project-side tool carries, so an unreviewed
  repository file can ask for a credential provider or define `claude` — with any
  command — as the verb the user already types: the shipped defaults give way to
  any project-side tool whenever the user config declares none of its own. Nothing
  here grants authority beyond
  what the tool's own launch already asks for, but the requests are real and
  neither `allow_tools` (#735) nor content pinning (#736) exists yet.

## Alternatives rejected

- **An omitted `sources` key meaning "source nothing".** It breaks #737's
  one-line writer, which would silently drop the user's whole configuration.
- **`:trust` on any path.** ADR-0038 guards exactly one file, and the user tier's
  authority is single-namespace; a second trusted path is #738's design problem,
  not a relaxation.
- **OCI fallback for an undeclared alias.** A typo would pull a public image.
- **First-wins for a project-side tool collision.** It pre-empts #735's qualified
  names and makes a duplicated verb depend on source order.
- **Suppressing the legacy notice inside `doctor`.** `project_config` already owns
  the legacy location and its `lstat`; the notice needed a fact, not a second
  probe.
