# ADR-0073: Host-managed project config

## Status

Accepted for [#733](https://github.com/gregwebs/agent-vm/issues/733), the first
of seven stacked children of [#732](https://github.com/gregwebs/agent-vm/issues/732).
Amends [ADR-0015](0015-config-driven-tools.md),
[ADR-0038](0038-config-dir-exposure-guard.md) and
[ADR-0040](0040-persisted-user-network-authority.md). Breaking release:
**0.8.0** — an in-repo `.agent-vm/config.toml` stops loading.

Amended by [ADR-0074](0074-flat-config-sources.md) (#734): the project config may
source other files; `doctor`'s legacy note is suppressed when the in-repo file is
sourced.

## Context

agent-vm merges two TOML **tiers** into one launch catalog. The user tier is
`~/.config/agent-vm/config.toml`; the project tier *was* `<cwd>/.agent-vm/
config.toml`.

That location made **viewing someone else's code change the user's agent-vm
configuration** (#732). Whoever can write the repository — its author, a
dependency's vendored tree, a branch the user merely checks out — authored the
project tier. A tools-only file is already the attack: it adds verbs, replaces
the guest command of a name it declares, and selects the boot image. Later
children of #732 put `sources`, source trust, `allow_tools` and project image
pins in the same file, so the file becomes the root of a project's trust.

```text
checkout a branch → its .agent-vm/config.toml is loaded at the next launch
                  → its `claude` verb runs the branch author's command
```

Nothing in the repository can be trusted with that role, so the project tier
moves to a directory only the user writes.

## Decision 1: `$HOME/.config/agent-vm/projects/<project-id>/config.toml`

`<project-id>` is `ProjectDir::digest_hex()`: the 64-hex lowercase SHA-256 of the
canonical captured project path's raw bytes — the same id `image-pins.json` and
`allowances.json` already use, so one project has one id across every store. The
full digest, never the 12-hex prefix that names a state directory: authority must
not depend on a truncated hash.

```text
HOME = /Users/al
cwd  = /Users/al/src/app            (canonical; ProjectDir)
id   = sha256("/Users/al/src/app")  = 3f9c…e1  (64 hex)

before: project tier = /Users/al/src/app/.agent-vm/config.toml          ← repo-writable
after:  project tier = /Users/al/.config/agent-vm/projects/3f9c…e1/config.toml
        /Users/al/src/app/.agent-vm/config.toml                          ← never read; doctor notes it
```

`project_config.rs` is the single place that spells these paths
(`projects_dir`, `project_dir`, `path`), so #736 (`pins.json`), #737
(`image set-default`) and #739 (`agent-vm config`) inherit one seam.

This release only **reads**. It creates neither `projects/` nor any file in it;
writers arrive with #737/#739.

## Decision 2: an in-repo config is never read; `doctor` says so

`<cwd>/.agent-vm/config.toml` is not auto-loaded and no compatibility path
remains. Because silence would look like a bug, `doctor`'s
`==> tool configuration` section ends with either

```text
note: <path> is not auto-loaded; agent-vm never reads an in-repo .agent-vm/config.toml.
To use it, review it and source it from this project's config with `agent-vm config edit`.
```

or, when `lstat` fails with anything but `NotFound`,

```text
note: could not check for an in-repo .agent-vm/config.toml at <path> (<ErrorKind:?>); agent-vm never auto-loads it.
```

The probe is `lstat`-only and lives outside `config::load`: only `doctor` asks,
so a launch never even touches the in-repo path. The note never changes the exit
status and appears whether the configuration loaded or failed.

## Decision 3: the project file is verified unconditionally

The project tier has no dotfile-symlink compatibility history — there is no
shipped configuration at the new path — and it is the root of a project's trust,
so a tools-only planted file must be refused exactly like one that declares
authority. Every present project config is therefore measured before its bytes
are decoded, whatever it declares. That differs from the user tier, whose
refusal is still decided by the *presence* of authority fields (ADR-0040).

Two properties make the measurement meaningful in the presence of symlinks:

- **No final component is followed.** The tier opens with `O_NOFOLLOW`
  (`host_paths::open_regular_no_follow_checkpointed`). `ELOOP` becomes
  `ThroughSymlink` without the target being opened or read; a successful open's
  descriptor facts are verified *before* `read_bounded`, so untrusted bytes are
  never decoded.
- **The store route is checked first.** `project_config::check_store_route`
  rejects a symlinked `projects/` or `projects/<id>`, and an ancestor alias
  (`~/.config/agent-vm -> <checkout>/…`) that resolves the store inside the
  active checkout. A `$HOME`, `$HOME/.config` or `/` project root is **not** an
  exemption: those runs stay allowed exactly while the store is reached
  unaliased, i.e. its canonical path *is* the canonical
  `$HOME/.config/agent-vm/projects/<id>` (macOS `/var -> /private/var`
  included). A dotfile-managed `~/.config/agent-vm` symlink therefore refuses
  the project tier even when the run is from `$HOME` — the same refusal a
  checkout alias gets, because from inside `$HOME` the two are indistinguishable
  and only one of them is safe.

The rules themselves are reused, not re-implemented:
`config_authority::verify_project` calls the unchanged Verus-proved
`authority_refusal` kernel with `symlink_metadata(parent)` (so a symlinked store
directory is `DirNotDirectory`, not followed) and attributes every refusal to the
new `AuthoritySubject::ProjectConfig`. No `AuthorizedConfig` token is minted,
because the project tier still parses no authority-bearing field
(`config::refuse_project_authority`). The user tier keeps ADR-0040's
`metadata(parent)` and its dotfile symlinks unchanged.

Diagnostics gain one sentence shape: `config: "<path>": the project config …`.
`AuthoritySubject::without` became an `Option`, so this subject omits
"(a symlinked config without … still works)" — a claim that would be false here.

## Decision 4: the exposure guard measures `projects/` and every entry

ADR-0038 refuses a writable live bind that *is or contains* a directory agent-vm
resolves through to reach its authority — and deliberately allows a bind strictly
*inside* it. `~/.config/agent-vm/projects` and each project's directory lie
inside, so "contains a route" alone would let a guest write a later launch's
project config.

Each is therefore its own measured store (D5):

```text
Pass 1 (all homes, in order):
  ~/.config/agent-vm                 (unchanged: routes + config.toml/allowances.json links)

Pass 2 (all homes, in order; entries sorted by raw filename):
  ~/.config/agent-vm/projects        (new: routes; prospective if missing)
  ~/.config/agent-vm/projects/<e>    (new, for each existing entry e that is a dir or a symlink:
                                      routes through any symlink + projects/<e>/config.toml links)
```

- **Every project, not only this launch's.** ADR-0038's cross-project threat is
  "P1's guest plants P2's authority", which the active project alone does not
  cover.
- **Sorted entries**, so a first-match refusal and a link-count error name the
  same file on every filesystem.
- **Two passes over the homes**, so a project-store route reached from a raw
  `$HOME` cannot outrank the account home's own `~/.config/agent-vm` in `decide`'s
  first-match scan.
- A bind strictly inside a project's directory (`projects/<e>/sub`) stays
  allowed, exactly as `~/.config/agent-vm/sub` is today.
- ADR-0038 Decision 2's one-name rule extends to every measured
  `projects/<entry>/config.toml`, through the now-generic `file_links`.

**Fails closed by design:** even an unrelated project's uninspectable route or
multi-link `config.toml` refuses every launch. Leaving it unmeasured would
launder it into a later launch, which is the thing the rule exists to prevent.

Two shapes of that fail-closed rule are worth naming, because both refuse a
launch for a reason a user has to fix:

- **An entry under `projects/` that is not a directory** (a regular file, or a
  symlink to one) refuses the launch. `lstat(<entry>/config.toml)` answers
  `NotADirectory` there, and R6's rule is that only `NotFound` is silence. It
  cannot hold a `config.toml`, so it *could* be skipped — but skipping is the
  classification this guard refuses to make, and the message can name exactly
  the entry to remove. The diagnostic therefore names the entry and the remedy,
  not only the unmeasurable path under it.
- **More than 1024 entries** under one `projects/` refuses the launch, naming the
  directory. Every entry is measured, so cost grows with the directory, and a
  directory agent-vm did not create can make each launch arbitrarily slow
  (measured: 8 s for 10,000 entries). Skipping entries is not an option for the
  reason above, so the bound is the fail-closed alternative to unbounded work.

## Decision 5: one `ProjectDir` capture, handed beside `Dispatch`

`ProjectDir::capture` is a clippy `disallowed-methods` entry: one capture per
command. Config discovery now needs it, and every consumer that already used it
must agree with it, or a cwd rename between two captures would let the catalog
and the pin/launch state describe different projects.

`main` therefore captures once, discovers and loads config from it, and passes
`Result<ProjectDir>` beside `Dispatch` into `run_dispatch`. `Dispatch` gains no
fields and `cli.rs` is unchanged. Every command that needs a project borrows
that capture — the catalog consumers (`doctor::run`/`run_to`,
`image_cmd::show`, `run::launch`, `setup::run`, `pull::run`,
`image_import::run`) and the ones that consume no catalog (`access`,
`clipboard`, `image build`, `image pins`, `image set-default`) — and none
captures again, so the clippy invariant is what it says: one capture per
command. Capture failure stays *data* where it always was (`doctor`,
`image show`), so a diagnostic verb keeps working when the cwd cannot be read;
the commands that treat it as fatal do so exactly as before.

## Consequences

- **Breaking (0.8.0).** A repository that shipped `.agent-vm/config.toml` loses
  its verbs. `doctor` names the file and the fix. `USAGE.md` documents the manual
  migration; #739 will ship `agent-vm config edit`.
- The project tier is now a **per-project, per-host** file. A config that was
  committed for a team no longer travels with the repository: team-shared tools
  belong in the user tier, or in a file each user sources (#734).
- One extra `read_dir` plus a resolution walk per entry per launch (A3): a
  handful of entries, one `lstat` per path component.
- `--mount ~/.config/agent-vm/projects[:…]`, another project's directory, and
  the target of a symlinked entry are refused writable; `:ro`, `:fork` and
  strictly-inside binds are unaffected.
- A hard-linked project config blocks launches until the extra name is removed —
  the same remedy ADR-0038 already prints.
- `agent-vm doctor --reset-msb-db` still reads no config, so it deliberately
  prints no legacy note.

## Accepted gaps

- **Stable routes.** As in ADR-0040, the checks are separate observations: a
  concurrent host-side swap of the store directory between the route check and
  `open` is out of scope. This is not a race-free lookup and is not claimed as one.
- **Ancestors above `projects/`** are trusted unless they alias into the active
  checkout; a hostile `~/.config` owned by another user is out of scope, exactly as
  it is for ADR-0040.
- **ACLs, network filesystems and hostile concurrent writers** are as ADR-0040
  describes: owner/mode/link facts only.
- **Missing per-project directories** are not recorded prospectively. Core binds
  are named by 12-hex state names or fixed words, which the name rule never
  equates with a 64-hex project id, so no core bind can create one; an explicit
  `--mount` of a missing source already fails source validation.
- **Identity is path-keyed.** The id is the canonical *path*, so deleting a
  project and cloning a different repository at the same path inherits that
  path's project config (`projects/<id>/config.toml`) — the same accepted
  property as `image-pins.json` and `allowances.json`. Harmless while the tier
  only declares tools the user wrote. ADR-0074 keeps `:trust` reserved to the
  user config, so no sourced file inherits authority from *where* it sits; the
  files an untrusted source contributes are still read unpinned until #736.
- **#735/#736/#737/#738/#739** are not implemented here: `allow_tools`,
  pins/`pins.json`, `image set-default` writing project config, inert sets in
  sourced files, mount/egress set changes, and the `agent-vm config`
  subcommand. The legacy note names `agent-vm config edit` before it exists
  because #733's acceptance criteria require that wording. `sources` and
  `:trust` arrive with #734 (ADR-0074).

## Alternatives rejected

- **Keep auto-loading in-repo config with a warning.** The threat is not
  accidental use but hostile bytes; a warning arrives after the load that
  already decided the catalog.
- **Guard only the active project's directory.** It leaves the cross-project
  plant that ADR-0038 exists to refuse, and P1 can plant P2's file with no
  project switch at all.
- **Give the project tier a presence trigger like the user tier.** The file is
  the root of the project's trust; a tools-only file is already harmful, and
  there is no shipped dotfile-symlink setup at this path to preserve.
- **A `follow_symlinks` flag on `verify`.** A boolean argument invites the wrong
  call, so the two policies are two call sites over one shared measurement:
  `verify` (user, presence-triggered, parent symlinks followed) and
  `verify_project` (project, unconditional, `symlink_metadata(parent)`).
- **`XDG_CONFIG_HOME` or another override.** Host authority stays at the literal
  `$HOME` location, as ADR-0038/0040 already require, so a per-session variable
  cannot move the store.
