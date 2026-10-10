# ADR-0032: One layer kind — a tool is a layer with a command

## Status

**Relocated:** the `examples/layers/` examples cited below moved to [agent-vm-images](https://github.com/gregwebs/agent-vm-images/tree/main/examples/layers) (agent-vm-images#23); paths here are historical.

**Superseded by [ADR-0035](0035-consume-user-owned-boot-images.md) (#257). The launcher DAG/current-tag/version-identity system was not implemented; committed recipe/version pins and source integrity checks are retained in the independent [image repository](https://github.com/gregwebs/agent-vm-images); source ownership moved by #265.**

Accepted (decision). Not yet implemented — tracked by the map
[Map: tool image composition architecture](https://github.com/gregwebs/agent-vm/issues/203).

Supersedes [ADR-0003](0003-project-tooling-layers.md)'s ordered layer chain and
its layer image contract (C1–C8). Extends
[ADR-0029](0029-compose-tool-images-by-layer-stitching.md)'s stitched DAG and
[ADR-0031](0031-tool-image-contract.md)'s contract to **every** layer. Amends
[ADR-0019](0019-tool-free-base-and-per-tool-layers.md) (the chain root) and
[ADR-0016](0016-tool-declared-guest-env.md) (which env keys a layer may
declare).

**Amended in place, 2026-09-29.** Stitch order is now *derived* from the
declared `parent` graph with declaration order demoted to a tie-break. It had
been declaration order, authoritative, with a child required to follow its
parent. The revision removes an error class instead of adding a rule: two
relations cannot disagree when the graph is the only one. Adopted after reading
Docker Sandbox Kits v3, which answers the same question with a derived order
("Composition is a function, not a sequence") — see
[../research/docker-sandbox-kits-v3.md](../research/docker-sandbox-kits-v3.md).

[ADR-0033](0033-default-rebase-with-build-provenance.md) amends base-change
handling: build identities retain the original parent as provenance, while a
rebased composition may reuse those artifacts on a new base with fresh
structural checks. A parent change due solely to a base update no longer
necessarily rebuilds every layer.

**Composition-root boundary clarified** by
[Acyclic composition root and identity boundaries](https://github.com/gregwebs/agent-vm/issues/214).
The root is base plus generated union accounts, with no catalog layers. This
replaces the circular root identity and the old root-as-finished-image wording;
all catalog layers, shipped or project-declared, sit in the DAG above it.

## Context

Layers were built before tools, and the two never merged. ADR-0003 made project
layers an ordered **chain**; ADR-0019 put catalog **tool layers** at the front of
that same chain; ADR-0029 and ADR-0031 replaced tool chaining with a stitched DAG
and gave tool images their own contract — leaving project layers on the old
chain and the old contract, and leaving the word "chain" naming something the
tool half no longer is.

The distinction was never load-bearing. It exists because of the order the two
features were built, not because a project layer is a different kind of thing:
`layer = { path = "…" }` already declares a project-owned layer as a catalog
entry, anchored on the declaring config file's directory (ADR-0019 D7). What the
split now costs is two contracts, two identity rules, two authoring surfaces, and
a chain whose rebuild amplification ADR-0029 exists to eliminate — paid on the
half that never got the DAG.

Two facts made the old arrangement actively unworkable rather than merely
redundant:

- ADR-0031 rejected C6's `/etc/passwd` allowance on the strength of project
  layers being a separate kind — *"under stitching, two appenders lose one
  account. Accounts belong in the base or in a project layer."* Once there is one
  kind, that escape hatch names nothing, and `examples/layers/chrome-devtools`
  is a shipped layer that appends to `/etc/passwd`, `/etc/group` **and**
  `/etc/shadow`.
- T2's "changes only `PATH` in the config" is not satisfiable by the shipped
  examples: `examples/layers/go-dev` sets `ENV GOTOOLCHAIN=local` and
  `examples/layers/rust-dev` sets `ENV RUSTUP_HOME=/opt/rustup`.

## Decision

### One declaration site

Every layer is one catalog entry in a `[[layers]]` section — `name`, a `layer`
source (`{ builtin = "…" }` or `{ path = "…" }`), an optional `parent`, an
optional `command`, and the tool fields that already exist (`args`,
`credentials`, `tools`, `persist`, `env`, `interactive_shell`, `version`).

- **A Tool is a layer with a `command`.** `command` becomes optional; a
  commandless layer contributes to the image and offers no verb. Epic #78's "one
  subcommand per resolved tool" becomes **one subcommand per launchable layer**,
  and `setup`'s supply-a-command rule (ADR-0019 D10) is reformulated the same
  way.
- The section is renamed `[[tools]]` → `[[layers]]` in one step. `RawTool` is
  `deny_unknown_fields`, so an older binary meeting a new config hard-errors;
  that is this repo's stated forward-compatibility stance (ADR-0016's
  Consequences) and the rename is deliberately not softened.
- The embedded catalog's filename follows the section (`default-tools.toml` →
  `default-layers.toml`): a rename, not a content change beyond the header.

### No discovery

`.agent-vm/layers/` is deleted as a discovery convention, and the singular
`.agent-vm/layer` guardrail with it. A project declares each layer in
`.agent-vm/config.toml`; a leftover `.agent-vm/layers/` directory is a hard
error naming the entries to add — the same shape of guardrail, retargeted from a
`git mv` to a config edit.

- **`--layer DIR` survives** as CLI injection for the try-then-adopt workflow
  (`agent-vm shell --layer examples/layers/chrome-devtools`). It stays
  repeatable and additive, and **provenance stays out of identity**, so
  `--layer`-ing a directory and later declaring the same directory in config
  produce the identical image: a cache hit, not a rebuild.
- **`parent` is declared in the entry** and defaults to the composition root.
  There is no in-directory `parent` file and no project-level layer manifest.
- **Stitch order is derived from `parent`, not authored.** The declared `parent`
  relation is the composition graph, and stitch order is its topological order:
  repeatedly place the earliest-declared layer whose ancestors are all already
  placed (a stable topological sort keyed on declaration position). Declaration
  order is therefore only a **tie-break among layers the graph does not order** —
  roots, and siblings under one parent — and not an order the author has to keep
  consistent with `parent`. A child declared above its parent is legal; it simply
  sits outside the tie-break's reach. An injected `--layer DIR` declares no
  parent, so it is a root and command-line order is its tie-break.
- **A `parent` naming a layer outside the composition, and a cycle, are hard
  errors.** The rule this replaces — "a declared parent must precede its child in
  stitch order" — is gone: with one relation there is nothing left for it to
  check, and the failure it was guarding against, a cycle, is now caught
  directly.

### The composition root is the foundation, not the finished image

The **composition root** is the base image plus the generated union account
layer, when accounts are declared. It contains **no catalog layers**. Every
catalog layer — including every shipped tool — builds above this foundation
or its declared layer parent. The final derived image stitches the foundation
and each participating layer's own layers exactly once.

```text
Base image + generated union accounts = Composition root
                                           ├─ codex
                                           ├─ claude ── claude-plugin
                                           └─ rust-dev
Root + ordered own layers = Derived image (boot image)
```

Composition uses a local foundation, never the released composed default as a
parent. A released default or an explicit image booted verbatim is a finished
**boot image**, not a composition root. ADR-0034's default release path retains
zero Docker calls; selecting a local build composes even the shipped set.

This separates build foundations from acquisition/boot selection, and removes
the identity cycle caused by putting layer identities inside their own parent's
identity.

### Everything is stitched

Each layer builds `FROM` its parent — as an independent build, with a declared
parent supplied as a build context (the prototype's `oci-layout://` aliasing,
confirmed working on the `docker` driver). The **derived image** is a new
manifest: the root's layers followed by each layer's own layers, in stitch
order. Only the derived image is ingested into the msb cache.

### Identity

- A **layer image** = `hash(SCHEME_TAG, parent identity, build context, sorted
  name=value of every build arg except BASE_IMAGE)` — ADR-0029's rule with
  ADR-0030's build-arg input. A layer whose parent is the composition root
  therefore anchors on the **root's identity**, not the base digest. Position
  does not enter; neither does provenance.
- The **composition root** = `hash(base digest, generated account layer
  identity when accounts are declared)`. Its identity contains no catalog-layer
  identities. The generated accounts depend on the base and declared account
  data, not on the build identities of the layers declaring them.
- The **derived image** = `hash(composition root identity, ordered layer
  identities)`. Order enters here and only here, because order is the manifest's
  layer order.
- The **project image handle** stays
  `agent-vm-layer:<project-slug>-<hash>`, with the slug **out** of identity.
  Within the same local cache, projects with identical resolved build inputs
  reuse validated layer artifacts. An identical derived composition already
  ingested into msb is reused without stitching or ingesting again; registering
  another project handle is metadata-only, not an archive read. Handles are
  readable references and separately retained GC roots, not build or ingest
  boundaries. Releasing one project's root cannot evict content retained by
  another. This replaces the earlier "build twice on purpose" rule, as settled
  by [Cross-project reuse of identical compositions](https://github.com/gregwebs/agent-vm/issues/216).
- The tag stays a **computed hash, not the stitched manifest digest**. It has to
  be computable on the launch path before anything is built, which is what makes
  the hash the staleness check and keeps a cache-hit launch at zero Docker
  processes.
- **Current tags stay a tool-image concept** (ADR-0030). Layer images get no
  current tag; version *resolution* for non-shipped layers is out of scope.
- **`SCHEME_TAG` moves to v2, once.** ADR-0030 already claimed v2 for tool
  images and nothing is implemented, so this work folds into the same bump
  rather than minting a v3. There is no grandfathering: v2 starts from an empty
  cache.

### One contract

[ADR-0031's contract table](0031-tool-image-contract.md#decision) is the sole
normative contract for every layer image. This section records the rationale
for its amendments, clarified by
[Config merge fields and ancestor overrides](https://github.com/gregwebs/agent-vm/issues/217):

- **T2 widens to Env, not arbitrary config.** `go-dev` and `rust-dev` need
  environment variables, not control of the guest's user or entry point.
  Non-Env config fields stay unchanged; labels retain their separate allowance.
  S3 preserves base labels and admits only `org.agent-vm.*` layer labels.
- **T3 stays strict for layer content.** No layer may replace or delete a base
  path. The **only** permitted write to a base-path file is the launcher's own
  generated, append-only account layer below.
- **S4 is new — no unrelated-layer env collisions.** This is S1's rule in
  a different medium: unrelated layers have no meaningful override order, so a
  silent winner would drop one layer's environment declaration exactly as an
  overlap drops one layer's file. Labels are not environment declarations.
- **Ancestry is transitive for S1/T3/S4.** In `A → B → C`, C may override
  A's introduced files or environment variables; a direct edge is not required.
  Base and generated account files remain protected at every depth.
- **Launcher-owned env keys are rejected as layer declarations**: `LANG` and
  `IS_SANDBOX` (published on every launch by `run::GUEST_ALWAYS_ENV`),
  `HOME`/`USER`/`LOGNAME` (owned by `user::guest_identity_env`), and the `MSB_`
  prefix — ADR-0016's rejection set, extended from tool entries to layer
  declarations. A layer declaring `LANG` would be silently overridden for the
  launched agent while still applying elsewhere in the guest; a
  silently-partially-effective declaration is the failure this repo refuses
  everywhere else.

### Accounts are declared, not appended

Accounts become data on the layer entry rather than a `RUN` step:

- `users = [{ name, uid, gid, home, shell, groups = [ … ] }]`, where `gid` is a
  number or the name of a declared group. Declaring a user **auto-creates a
  same-named group with that gid** when nothing else claims it — the
  `useradd --user-group` convention Debian already uses, and what collapses
  `chrome-devtools`' two declarations into one.
- The launcher generates **one append-only account layer** carrying the union of
  every declared account, placed **in the composition root below every layer**.
  Build-time visibility is the reason it is a layer and not a boot-time patch:
  `chrome-devtools` runs `sudo -u chrome -H npx …` and self-tests with
  `sudo -n -u chrome -- id -u` inside its own `docker build`.
- **It must be the union, and byte-identical wherever it appears.** Appends
  compose as *operations* but mask as *files*: two layers each appending their
  own account still leave the upper one's `/etc/passwd` masking the lower's,
  silently losing an account — precisely the failure ADR-0031 rejected C6 for.
  A single union layer dedupes to one write.
- `/etc/shadow` entries are generated **locked** (`!`) with a **fixed** `lastchg`
  constant, never today's date, so the layer stays byte-identical across builds
  and ADR-0029's determinism guarantee holds. This is the first time agent-vm
  writes `/etc/shadow` at all.
- The generated stage also creates the declared home directory, owned
  `uid:gid`, matching `useradd -m` — a declared home that does not exist is a
  foot-gun.
- **Everything that is content rather than identity stays in the Dockerfile**:
  home *contents*, NSS CA trust, sudoers, the MCP pre-warm, and the capability
  marker (T6/C8).
- **Collisions.** Declared-vs-declared (same name, uid or gid twice) is a
  plan-time hard error naming both layers. Declared-vs-base runs `getent` inside
  the generated stage — where the whole filesystem is available, exactly where
  `chrome-devtools` checks today — so it surfaces as a build error.
  Declared-vs-**host identity** is a plan-time hard error: the launcher appends
  the host uid and username before boot regardless, and
  [ADR-0002](0002-mirror-host-home-and-username.md) records the resulting
  `getpwuid` misresolution as an *accepted risk* naming this very layer. A wrong
  home directory is symptomless, so the risk becomes a check. (Prepending the
  host identity instead is the alternative, and was rejected: it trades a loud
  failure for a silent one.)

## Considered Options

- **Keep two kinds, one mechanism.** Rejected: the glossary would keep two terms
  for one thing, and ADR-0031's account rationale would keep depending on a
  distinction this ADR deletes.
- **Unify the mechanism but keep `[[layers]]` and `[[tools]]` as two sections**
  with tools referencing a layer by name. Rejected: one concept behind two
  sections, and the drift between them is what the change exists to remove.
- **Keep `.agent-vm/layers/` discovery as sugar synthesizing parentless
  entries.** Rejected by the owner: two declaration sites can drift, and a
  directory's own order would compete with the config's as the tie-break.
- **Chain project layers onto the composed root instead of stitching them.**
  Rejected: two composition mechanisms, a second contract family, and a second
  identity rule — for a reuse win that is admittedly smaller on the project half,
  since a project's layer set never recurs across tool sets. Uniformity is worth
  more than the smaller claim.
- **One account node per declaring layer, as that layer's parent.** Rejected: two
  appender nodes mask each other's `/etc/passwd`.
- **Declare accounts at boot only.** Rejected: a layer cannot `sudo -u` or
  pre-warm as an account that does not exist yet during its own build.
- **Prepend the host identity on collision rather than erroring.** Rejected: see
  above — silent home-directory misresolution.

## Consequences

- **C1–C8 are retired.** ADR-0003's contract table is no longer normative for
  anything; ADR-0003 remains as the history of how layers were built.
- **Every existing project with layers breaks at the authoring surface**, not
  merely in semantics: `.agent-vm/layers/*` becomes `[[layers]]` entries, and
  the error names them.
- **Cold cache** on the v2 bump, for layer images, the composition root and
  derived images. No grandfathering.
- **Changing a declared account changes the composition root and rebuilds
  every layer above it.** This is the price of the union layer sitting at the
  root instead of per declaring layer. A tool source/version change instead
  rebuilds that tool and its declared descendants, not independent siblings;
  no catalog layer is an input to the composition root. Base-only changes
  remain subject to ADR-0033's rebase policy rather than this account-change rule.
- **A shipped layer that declared an account would require CI to bake it into
  the published template**, because the shipped default set boots the published
  template verbatim. No shipped layer does today; the constraint lands on
  CI, published surface, and image-API migration.
- **T3 now needs the base image's file list**, not only the tool images' — the
  one read ADR-0031's "the stitcher already reads file lists" argument does not
  yet cover.
- **The account-collision predicate carries a `verus!` contract.** It is a new
  pure function over untrusted config values deciding which identity the guest
  resolves, which ADR-0018's rule and `byte_paths_overlap`'s precedent in
  `config.rs` put in scope. ADR-0018's kernel/adapter split applies: the
  collision predicate is the proved kernel, and the TOML read stays outside as
  the trusted adapter.
- **Glossary churn.** `Tooling layer`, `Layer chain` and `Layer image contract`
  are retired; `Tool layer` and `Tool image` generalize to `Layer` and
  `Layer image`, with `Tool` narrowing to "a layer with a command". See
  [CONTEXT.md](../../CONTEXT.md) for the new wording.
- **`--update-check` and `agent-vm pull` are unaffected**: they still never
  target `agent-vm-layer:<hash>` (ADR-0019 D6).
