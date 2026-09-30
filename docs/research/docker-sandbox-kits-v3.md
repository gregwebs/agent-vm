# Docker Sandbox Kits v3: composition model and its overlap with agent-vm

**Research date:** 2026-09-29

**Upstream snapshot:** [`docker/sandbox-kit-spec`](https://github.com/docker/sandbox-kit-spec) @ `3e2f362d74b978f6eb1ac43fe32b2fb136d7fa6e` (2026-09-29), `docs/spec/SPEC-v3.md` (1117 lines) and the Go implementation it declares authoritative.

**Local snapshot:** `agent-vm` `bb50c45` (ADR-0032 landed).

**Method:** `SPEC-v3.md` was read in full. Where the spec defers to code ("where this document and the code disagree, the code wins", `SPEC-v3.md:5-8`), the Go packages named inline were read at the same commit. No Docker binary, `sbx`, or runtime was installed or executed, so this records **specified and implemented** behaviour, not observed behaviour. Line numbers are the pinned commit's; function names are the durable reference. Related notes in this directory: [docker-compositional-systems.md](docker-compositional-systems.md) (Dagger/Earthly/Buildpacks) and [docker-sandbox-credential-ui.md](docker-sandbox-credential-ui.md) (which examined the v2 grammar and declined to adopt kit credential semantics).

## Executive summary

Docker Sandbox Kits v3 is the closest external design to the one ADR-0029/0030/0031/0032 settled on, and it was reached independently. It composes a bootable environment by concatenating independently-built OCI layers and synthesizing a config from merged declarations, preserving each contributor's layers rather than repacking them, and addressing the result by a **computed deterministic tag** rather than a state file. That is our stitching architecture, with the same consequences we derived from it.

One rule matches almost verbatim: **two contributors that set the same environment variable to different values is a hard error, an identical restatement is allowed, and `PATH` is the only additive variable.** That is our S4 (with `PATH` exempt) exactly. Their contributors are all effectively siblings because their model has **no parent relation between kits at all**, so their single rule is our sibling rule; our T2 ancestor carve-out is the generalization a `FROM` chain requires.

The divergences all follow from one structural choice, and it is worth stating before anything else:

> **Their kits have no build-time parent.** A mixin is a delta against its own base, joined to others only at assembly. Ours are chained `FROM` their parent. Their "Composition is a function, not a sequence" tenet ("A resolved Kit set is ordered by its dependency graph rather than by the order arguments were typed", `README.md:135-138`) is a *consequence* of that: with no `FROM` edge there is no build relation to order by, so order has to come from the compatibility declarations instead. agent-vm adopted the same principle when ADR-0032 was amended to derive stitch order from `parent` and demote declaration order to a tie-break (§6) — the remaining difference is *which* relation is ordered. And once layers are independent deltas, every cross-contributor file overlap must be fatal, because a delta is only valid against the base it was built from. Our chained builds let a descendant legitimately modify what an ancestor installed, which is why our S1 forbids overlaps only between *unrelated* layers.

Two other divergences are load-bearing. They kept **two kinds** (`workload` + `mixin`) where ADR-0032 collapsed them into one, and the cost is visible in their own examples: `examples/claude/claude.yaml` and `examples/claude-mixin/claude-mixin.yaml` are two published artifacts that both declare `provides: ["claude@2.1.285"]`, and a one-provider-per-name rule exists to refuse composing them ("Composing `claude` with `claude-mixin` is the canonical mistake this refuses", `SPEC-v3.md:386`). And they have **no account model** — a bare `agent` uid 1000 platform floor plus two narrow overlay-ownership rules — which means two mixins cannot both add a user, precisely the case our generated union account layer exists to make compose.

The single most transferable idea is not in the composition machinery at all. Their tenet "One artifact, one digest. Declarations live in the manifest of the image they describe" (`README.md:111`) is the **root cause** of a cost ADR-0032 explicitly accepted — that a *shipped* layer declaring an account needs CI to bake it into the published template. Our declarations live in `agent-vm.toml` and a compiled-in default, so they cannot travel with the artifact that needs them.

Nothing here overturns a decision we made, though one was amended as a consequence: ADR-0032's ordering rule, discussed in §6. The document ends with four borrowable items, one of which lands directly on the open map ticket for rebasing layers onto an updated base.

## 1. The model

### 1.1 One kit is one ordinary OCI image

"A **Kit** is one OCI image. Its manifest annotation `vnd.docker.sandbox.kit.descriptor` carries the Kit's declarations … and its layers carry the Kit's content. There is no kit-specific media type or artifactType: a Kit pulls, inspects, and `FROM`s with stock tooling, and an engine that does not read the annotation runs it as an ordinary image" (`SPEC-v3.md:25-31`). Publishing is the build: a BuildKit frontend, dispatched by the descriptor's `# syntax=docker/sandbox-kit:3` first line, validates the descriptor, builds the content, and writes the expanded descriptor as compact JSON into the manifest annotation (`SPEC-v3.md:14-17`, `:247-252`, `:783-795`).

Every kit also **stages its own sources** into a layer at `/usr/share/sandbox/kit/<stem>/kit.yaml` and `…/kit.dockerfile`, so "a published Kit is self-describing — inside any sandbox that composes it, the declarations and the recipe are readable in place", and every manifest carries at least one layer (`SPEC-v3.md:979-989`). The OCI empty descriptor is explicitly rejected for the declaration-only case because it "breaks the ordinary pullable-image property Kits are built on" (`SPEC-v3.md:1024-1027`).

### 1.2 Two kinds

| Kind | Layers are | Count per composition |
|---|---|---|
| `workload` | A root filesystem; the image config carries entrypoint, cmd, env, user, workdir | Exactly one |
| `mixin` | An overlay that lands on a workload's filesystem; may be declaration-only | Zero or more |

(`SPEC-v3.md:34-39`.) A descriptor "deliberately carries **no top-level identity name, image reference, or runtime config**" — launch config lives in the OCI image config where images already carry it, and the only declaration the image config has no slot for, an interactive argument tail, lives in the `lifecycle@1` capability (`SPEC-v3.md:41-46`, `:751-762`).

A third value, `kind: set`, is an authoring form that lists other kits by digest-pinned reference and merges them; it "**MUST NOT** appear in a published descriptor" because publishing derives `workload` or `mixin` from the listed kits (`SPEC-v3.md:173-215`). Its list order "carries no meaning" (`SPEC-v3.md:205`). A set is how a working environment is shared as one reference "instead of a command line someone has to retype" (`SPEC-v3.md:173-177`).

### 1.3 How a set becomes an image

At create time: "a resolver produces a locked set and an assembler emits an ordinary image — config synthesized from the merged declarations, layers concatenated in dependency order — identified by the lock, which is what makes recreate exact" (`SPEC-v3.md:1030-1037`). The assembler emits a fresh manifest and config, concatenating `RootFS.DiffIDs` in the same order and reusing each kit's existing blob descriptors (`assemble/assemble.go`).

Publishing a set does its own merge, and its rule for cross-contributor file overlap is instructive:

> "Two Kits contributing the same file resolve by that order, rather than failing the way the same two would when a runtime composes them at create. The rule is not relaxed, only unenforceable where the merge happens: deciding it needs every Kit's layer inventory, and a build frontend reaches neither the layer blobs nor a filesystem listing cheaper than one round trip per directory. A merged set is therefore judged for collisions where its layers can be read — from the published artifact." (`SPEC-v3.md:863-871`)

### 1.4 Identity: the lock, not a state file

The composed image is addressed by `assemble.Tag(lockJSON)` = `"sandbox-kit-assembled:" + sha256(lockJSON)[:16]` (`assemble/assemble.go:208`), where the lock records the resolved set in composition order — per kit its reference, digest, image, kind, args, and permission surface (`resolve/lock.go`). Staleness is a re-resolution compared against the lock: a moved tag errors rather than silently rebuilding. GC and eviction are "runtime concerns outside this specification" (`SPEC-v3.md:1036-1037`) — the same gap our map carries as unresolved fog.

## 2. Conflict and merge rules

### 2.1 Environment — the rule that matches ours

`assemble/assemble.go:104-106` states the model: "PATH is additive by construction: the mixin's PATH value holds only the elements it added … Every other env var is first-writer-owned." If two contributors set one non-`PATH` variable to different values, assembly returns

```go
return fmt.Errorf("env conflict on %s: %s and %s set different values", k, prev.kit, m.Name)
```

(`assemble/assemble.go:122`), naming both parties; an identical restatement is accepted (`:113-126`). `PATH` is appended and deduplicated (`:164-196`). Labels are first-writer-wins with no error; `EXPOSE` and `VOLUME` union (`assemble/assemble.go`).

The spec's own account is thinner than the code's: "Image defaults are composed first, create-argument `env` exports replace them, and explicit runtime environment overrides win last" (`SPEC-v3.md:475-477`).

There is **no reserved-key list** for image-config env: a kit may set anything. A restricted environment exists only for hook *processes* (`PATH`, `HOME`, `HOSTNAME`, `TERM`, `PWD`, `OLDPWD`, `SHLVL`, `_`), enforced by a TCK check, not for the image config (`capabilities/com.docker.sandbox/lifecycle@1.md`).

### 2.2 Filesystem

Cross-kit file collisions are a hard error when the inventories are readable: the built-in validator reads every tar header (bodies discarded) and walks an overlay model against accumulated owners, so a later entry hitting a lower-contributed path fails unless it is a directory replacing a directory; whiteouts count (`fetch/layer_validator.go`, `fetch/assemble_collisions.go`, `fetch/assemble_inventory.go`).

Two things weaken this relative to our S1. Validation is **opt-in at the API level** — "Layer validation is opt-in; set LayerValidator to DefaultLayerValidator to run", and the assembly path only calls it `if options.LayerValidator != nil` (`fetch/assemble.go:18`, `:168-169`) — so a caller that does not opt in composes without checking. And at publish-merge time it is unavailable, as quoted in §1.3 above. Our S1 is unconditional, which we can afford because we build the layers locally and already hold their inventories; theirs must read blobs the runtime has deliberately not fetched ("layers are never fetched until the runtime pulls the image itself", `SPEC-v3.md:1028-1030`).

The spec also carries two narrow ownership rules that no collision check would catch, because they are about *directory metadata* rather than overlap: "A mixin **MUST NOT** ship `/home` owned by anyone but root, or `/home/agent` by anyone but uid `1000`" — "Either inversion takes the home from the user who needs it" — and a mixin **SHOULD NOT** ship a symlink its own layers do not resolve, since the base it lands on is unknown (`SPEC-v3.md:1000-1008`).

### 2.3 Declarations

Declaration merges are per-type and typed: `provides`/`conflicts`/`licenses` union; `requires` and `integrates` union *minus* entries the set satisfies itself, "a Kit cannot satisfy its own requirement" (`SPEC-v3.md:884-892`); instance-shaped capabilities union deduplicated on their own key while two different configs under one key is an error; `lifecycle@1` install hooks, startup hooks, and files concatenate in composition order, and two of them writing one file path is an error (`SPEC-v3.md:896-930`). Capability arity is either singleton (at most one entry in the effective descriptor) or instance-shaped, and exact duplicates of any type are rejected (`SPEC-v3.md:557-577`).

## 3. Order is derived, not declared

A conforming runtime resolving a set **MUST** "order composition by the dependency graph (providers before requirers; met `integrates` entries order like requires), never by flag order" (`SPEC-v3.md:305-307`). The workload is always first in image order regardless of where the topological sort placed it (`assemble/resolve.go`, `assemble/doc.go`). Ties are broken lexicographically by reference (`resolve/resolve.go`), so **no author-declared ordering exists anywhere in the model** — the closest thing is a `requires` edge, which orders as a side effect of expressing compatibility (`examples/tool/tool.yaml` requires `hello >= 1.0.0` solely to land after it).

Resolution stays deliberately shallow: "resolution stays a **closed-set check** (the set already names its providers; at most one provider per capability name), never a backtracking solver that picks versions from a registry", and `requires`/`integrates`/`conflicts` "MUST stay literal … a parameterized constraint would make the judgment depend on caller input" (`SPEC-v3.md:300-311`).

Versions are a separate truth-seeking mechanism. Publishing reads the package databases out of the content — `/var/lib/dpkg/status`, `/lib/apk/db/installed` — and states one `provides` entry per installed package under the reserved `deb/` and `apk/` namespaces, "around one package in twenty" of which need the dots and pluses the name grammar allows. Author-declared `version:` is "a fallback, never an override", and derivation exists because otherwise `provides: [bash]` under `version: "1.0.0"` would be "a statement about the Kit's release number wearing the name of a shell" (`SPEC-v3.md:244-252`, `:938-975`). Derivation applies to workloads only, and that is stated as what keeps one-provider-per-name satisfiable: "a composition has exactly one workload, so a derived name has exactly one owner by construction" (`SPEC-v3.md:955-958`). It also documents a case it refuses to state at all: a tilde in the upstream version half is dropped rather than truncated, because dpkg sorts `1.69~deb13u1` *before* `1.69` and their own comparison would order `2.0-rc1` above `2.0` (`SPEC-v3.md:966-975`).

## 4. Accounts: the platform floor

There is **no users, groups, or accounts surface anywhere in the descriptor** (`schema/kit.schema.json`, `SPEC-v3.md` §4). What exists instead:

- A **platform floor** the runtime guarantees and a workload promises: "`bash` and `sh`, `curl`, `git`, a populated CA store, and a non-root default user named `agent`, uid `1000`, home `/home/agent`" (`SPEC-v3.md:1101-1108`). A workload's recipe "**SHOULD** build on a base providing the runtime's platform floor … or the Kit builds fine and fails at agent launch" (`SPEC-v3.md:225-227`).
- A TCK check that refuses a workload whose image-config `user:` is absent or does not resolve against the image's own `/etc/passwd`/`/etc/group` (`tck/kit/kit.go`).
- The two overlay-ownership MUSTs quoted in §2.2.

Additional users are the overlay's business, expressed as ordinary file writes in a mixin's Dockerfile, and any conflict surfaces as the generic file-overlap rule. Because a mixin's layer is a delta against *its own* base, **two mixins cannot both add a user**: the second's `/etc/passwd` shadows the first's. The model has no mechanism that would notice, short of the collision check seeing two contributions at one path.

Note `spec/groups.go` and `tck/sandbox/groups.go` are **not** unix groups — they are capability groups: coupled capability entries selected atomically under one `optional`, where "a group's members are applied only after selection finishes" and a partial application is forbidden (`SPEC-v3.md:579-640`).

Against the host, there is no mapping at all: the host "resolves the image's own passwd", so host identity is never injected into a guest's passwd.

## 5. Point-by-point

| Concern | Docker Sandbox Kits v3 | agent-vm | Verdict |
|---|---|---|---|
| Unit of composition | Kit: `workload` \| `mixin` | Layer, `command` optional (ADR-0032) | Their split publishes one tool twice (`claude` + `claude-mixin`) and needs a name-collision rule to refuse composing both |
| Layer artifact | Stock OCI image + descriptor annotation | Stock OCI image in the shared layout, untagged nodes | Same |
| Assembly | Concatenate layers; synthesize config from merged declarations | Stitch manifests (ADR-0029) | Same |
| Layer content | Preserved, blobs stay shared | Preserved (stitching) | Same |
| Order | Derived from `provides`/`requires`, ties lexicographic | Derived from `parent`, ties by declaration order (ADR-0032, amended) | Both derived; they order by compatibility, we by build edge |
| Composed identity | `sha256(lockJSON)[:16]` under a fixed prefix | Computed `agent-vm-layer:<slug>-<hash>` | Same reasoning, computed before any build |
| State file | Lock, which also gates permission widening | None; the tag is the staleness check | Theirs does strictly more |
| Strict decoding | `KnownFields(true)`; a misspelled key is an error | `deny_unknown_fields`; deliberate hard break | Same stance |
| `PATH` | Sole additive env var, appended + deduped | T2: additive | Same |
| Other env keys | Hard error on differing values between contributors; identical OK | S4: hard error for siblings; identical OK; ancestor override legitimate (T2) | **Their rule is our S4**; ours is its DAG generalization |
| Launcher-owned env keys | None reserved for the image config | `LANG`, `IS_SANDBOX`, `HOME`/`USER`/`LOGNAME`, `MSB_` rejected | Ours stricter |
| Unrelated file overlap | Hard error, opt-in validation, unavailable at publish-merge | S1: hard error, always enforced | Ours stricter, affordable because we build locally |
| Accounts | Undeclared; platform floor + overlay ownership MUSTs | Declared `users`/`groups` → one generated union layer | Ours is load-bearing: chrome-devtools already owns `/etc/passwd` |
| Version truth | Package databases → derived `deb/`,`apk/` provides | Image version labels (ADR-0030) | Same instinct: don't trust declarations |
| Declarations live | In the image's own manifest annotation | `agent-vm.toml` + compiled-in default | Theirs travels with the artifact |
| Publishable composed environment | Yes: a `set` publishes as one kit with digest-pinned `kits:` | Only the shipped default template | Gap |
| Version ladder | `schemaVersion` + per-capability `@N`, independently | One `SCHEME_TAG` (v2) | Our next layer-field change invalidates every cached node |
| Conformance | TCK, `kit-tck` adapter protocol, clause→test markers | Contract clauses T1–T7/S1–S4, build-time checks | Technique worth taking |
| GC/eviction | Outside the spec | Open fog on the map | Same gap |

## 6. Where we diverge, and why

**Order and visibility.** Their tenet "**Composition is a function, not a sequence.** A resolved Kit set is ordered by its dependency graph rather than by the order arguments were typed, so the same set always composes to the same image" (`README.md:135-138`) is the principle ADR-0032 was amended to adopt: stitch order is now derived from `parent`, and declaration order only breaks ties. What remains different is **which relation is ordered**. Theirs is `provides`/`requires` — compatibility, which a layer can assert about a stranger it has never been built against. Ours is `parent` — a build edge, because our layers are chained `FROM` and each layer's identity includes its parent's. Their choice is forced by their artifact model, and it costs them real capability: because a mixin's layer is a delta against its own base, no mixin can *modify* what another contributed — only add a path that must not already have an owner. A project layer that adjusts a shipped tool's configuration in place is inexpressible. That is a common shape for us and it is why our S1 is scoped to non-ancestors. The cost we pay is the one ADR-0032 already recorded: a change at the root rebuilds every layer above it.

**Accounts.** Their design cannot have two contributors add users, and needs none of the machinery we specified. Ours needs it because the shipped set already contains a layer that appends to `/etc/passwd` (`examples/layers/chrome-devtools/Dockerfile:15-29`), so without a single generated writer, the first project layer that wants a user would collide with a *shipped* layer and be unable to proceed at all. Their "no mapping against the host" answer to identity collision is also unavailable to us: we mirror host files under the host uid (ADR-0002), which is where the collision risk ADR-0032 now checks for comes from.

**Declarations in the artifact.** Their tenet "One artifact, one digest. Declarations live in the manifest of the image they describe" (`README.md:111`) is a direct contrast with our config-file and compiled-in-default declarations. The practical consequence is the cost ADR-0032 accepted: a shipped layer's declaration cannot travel with the shipped image, so CI must bake it into the published template. A manifest annotation on the shipped layer image would remove that constraint — and note that the descriptor is *expanded and signed at publish* (`SPEC-v3.md:783-795`), so the declaration a consumer reads is the one the publisher validated, not one a user could inject.

**Versioning ladder.** "Let types evolve on their own clock. The `@1` in a capability type versions that type's config schema, so a capability can change shape without a descriptor grammar bump" (`README.md:145-149`), with `schemaVersion: "3"` reserved for grammar-shape changes (`RELEASES.md`). ADR-0032 chose one `SCHEME_TAG` v2 covering everything. Their reason for a ladder is third-party implementers, which we do not have — but the tradeoff is real: our next change to a layer field invalidates every cached layer image on every machine, and theirs would not.

**Product shape.** Theirs composes to *one launch target*: exactly one workload, whose image config supplies the entrypoint. Ours composes to *one image offering N verbs*, chosen at launch, with the per-verb credential requirement set riding on the tool entry. That difference is upstream of everything else in this section — it is why they need two kinds and we do not, and why their `provides`/`requires` graph exists (the set must be coherent for the one launch) where our `parent` is about build visibility.

**Interop, tentatively.** Their `mixin` is close to our commandless layer and their `workload` to our layer with a `command`, so ADR-0032's unification makes a foreign kit cheap to *import* — a mixin would enter as a commandless layer, a workload as a layer with a `command` — which is a far smaller project than adopting their semantics. The reverse direction is harder: a conforming runtime must answer `com.docker.sandbox/*` capability types and honor exactly-one-workload. Much of that capability surface already has an agent-vm counterpart under a different name (credentials, network policy, forked mounts/volumes, git identity, image-owned packages — per ADR titles, not verified here), so "agent-vm as a partial kit runtime" is plausible but unexamined.

## 7. What is worth taking

1. **Declared compatibility, checked before a build — for the rebasing ticket.** Their `requires`/`provides` mechanism plus derived `deb/`/`apk/` package provides means a layer can state what it needs of whatever it lands on, and after a base bump an incompatible layer fails **resolution in milliseconds instead of at the end of a rebuild**. Since derived entries ride the set's `provides` union (`SPEC-v3.md:884-892`, `:955-975`), a layer requiring `deb/openssl >= 3.5` would be judged against the base's own package database. *Inferred from the spec, not demonstrated* — but it is directly on the critical path of the map's rebasing ticket, which currently relies on rebuild-and-recheck.
2. **Declarations in the shipped image.** A manifest annotation on each shipped layer image carrying its own declaration would let CI bake accounts at publish instead of requiring them in the published template. Relevant to shipped layers only; project layers should stay in config, since a project's declarations are the user's to write.
3. **Clause→test mapping.** Every normative clause in their spec carries an inline marker naming the conformance check that accounts for it (`<!-- tck: SPEC-v3 §5.3/one-provider-per-name -->`), and governance requires each MUST/SHOULD be mechanically accounted for. Our T1–T7/S1–S4 have no such mapping; the technique is cheap and would make the contract auditable.
4. **Their ownership rules as a check on our contract.** The two overlay MUSTs in §2.2 cover a class our T3 does not: *directory metadata* at a path that already exists, where a wrong owner breaks the user's home without any path overlap. Worth asking whether our guest-home mirroring needs the same guard.

## 8. What I would not take

- **The two-kind split.** It duplicates publication for one tool and requires a rule to refuse the resulting mistake.
- **Registry-and-lock assembly.** Our [docker-compositional-systems.md](docker-compositional-systems.md) already concluded that registry-less local composition is "normal, not a hack"; kits pay for portability with a lock and a fetch, which we do not need while we build locally.
- **The lock as permission gate.** Interesting — a version move whose permission surface stays within the granted one applies silently, any widening stops for approval (`SPEC-v3.md:700-736`) — but it belongs to credential work, which this map excludes and which [docker-sandbox-credential-ui.md](docker-sandbox-credential-ui.md) already declined to adopt.
- **Any "Docker-compatible" claim.** Consistent with the earlier credential research: this remains an experimental specification. "This specification is experimental. It is published to be used and argued with, and it will keep moving as implementers find gaps" (`README.md:55-57`); releases are `v3.0.0-m.1`…`m.6` prereleases; final version targeted for Q4 2026; one maintainer.

## 9. What I could not verify

- **Runtime behaviour.** No Docker binary, `sbx`, or runtime was installed or run. Everything above is spec plus the Go implementation at the pinned commit.
- **Whether real Docker launches check file collisions.** The plumbing is opt-in (`fetch/assemble.go:18`, `:168-169`); I did not establish which callers pass `DefaultLayerValidator`.
- **Whether any conformance test re-checks collisions on a merged set.** Despite `SPEC-v3.md:863-871` deferring that judgement to "the published artifact", I found no TCK check that composes the filesystem layers and re-runs the collision walk; `tck/sandbox/*` verifies runtime adapter behaviour.
- **That a mixin can require a base's derived package provide.** Recommended in §7 as inference, not demonstration.
- **Whether the examples' mixin/workload pairs are genuinely redundant.** `claude` and `claude-mixin` both `provides: claude@2.1.285` at the same default version, which is the duplication argument in §6; I read the descriptors and their capability lists, not the full Dockerfiles, so I cannot say the content is equivalent.
- **v2-era inconsistencies** documented in [docker-sandbox-credential-ui.md](docker-sandbox-credential-ui.md) still apply to anything outside this v3 spec.
- Code and conformance claims rest on a directed reading of the pinned commit; the spec sections quoted in §1–§4 were read directly and in full.

## Sources

- [`docs/spec/SPEC-v3.md`](https://github.com/docker/sandbox-kit-spec/blob/main/docs/spec/SPEC-v3.md) — the normative grammar and the composition contract.
- [`README.md`](https://github.com/docker/sandbox-kit-spec/blob/main/README.md) — the eight tenets (`:106-149`), the experimental notice (`:55-66`).
- [`docs/kit-intro.md`](https://github.com/docker/sandbox-kit-spec/blob/main/docs/kit-intro.md), [`docs/spec/conformance.md`](https://github.com/docker/sandbox-kit-spec/blob/main/docs/spec/conformance.md), [`GOVERNANCE.md`](https://github.com/docker/sandbox-kit-spec/blob/main/GOVERNANCE.md), [`RELEASES.md`](https://github.com/docker/sandbox-kit-spec/blob/main/RELEASES.md).
- Implementation: `assemble/assemble.go`, `assemble/resolve.go`, `assemble/image.go`, `fetch/assemble.go`, `fetch/assemble_collisions.go`, `fetch/assemble_inventory.go`, `fetch/layer_validator.go`, `resolve/resolve.go`, `resolve/lock.go`, `spec/merge.go`, `spec/validate.go`, `internal/overlayfs/fs.go`, `schema/kit.schema.json`, `tck/`.
- Capability pages: `com.docker.sandbox/{lifecycle,credential,git-identity,agent-skills,network-policy@2,ssh-agent,kit-registry}@*.md`.
- Examples: `examples/claude/claude.yaml`, `examples/claude-mixin/claude-mixin.yaml`, `examples/shell/shell.yaml`, `examples/tool/tool.yaml`.
