# ADR-0043: Image command group and Docker-daemon import

## Status

Accepted. Breaking in **0.5.0**. Amends ADR-0035's explicit build/import
decision (#260); implements #359. Amended in **0.6.9** by #385 (defaulted
import tag, selection-aware import completion). Amended in **0.7.0** by #389:
`image refresh` (boot-free native acquisition) and `image set-default` join the
group, and no top-level `pull`/`upgrade` alias exists. Amended in **0.7.2** by
#390: both update verbs take a nested `--yes` (candidate replacement consent).
Amended in **0.7.34** by #391: an explicit build/import approves its own result
reference, prompt-free. Amended in **0.7.35** by [ADR-0061](0061-explicit-launch-builds.md)
(#527): a launch may build, but only for an explicit `--dockerfile FILE`, and
that build publishes through this same module without approving anything.

## Context

A Docker-daemon image is not in agent-vm's image cache. Launch reads the latter,
then a registry; an unqualified daemon-only tag can yield a Docker Hub 401 that
looks like a credential failure.

```text
Dockerfile → image build  → completed archive → image_publish → native cache
Docker daemon / archive → image import ──────────────┘              ↓
                                                             launch
```

## Decision

- `agent-vm image build` retains build's option surface.
- `agent-vm image import (--docker REF [--tag REF] | --input FILE --tag REF)`
  imports a completed image. Docker save must succeed before ingestion; archive
  input needs no Docker. Neither verb selects, adopts, configures or boots
  anything. #385: `--tag` is optional only with `--docker`, where the source
  supplies the result reference; it crosses the same mutable-reference parser,
  so an explicit `--tag` is needed only when that parser rejects the source
  (e.g. a digest-pinned reference or local path). Such rejection is a value-free
  usage error before any state exists. Bare hexadecimal IDs may parse as mutable
  names. An explicit `--tag` always wins.
- One publication module, `image_publish`, resolves the ambient SDK cache,
  stages privately and calls native `load_archive`.
- No `build` alias (ADR-0035's no-shim decision and ADR-0042's single surface).
  `image` is reserved; `build` is available to configured tools.
- Launch/`image refresh`/setup registry failures for explicit mutable tags get a text-only
  import hint, with the original error chain retained. Digests and redacted
  defaults get no hint. No launch runs Docker or falls back to import, except the
  explicit `--dockerfile` launch build of
  [ADR-0061](0061-explicit-launch-builds.md).
- **Nested `--yes` on the update verbs (#390).** `image refresh [--yes]` and
  `image set-default --image REF [--yes]` use `--yes` to pre-authorize exactly
  the one current registry candidate they resolved and displayed. It never
  bypasses the resolved-candidate freeze or the revision compare-and-swap, and
  there is no `-y`, environment variable, global, launch, setup, build or import
  `--yes`. A first pin or an unchanged digest ignores it. This is digest-
  replacement consent, not the removed composition/build `--yes` [ADR-0035](0035-consume-user-owned-boot-images.md)
  rejected.
- **Import/build approve only their result reference (#391).** Each publishes
  cache content *and* approves exactly the one reference its own argument names —
  a build's `--tag`, or an import's `--tag` or inferred `--docker` source — at
  the content it published, for the host Linux platform. No prompt and no
  `--yes`: the command that supplied the bytes is the consent. The change is
  rendered on stderr before it is committed, and an unchanged approval is
  neither rewritten nor rendered. Archive-carried aliases are published to the
  cache but never approved, and neither verb adopts or moves the retained
  default (the store's own journal recovery of an interrupted run — which any
  explicit image write performs — is the one write that may, and it adopts
  nothing). The approval runs after the
  exclusive publication barrier is released, because its cache-only read-back
  takes the shared barrier: approving inside `publish` would self-deadlock. A
  published result that cannot be validated for this host is not approved, and
  the command exits nonzero saying the image was published but not approved.

### Publication semantics

The native loader publishes `--tag` and every archive-supplied name: Docker
`RepoTags` and OCI `org.opencontainers.image.ref.name`. Every image in a
multi-image archive is published under its own names; `--tag` names the first.
References commit one at a time, not as an atomic one-target publication.
On failure, `image_publish` restores the requested tag's previous metadata (or
removes it if new). Aliases are not restored; native blobs may remain. A failed
rollback reports both errors. Process termination mid-import is not covered, and
neither is a concurrent writer that takes no publication barrier: rollback can
revert a direct SDK client or an older binary, because the native loader itself
takes no lock. Participating `image build`/`image import` runs do serialize on
that barrier, whatever reference each names — each holds it exclusively from its
requested-alias snapshot through the loader and its rollback. **Only the
result reference the command itself approves can change launch content under an
existing pin** (#391): every other name is cache evidence, and a pinned launch
validates the approved `repo@child` entry before the SDK consumes it, restoring
it from its content receipt when an alias overwrote the metadata. Every cache
entry this binary validates leaves such a receipt; an approval created by an
older binary has none until a launch re-validates its content, and if an archive
overwrote that digest key first, nothing on the host recorded what it held —
the launch then reports the approved content as unavailable instead of falling
back to the tag.

### Output and diagnostics

Both completion notices go to stdout; stderr carries errors and Docker output.
This moves build's notice from stderr. Import parse diagnostics are replaced
with fixed value-free text (exit 2); build retains clap's diagnostics. Printed
commands use one bash/zsh shell word per reference (`$'…'` for non-ASCII), so
accepted spellings remain copy-pasteable without terminal control bytes. The
#391 approval render is excluded from that rule: it is display text on stderr,
terminal-escaped for safety and deliberately not pasteable.

#385 makes import's completion **selection-aware**, and only after publication:
import observes the selection once through the same typed selector and
environment rule as `image show` (never by parsing its report or spawning it).
An exact reference match — compared as exact text, so `app` and `app:latest`
differ — suppresses the completion sentence. An explicitly configured different
image (environment/user/project, i.e. the effective winner is not a fallback)
adds a fixed hint to run `agent-vm image show`; a retained or recommended
fallback keeps only the launch sentence. The selected reference, its source path
and any selection error are never printed. An unreadable configuration, invalid
override or damaged needed record therefore cannot fail a committed import or
change its exit status: the selection is unknown, handled like a different image
(guidance plus hint). `image show` keeps its strict failure policy, and build's
notice stays unconditional. Observing after publication also keeps the default
tier's process-global dependency-log guard from suppressing the native import's
own diagnostics.

## Considered Options

- Auto-import or `docker image inspect` at launch: rejected, violates ADR-0035.
- Keep `build` as an alias: rejected, violates ADR-0042's single surface.
- Give import/build an automatic or implicit approval: rejected; an archive can
  name an unknown alias set, and silently authorizing any of them would recreate
  the #390 defect. Approving the one reference the command names was accepted in
  #391 — the command names it explicitly, so the command is the consent.
- Approve every archive-supplied name: rejected, same unknown alias set, and no
  argument names it.
- Replace the registry error with the hint: rejected, loses network/TLS detail.
- Patch the vendored loader or reimplement one-target import: rejected; keep
  native `msb image load` parity and accept documented aliases (user decision).
- Leave build's notice on stderr: rejected; one stream rule for both verbs
  (user decision).

## Consequences

Scripts using `agent-vm build` break, or launch a configured tool named `build`.
Scripts reading its notice from stderr must read stdout. See the
[0.5.0 migration note](../../USAGE.md#explicit-builds-and-archive-import).
Importing `--docker src --tag dst` also leaves `src` in agent-vm's cache.
The `msb image load` passthrough is unchanged and still has catalog semantics.

From #391, a rebuild or re-import under an approved result reference switches the
next launch of that reference to the new bytes, with no prompt and no registry
request. Importing over an *alias* does not: an archive-supplied name never
approves anything, so a reference approved earlier keeps its digest until that
reference is itself published or refreshed. A daemon-only image therefore needs
no `image refresh` to become launchable — importing it under the reference you
will select is enough. The multi-alias rollback limitation above still applies
to the cache, not to approval.
