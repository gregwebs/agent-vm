# ADR-0043: Image command group and Docker-daemon import

## Status

Accepted. Breaking in **0.5.0**. Amends ADR-0035's explicit build/import
decision (#260); implements #359. Amended in **0.6.9** by #385 (defaulted
import tag, selection-aware import completion). Amended in **0.7.0** by #389:
`image refresh` (boot-free native acquisition) and `image set-default` join the
group, and no top-level `pull`/`upgrade` alias exists.

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
  defaults get no hint. Launch never runs Docker or falls back to import.

### Publication semantics

The native loader publishes `--tag` and every archive-supplied name: Docker
`RepoTags` and OCI `org.opencontainers.image.ref.name`. Every image in a
multi-image archive is published under its own names; `--tag` names the first.
References commit one at a time, not as an atomic one-target publication.
On failure, `image_publish` restores the requested tag's previous metadata (or
removes it if new). Aliases are not restored; native blobs may remain. A failed
rollback reports both errors. Process termination mid-import and concurrent
publication of the same reference are not covered: rollback can revert a
concurrent writer, and the native loader takes no publication lock.

### Output and diagnostics

Both completion notices go to stdout; stderr carries errors and Docker output.
This moves build's notice from stderr. Import parse diagnostics are replaced
with fixed value-free text (exit 2); build retains clap's diagnostics. Printed
commands use one bash/zsh shell word per reference (`$'…'` for non-ASCII), so
accepted spellings remain copy-pasteable without terminal control bytes.

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
