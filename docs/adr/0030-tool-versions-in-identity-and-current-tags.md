# ADR-0030: Tool versions are identity inputs, moved by a current tag

## Status

Accepted (decision). Not yet implemented — tracked by the map
[Map: tool image composition architecture](https://github.com/gregwebs/agent-vm/issues/203).
Amends [ADR-0029](0029-compose-tool-images-by-layer-stitching.md)'s identity
rule, supersedes [ADR-0019](0019-tool-free-base-and-per-tool-layers.md) D8, and
narrows [ADR-0003](0003-project-tooling-layers.md)'s "no state file" rule for
tool images.

## Context

Today a locally composed tool layer freezes whatever version upstream shipped
the day it first built (ADR-0019 D8). The `AGENT_VERSION_*` build args are
only cache keys, and codex, opencode and claude ignore them and install
latest. The earlier ticket Identity of a rebuilt layer kept versions out of the
tag and had a rebuild replace an image under its old tag. Under ADR-0029 that
breaks: a tool that declares this one as parent, and the composed-image cache,
are both keyed on the tool's identity, so they would keep serving the old
version. The identity has to determine the content.

## Decision

- **Identity covers every build arg passed.** A tool image = hash(parent
  identity, build context, sorted `name=value` of every build arg the launcher
  passes except `BASE_IMAGE`). That includes each `AGENT_VERSION_<NAME>` slot
  (two for dsh and pi) and `AGENT_INSTALL_SOFT_FAIL`. Dockerfile defaults are
  covered by the context hash. `SCHEME_TAG` moves to v2.
- **A plain launch never looks up a version.** Each tool's default is written
  in its Dockerfile (`ARG AGENT_VERSION_CODEX=<exact>`). dsh and pi keep empty
  slots, so they build from the committed lockfile. Only the upgrade command
  and CI run the version resolver, so a launch works offline.
- **A tool installs exactly the version it is given.** codex (`CODEX_RELEASE`),
  opencode (`VERSION`) and claude (positional argument) pass it to their
  installers. Every tool records it as `LABEL org.agent-vm.version.<name>`, and
  the build fails if the installed tool doesn't report that version.
- **The version a launch uses**, highest precedence first:
  1. An exact `version` on the tool's `[[tools]]` entry. `version = "latest"`
     is the same as omitting it: no pin.
  2. The tool's **current tag**: a second `ref.name` entry in the shared OCI
     layout, pointing at the tool image the upgrade command last built. The
     launch reads that image's version labels and computes the identity from
     them on the *current* parent, building only if it's missing. So an
     upgrade survives a base `pull`.
  3. The Dockerfile default.
- **A current tag goes stale when the shipped recipe changes.** Each tool
  image records its build context hash. If the launcher's context for that
  tool differs (a new default version or any recipe edit), the launch drops
  the tag, prints a notice, and uses the default.
- **Tools the launcher can't look up** (a user tool that declares
  `ARG AGENT_VERSION_X` but isn't in the launcher's table) receive the literal
  `latest` on upgrade. Their identity includes `latest`, so they stay frozen
  until their context or current tag changes, and the launch says so.

## Consequences

- A version bump changes a tool image's identity, and so the identities of the
  tools that declare it as parent and of the composed image. Nothing serves a
  stale version under a current name.
- The current tags are mutable state, which ADR-0003 avoided. They live beside
  the images they name, in agent-vm's single-writer layout, so a tag and its
  image can't disagree, and they are the roots a future garbage collector keeps.
- Deleting the cache resets upgrades to the defaults. A user who wants a
  version to survive that pins it in config.
- Any launcher change to a tool's recipe also resets that tool's upgrade, not
  only a change to its default version.
- The launcher's defaults lag upstream until a launcher release moves them.
  Users of the published template still get what CI resolved.

## Alternatives

- **Rebuild under the same tag, version only in a label** (Identity of a
  rebuilt layer): leaves dependents and the composed cache on the old version,
  unless everything downstream is keyed on content digests instead.
- **A lockfile in the state directory:** survives cache deletion, but it is a
  second store that can disagree with the images. Config pins cover the
  survival case.
- **Resolve latest at every launch:** needs the network on every launch plus a
  cache and an offline fallback, and first builds stop being reproducible.
- **Keep newer of lock and default:** needs a version comparison per tool, and
  tag formats differ (codex tags are `rust-v…`).
