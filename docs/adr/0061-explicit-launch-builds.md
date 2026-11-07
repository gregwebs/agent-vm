# ADR-0061: Explicit launch builds

## Status

Accepted and implemented in **0.7.35**
([#527](https://github.com/gregwebs/agent-vm/issues/527)). Amends
[ADR-0035](0035-consume-user-owned-boot-images.md)'s "no launch builds an image"
rule and [ADR-0043](0043-image-command-group-and-daemon-import.md)'s command
group placement.

## Context

[ADR-0035](0035-consume-user-owned-boot-images.md) established the ownership
boundary: agent-vm owns launch, supervision, image selection, acquisition and
runtime tool declarations; users own their images. Under that boundary the
launcher was forbidden from building anything ("no launch builds an image or
runs Docker").

The defect ADR-0035 corrected was that an image could be built **implicitly**:
declaring a tool or opening an unfamiliar project could trigger an unrequested
multi-minute local build. But that made the edit-run loop for a Dockerfile
clumsy — `agent-vm image build -t T -f F ctx`, then `agent-vm --image T shell`,
with a temporary tag to invent and delete.

A user typing `--dockerfile <file>` explicitly commands a build for that one
execution. There is no implicit surprise, no project-driven build, and no
coupling to catalog declarations.

## Decision

1. **Explicit-only CLI launch option.** `--dockerfile FILE` is a launch option,
   accepted before a catalog tool or a direct command. Nothing else can supply
   it: no environment variable (`AGENT_VM_DOCKERFILE`), no user or project config
   key, no catalog field. It is rejected on `setup`, which has no image
   selection.
2. **Cannot be combined with `--image`; outranks everything else.**
   `--dockerfile` together with a *typed* `--image` is a usage error (status 2)
   on every route. `AGENT_VM_IMAGE_TAG`, a user or project config `image`, and
   the default boot image are **ignored** rather than conflicting, because
   `--dockerfile` outranks them all. clap's `conflicts_with` cannot express this
   (it counts an env-sourced value), so the check compares
   `ImageArgs::typed_on_command_line()`.
3. **The build context is the Dockerfile's parent directory.** Both paths are
   resolved relative to the working directory; the context is the *typed*
   parent, never re-canonicalized. There is no separate context argument and no
   `-` Dockerfile: Docker's stdin is `/dev/null` (see 9).
4. **Deterministic internal name.** The export is published into agent-vm's
   native image cache (the SDK backend's `cache_dir`, `$MSB_HOME/cache`) under
   `agent-vm.invalid/dockerfile/<sha256 of the canonical Dockerfile path>:latest`.
   The `.invalid` TLD is guaranteed never to resolve (RFC 6761) and does not
   match the plain-HTTP heuristic, so this name can never become a registry.
5. **Every launch builds.** There is no source hashing and no skipped build;
   BuildKit's own cache is the only reuse. The result is whatever `docker buildx
   build --output type=oci` produced this time.
6. **No image pin and no approval.** A launch build writes nothing under
   `~/.config/agent-vm`: no `image-pins.json` entry, no retained default, no
   approval read. Typing the flag is the consent, for that launch. For a named,
   reusable image, use `agent-vm image build` and `--image`.
7. **The launch boots the published digest, not the moving tag.** Publishing
   takes the exclusive publication barrier and releases it before the read-back,
   so a multi-minute build never blocks any other publisher. The read-back then
   takes the *shared* barrier, reads the tag cache-only, and requires its digest
   to equal the digest the loader reported; that read also preserves the
   content-addressed `repo@digest` metadata. Preparation later reads that
   immutable `repo@digest` cache-only and holds the shared barrier through
   create.
   - A concurrent launch build of the same Dockerfile that publishes *different*
     content between this launch's publication and its read-back makes this
     launch **fail** ("the … build result changed in the image cache before this
     launch could boot it …; re-run the command"). It never boots the other
     content, and it never boots a partial mixture.
   - A publish *after* the read-back cannot affect this launch at all: it holds
     the digest it verified.
   - There is no check "under" the exclusive barrier, because the loader's
     digest equals the staged digest by construction; the read-back is the
     comparison that can actually fail.
8. **The build runs early and holds nothing.** It follows every side-effect-free
   rejection — CLI arithmetic, mount preparation and its rejections, `MSB_HOME`,
   the db-ahead preflight and the socket-path fit — and precedes the Pi
   migration, the banner, session state, guest HOME, SecretSpec sessions and
   credential snapshots. A failed build therefore leaves no session state, no
   credential working copy and no aged token behind.
9. **Reserved stdin is never consumed.** The build's stdin is `/dev/null`, so a
   streamed direct command (`echo hi | agent-vm --dockerfile F -- cat -`) still
   reaches the guest.
10. **Diagnostics name the typed path.** The banner and the ADR-0060 report use
    `--dockerfile <typed>`. Contract diagnostics render
    `--dockerfile <typed> (built as <internal name>)` so the most likely
    iteration failure (a program missing from a Dockerfile you are editing) names
    your file. Build progress is Docker's own, on stderr; the launcher's stdout is
    untouched.
11. **A failed build is the launcher's failure.** Status 125 for a direct
    command, 1 for a tool launch — never Docker's exit code, which appears only in
    the message.
12. **`PullPolicy::Never`, and no `.insecure()`.** A launch build's image is
    cache-only by construction: the create must not resolve its internal name
    against a registry, so the plain-HTTP reading that a `.local`-style name would
    attract is suppressed as well as the fetch. `PreparedSelection` carries this,
    and `pull::registry_is_insecure` is the one decision function.
13. **Contract diagnostics are the only display surface.** `image show` and the
    inspection verbs refuse a launch-build selection as an internal error, since
    no verb but a launch can hold one.

## Alternatives rejected

- **An environment variable or config key.** Rejected: a repository-supplied
  `.agent-vm/config.toml` or an inherited variable would recreate exactly the
  implicit build ADR-0035 removed.
- **Hold the publication barrier from the start of the build through create.**
  Rejected: it would block every `image build`, `image import` and launch
  preparation on the host for the length of a Docker build.
- **Hash the source and skip the build when unchanged.** Rejected: Docker's own
  BuildKit cache already does this, and a second, weaker identity would be a
  correctness liability (a context file outside the hash, a `.dockerignore`
  change).
- **clap's `conflicts_with = "image"`.** Rejected: an env-sourced `--image`
  value counts as present, which would make `AGENT_VM_IMAGE_TAG` conflict
  instead of being outranked.
- **Pin the result like any other OCI selection.** Rejected: the content is
  produced by the command the user just ran; there is nothing to review, and a
  prompt would break the loop the feature exists for.
- **Name the internal tag under `.local`, or reuse a user-visible tag.**
  Rejected: `.local` invites an mDNS pull if the cache loses the entry, and a
  user-visible tag would make a launch build collide with, and possibly approve
  over, a name the user owns.
- **Build options (context argument, `--build-arg`, `--target`, `--builder`,
  `--no-cache`, `--progress`, `--pull`).** Deferred: `image build` already owns
  that surface, and a launch build with its own option set would grow a second
  one. `BUILDX_BUILDER`/`DOCKER_HOST` still pick a builder from the environment.

## Consequences

- Direct iteration on a guest image, with no temporary tag and no approval trap:
  edit the Dockerfile, run the launch again, boot the new content.
- ADR-0035's promise survives intact. Nothing an environment variable, a config
  file, a repository or the catalog declares can start a build; only typing the
  flag does.
- Superseded launch-build content stays in the cache, exactly as `image build`
  output does. There is no pruning, and an interrupted build can leave a staging
  directory behind, as `image build` already can.
- Two launches of the same Dockerfile that publish different content
  concurrently can make one of them fail and ask to be re-run. That is a
  deliberate trade: failing is safe, booting unknown content is not.
- A Dockerfile in `$HOME` takes `$HOME` as the build context, and a remote
  builder would receive it. There is no guard; USAGE documents the hazard.
