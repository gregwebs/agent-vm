# ADR-0033: Default to rebase, preserving build provenance

Accepted (decision), not yet implemented. Resolved by
[Rebasing tool layers onto an updated base](https://github.com/gregwebs/agent-vm/issues/208)
on [Map: tool image composition architecture](https://github.com/gregwebs/agent-vm/issues/203).
The earlier rebuild-only resolution on that ticket is superseded.

When only the base changes, default to **rebase**: retain the installed layer
files and stitch them onto the new base without rerunning their installers.
Provide an explicit **rebuild** option that reruns the layer builds against the
new parent, using normal Docker/BuildKit caching. Warn on rebase that major base
changes can cause incompatibilities and that rebuild should be used if needed.
Do not introduce automatic runtime/ABI dependency management, compatibility
identifiers, or layer opt-in declarations. The owner accepts runtime
compatibility risk in exchange for a simpler design and avoiding reinstalls.

## Identity and validation

- Preserve each reused layer artifact's original build-parent identity and
  provenance. Never record reused files as a fresh build against the new parent.
  The rebased composition is identified separately by the new base digest and
  reused artifacts in stitch order, including the regenerated account layer.
  Rebuild creates artifacts built against the new parent. This amends
  ADR-0032's implication that a changed parent always requires a new layer build;
  its build identity remains valid as build provenance.
- Reuse applies when only the base changes. Changed layer sources, versions,
  parent declarations, or other build inputs still trigger normal builds.
- Retain structural validation against the destination: base-file collisions,
  cross-layer collisions, command shadowing, and config conflicts remain hard
  errors. Cached source artifacts do not authorize skipping destination checks.
  ADR-0031's cache-hit exemption does not apply to a newly rebased composition.
- Regenerate the append-only union account layer against the new base, including
  account-collision checks. Do not copy old base account files into a new base.
- T1's parent-prefix check continues to establish the original build provenance
  and the artifact's own layers; rebasing does not pretend its original parent
  prefix matches the new base. Runtime ABI compatibility is not inferred from
  any structural check or command-path resolution.

No runtime/build base split is introduced. The Docker-local
`agent-vm-base:<manifest-digest-hex>` Base link continues to refer to the actual
base used for a build, not to an ABI promise. Published-default launches still
boot the published template verbatim. Pull/update-check targeting is unchanged;
a locally composed launch with an updated base uses this rebase policy.

Exact option syntax and rebuild targeting remain with Upgrade pattern for tool
images. CI/published-surface integration remains with CI, published surface, and
image-API migration. This decision does not implement either interface.

## Considered options

Always rebuild on a changed base digest is conservative but reinstalls agents
unnecessarily for ordinary compatible updates. Compatibility epochs or explicit
ABI dependency declarations add policy and maintenance obligations the owner
does not want now. Neither is part of this effort.
