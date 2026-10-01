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

No runtime/build base split is introduced. A **Base link**, where used, refers
to the actual base used for a build, not to an ABI promise. ADR-0034 supersedes
this ADR's historical registry/template and pull/update-check interfaces:
released-default launches boot the pinned composed default verbatim, while
local composition supplies the base through an OCI-layout named context.

ADR-0034's **base selection** policy defines when a locally composed launch sees
an updated base: changed recipe/build inputs or a successful explicit refresh,
never an ordinary launch-time upstream check. A changed selected manifest digest
invokes this rebase policy when layer inputs are unchanged; an unchanged digest
does not. Failed destination checks block that launch without replacing its
retained working composition.

## Artifact selection

Resolved by
[Selecting artifacts for a base-only rebase](https://github.com/gregwebs/agent-vm/issues/215).

Select artifacts in parent-derived order before building:

1. Prefer a validated shared-cache artifact with the exact build identity for
   the selected destination parent.
2. Otherwise, look for a validated, available artifact in **this project's
   retained last composition**. Do not search other projects' histories or an
   arbitrary shared index for older rebase candidates. A project without a prior
   composition still shares exact build-identity hits, but builds on a miss.
3. Reuse that prior artifact only when the base is the sole changed build input
   for the layer and its declared ancestors. Compare normalized build contexts,
   resolved versions and all passed build arguments except `BASE_IMAGE`, declared
   parent relationships, and union account data. Retain the scheme/platform
   identity boundaries too. Ignoring the parent hash alone is not proof: trace
   retained provenance to establish that ancestor differences are base-only.
4. Otherwise build normally. A missing prior artifact is a build miss, not a
   reason to search another project's history.

Eligibility is **per layer**, not all-or-nothing for the catalog. A simultaneous
base change and tool-version change may rebase unchanged independent layers
while normally building that tool and its descendants. A non-base ancestor
change disqualifies its descendants; an unrelated layer change does not.
Changed union account data affects every layer's foundation and disqualifies
all prior artifacts. Current-parent and rebased artifacts may coexist in one
composition, subject to the destination checks above.

Record sufficient resolved-input and original build-parent metadata with the
retained composition to make this comparison without Docker or an upstream
lookup, including through repeated rebases. Compute the final identity from the
destination composition root and the selected artifact identities in stitch
order before layer builds; planned normal builds use their computed build
identities. Reuse keeps original artifact identities rather than relabeling
artifacts as current-parent builds. This preserves the no-Docker cache-hit path
and shared reuse of an identical final composition.

Exact option syntax and rebuild targeting remain with Upgrade pattern for tool
images. CI/published-surface integration remains with CI, published surface, and
image-API migration. This decision does not implement either interface.

## Considered options

Always rebuild on a changed base digest is conservative but reinstalls agents
unnecessarily for ordinary compatible updates. Compatibility epochs or explicit
ABI dependency declarations add policy and maintenance obligations the owner
does not want now. Neither is part of this effort.
