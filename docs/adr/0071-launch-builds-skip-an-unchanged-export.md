# ADR-0071: Launch builds skip an unchanged export

## Status

Accepted and implemented in **0.7.74**
([#677](https://github.com/gregwebs/agent-vm/issues/677)). Amends
[ADR-0061](0061-explicit-launch-builds.md) §5.

## Context

ADR-0061 §5 has every launch build re-run `docker buildx build --output
type=oci,dest=-` and relies on BuildKit's cache for reuse. That cache covers
the build steps, not the **launch-build export**: BuildKit re-sends the whole
archive on every launch. Measured on colima with a 633 MB image and every step
`CACHED`, a warm launch took 8.5–8.9 s, of which `sending tarball` was
7.3–7.7 s (~85 MB/s, independent of the sink). Publication was already ~50 ms:
the native loader's early gate skips layer staging when the image is
materialized.

`--output type=image,oci-mediatypes=true,store=false --metadata-file F` runs the
same build and reports `containerimage.digest` without writing the Docker image
store. On both the `docker` and `docker-container` drivers that digest equals
the manifest digest the OCI export produces. Warm, the probe costs 0.36–0.50 s on
the `docker` driver (`colima`) and 0.32–0.73 s on the `docker-container` driver
(`agent-vm-dc`): the span of every warm probe measured, across four
repeat-launch runs and the initial toolchain probe.

Both halves of that equality are load-bearing, and each was measured. Without
`oci-mediatypes=true` the `docker` driver reports a Docker-format manifest's
digest, which does not match the export (`sha256:7a95f31a…` against
`sha256:d435b1ad…`). An unknown exporter attribute is ignored, so a builder that
can run the `type=oci` export does not reject the probe's output; an exporter
that does not exist fails exactly like a failing build step (exit 1, no metadata
file), which is why agent-vm cannot tell the two apart and does not try.

## Decision

1. **Every launch still builds.** The first Docker run is the **launch-build
   probe**: the same build with the probe output above. Docker decides whether
   anything changed; agent-vm hashes no source and keeps no record.
2. **The image cache is the record.** With probe digest `D`, the launch reads
   `<internal name>@D` cache-only under the shared barrier. If present, it boots
   that and skips both the export and publication; the internal `:latest` tag is
   left as is.
3. **A miss runs today's path.** Export, publish and read back exactly as
   ADR-0061 §7. If the published digest differs from `D`, a debug line names
   both.
4. **Probe and export share one argument list** that differs only in its output
   flags: `--output`, plus the probe's `--metadata-file`. So platform,
   provenance, SBOM, media types and compression cannot drift.
5. **A probe problem never fails the launch; Docker's verdict does.** Once the
   probe exits 0, anything agent-vm cannot read falls back to the export with a
   debug line: a missing metadata file, no `containerimage.digest`, a malformed
   digest, or a failed cache read. A non-zero probe exit is the build's failure
   (ADR-0061 §11) and is not re-run. Docker reports a failing step and a rejected
   exporter the same way (exit 1, no metadata file), and BuildKit ignores
   exporter attributes it does not know, so a builder that can run the
   `type=oci` export does not reject the probe's output.
6. **Still no pin, no approval** (ADR-0061 §6 unchanged).

## Alternatives rejected

- **Record the digest in image pins.** A pin is a project-scoped approval
  record; a launch build approves nothing. The cache lookup is needed anyway to
  boot `repo@D`, so a pin adds state without removing a check.
- **Probe into the Docker image store** (`type=image` with a name, or without
  `store=false`). Leaves a visible, disk-duplicating image per Dockerfile.
- **A persistent OCI layout directory** (`type=oci,tar=false`). Incremental
  (0.46 s warm, 0.54 s after a small edit), but needs a directory per
  Dockerfile, garbage collection, concurrent-launch handling, another on-disk
  copy and a loader that reads directories. Its advantage, faster changed
  builds, is out of scope.
- **`type=cacheonly` plus the progress stream's final vertex digest.** Relies on
  an undocumented schema rather than an image digest.

## Consequences

- A repeated launch of an unchanged Dockerfile costs the probe, not the
  transfer.
- A changed build pays the probe plus the export, and `store=false` means the
  result is not kept — not that nothing is sent. Measured on the `docker` driver:
  editing one small layer added 0.2 s of probe time (0.53 s) before the 8 s
  export; a first build with a fresh 633 MB layer paid 9.9 s in the probe's own
  export step and 6.3 s in the export. On `agent-vm-dc` the same cold miss paid
  8.0 s in the probe's export step and 3.6 s in the export. Only a repeat of
  unchanged content is free of that transfer.
- Switching builders can change `D` for identical content; that is one miss,
  then hits.
- A future buildx whose probe and export digests diverge degrades to today's
  speed, never to wrong content.
- Whether a legacy (non-containerd) Docker image store honours `store=false` is
  unverified. Such a `docker` driver cannot run the `type=oci` export, so a
  launch build there fails as before; at worst the probe also leaves a dangling
  Docker-store image.
