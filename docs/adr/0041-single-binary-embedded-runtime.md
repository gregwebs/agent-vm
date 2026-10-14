# ADR-0041: Single-binary embedded runtime

## Status

Accepted. Additive release: **0.3.7**. Publication is a separate follow-up;
this change supplies a source-buildable release form, not a release workflow.

## Context

Copying only `bin/agent-vm` loses its runtime pair. The SDK execs msb, which
then dlopens libkrunfw: both must exist as files. Our patched libkrun cannot
be replaced by upstream `download-binaries` or `msb self install`.

## Decision

`embedded-runtime` is opt-in. npm subpackages, the three-file macOS bundle,
and normal development builds are unchanged. `macos.sh --single-binary`
publishes only `target/macos-single/agent-vm`, after a lone-copy smoke and
architecture, signature and entitlement checks on the unpacked runtime.
Extraction preserves signed bytes verbatim; it never re-signs msb.

```text
MSB_PATH → resolved-exe sibling → reported-exe sibling → source build
                                                        ↓ missing
                    embedded payload → cache/runtime/<id>/{bin,lib}
```

The resolved directory wins over the launcher-link directory so an unrelated
standalone msb beside a link cannot shadow the patched runtime. A stale
MSB_PATH still refuses unless a sibling exists.

The cache root is `$XDG_CACHE_HOME/agent-vm`, else `$HOME/.cache/agent-vm`.
Empty/relative XDG paths are ignored; HOME must be absolute. The id is the
first 16 hex digits of SHA-256 over both recorded file digests. A private
0700 stage is stream-decoded, checked for recorded length and full SHA-256,
fsynced, and atomically renamed. Files have modes 0755/0644. A losing
publisher adopts the complete peer runtime. Reuse checks regular-file
existence and recorded lengths only: **full hashes run only on publication**.
Mismatch fails closed with a quoted removal hint; there is no self-healing.

Unpack stays in the pre-Tokio prologue, outside launch state. Both MSB_PATH
and MSB_LIBKRUNFW_PATH are pinned before SDK lookup. The rejected-launch
invariant (`run.rs` mount preflight; `config-dir-guard-live.sh` N1/N5) is
unchanged: AGENT_VM_STATE_DIR stays empty (C10). A rejected launch may populate
this cache once per payload: about 63 MB (63,472,432 bytes for the measured
pair), plus publication work. SHA-256 alone measured 183 ms median without
sha2 asm; M4 measured a 1.687 s cold invocation, 22.34 ms warm median (five runs),
and 19.10 ms bundle baseline median (five runs) on this Apple Silicon host.
Cold minus baseline was 1.668 s; warm minus baseline was 3.24 ms. These are
wall-clock observations, not latency guarantees. Reuse adds two file lstats
rather than hashing 63 MB per invocation. Doctor reports the cache path without unpacking.

## Trusted vs proved

No new Verus contracts: these are host-side I/O adapters over user-owned
files and build-time bytes, like existing msb discovery and identity checks,
not sandbox-boundary or untrusted-input policy kernels (ADR-0018). Verus
translation remains a required CI gate; local cargo-verus is unavailable.

## Accepted gaps

- The reuse gate checks only the final component's type and recorded length,
  so any same-length replacement passes: an in-place edit (C5c), a replaced
  file, or a symlinked `bin`/`lib` ancestor
  (`unpack_reuse_accepts_symlinked_bin_ancestor`). Deletion plus a rerun
  restores fully hashed bytes. Only complete hashed stages are renamed in.
  Closing this needs hash-on-reuse (rejected on cost) or a mount guard.
- A writable guest mount over the cache can replace the runtime, as a mount
  over a bundle or `~/bin` already can. No new mount guard is added.
- No garbage collection: each old payload retains about 63 MB. Cache removal
  is safe while no runtime is in use; the next invocation republishes it. A
  `.stage-*` directory left by a killed publish is likewise not collected —
  the next run still publishes
  (`unpack_recovers_with_a_stale_stage_directory_present`).
- Signing msb touches the payload every build, causing relinking each time.
- fsync does not request macOS F_FULLFSYNC. Power-loss same-length damage
  falls under the accepted length-only gap.
- The embedded rung overrides inherited MSB_LIBKRUNFW_PATH.
- User-selected XDG_CACHE_HOME inside the state root overlaps those locations.
- Linux release packaging is deferred; non-macOS feature builds require both
  explicit payload source variables.
- Quarantine/Gatekeeper behaviour is not certified: M6 needs a Safari download
  and Archive Utility extraction of an actual distribution, not an xattr simulation.

## Rejected alternatives

- In-process runtime: the SDK execs msb.
- Upstream runtime downloads: missing patched libkrun.
- Re-signing extracted files: destroys the embedded entitlement identity.
- TMPDIR: ephemeral, not a persistent content-addressed cache.
- Self-healing mismatch: would hide damaged or replaced runtimes.
- MSB_HOME/state-root unpack: violates rejected-launch state emptiness.
- PreparedLaunch refactor: unnecessary launch restructuring; location preserves
  the invariant without moving the pre-Tokio environment writes.
- Hashing every reuse: about 0.18 s CPU per invocation.
- sha2 asm: changes the existing unified dependency feature set.
- Static libkrunfw: future replacement, not available in the current SDK.

## Verification

Build-workflow fixtures cover separate publication and failure preservation.
Unit tests cover digests, decode damage, lengths, modes, concurrency, path
ordering and exact diagnostics. The boot-free single-binary contract covers
C1–C11 including the lone-copy repro and non-vacuous rejected-launch state.
V1–V11 and native M1–M7 commands/results are recorded in the implementation
verification report. Real VM boot and quarantined download require native
operator evidence; neither is implied by the fake-payload contracts.
