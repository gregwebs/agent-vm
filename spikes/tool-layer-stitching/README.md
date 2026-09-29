# PROTOTYPE — tool-image composition by layer stitching

Throwaway. Answers **Prototype the full-fidelity composition**
(gregwebs/agent-vm#210) with evidence for
[ADR-0029](../../docs/adr/0029-compose-tool-images-by-layer-stitching.md)
(branch `adr/0029-tool-layer-stitching`). Not production code; nothing here is
tested beyond running it.

```sh
spikes/tool-layer-stitching/spike.sh     # needs docker+buildx (docker driver), agent-vm, a local base image
```

- `compose.py`: plan (identities computed from inputs) → build (generated
  `docker buildx bake`, only for tool images that aren't cached) → stitch
  (a new manifest: base layers + each tool's own layers) → export (an OCI
  archive). It prints the state after every phase. State lives in `out/`.
- `user-tool-claude-extra/`: a user `path` tool that declares **parent =
  claude**, because it runs `claude` at build time.
- `user-tool-broken/`: a tool whose build fails, to test failure handling.
- `project-layer/`: a project tooling layer chained on top, via `--layer`.

## Results (linux/arm64, colima `docker` driver + containerd store, base `agent-vm-base:dev`)

| Question | Result |
|---|---|
| All seven tools built `FROM` their parent and stitched | **Yes.** 37 layers = base 12 + dsh 4 + pi 9 + codex 2 + opencode 2 + claude 5 + copilot 2 + claude-extra 1; 1016 MB compressed. Stitching itself takes ~10 ms. |
| Config derived from the tool images | `PATH` = claude-extra, `.local/bin`, `.claude/local/bin`, `.opencode/bin`, then the base's PATH. **No other config changes** in any tool. |
| Runs | `docker run`: all 7 `--version` checks pass. **Booted in agent-vm** (msb `load_archive` → microVM, host uid 502): all 7 pass. |
| Project tooling layer on top | Builds, passes the enforced contract clauses C1–C4, and boots (`project-hello` + `claude-extra`). |
| Deterministic | Re-running with the same inputs gives the same manifest digest **and** a byte-identical archive. |
| One-tool bump (codex) | **1 tool image rebuilt** (28 s); 35 of 37 layers unchanged; re-stitch under 10 ms. The chain would rebuild codex and every layer above it (opencode, claude, copilot, claude-extra). |
| Different tool set `{dsh, claude, claude-extra}` | **0 builds**: every tool image reused; 22 layers, 477 MB; 4.9 s including the overlap scan. |
| Re-ingest into msb | First load 17.5 s. After the codex bump **17.9 s**: msb reuses EROFS by `diff_id`, but it re-reads and re-hashes every blob in the archive and rebuilds the per-image fsmeta/VMDK. A set whose layers are all already converted: 5.3 s. |
| Overlaps between tools | 554 flagged file overlaps, **all under `/tmp/node-compile-cache/`** (Node's compile cache from npm installs in dsh, pi, claude, copilot). No overlap outside `/tmp`. |
| Tools rewriting base files | **None** (the only hit is pi whiting out its own `/tmp` cache). Good news for rebasing. |
| Several bake exports into one shared OCI layout | **Refuted.** Exports that share a blob (a tool and its declared parent in the same bake) race in the layout's `ingest/` dir: toy repro failed 2/5, and the real run failed. Disjoint exports happened to pass (12/12, three runs) and a later bake appended to `index.json`, but that is not safe. **Fix used:** one staging layout per export; the composer hardlinks blobs into the shared store (skipping blobs already there) and is the only writer of `index.json`. 0/6 failures. |
| `oci-layout://` parent contexts on the launcher's `docker` driver | **Confirmed**, by digest and by tag (containerd image store; the classic store was not tested). |
| One failed tool keeps the others cached (ADR-0029 "Failure") | **Not with a single bake**: one failing target CANCELS the others and their exports never land. **Fix used:** one bake process per independent group (a root tool plus the tools that declare it as parent), run concurrently. `broken` fails and is named; codex, claude and claude-extra land; the retry builds nothing. |

### Smaller findings for the real implementation

- Bake needs `--allow=fs.read=<context>` for every build context outside the
  bake file's directory, and `--allow=fs.write=<staging>` for the export.
- Two entries in one layout with the same `org.opencontainers.image.ref.name`
  replace each other, so tags must be unique (use the identity).
- The exported archive needs **both** `io.containerd.image.name` (Docker reads
  this, and wants it fully qualified: `docker.io/library/…`) **and**
  `org.opencontainers.image.ref.name` set to the full reference (msb takes
  this as the image reference).
- A layered launch pulls its chain root from a registry even when msb already
  has it cached, so booting a local composed image under `--layer` needed a
  push to the local registry. The real implementation would pass the composed
  image to the layer build directly.
- A declared parent must come earlier in stitch order; the stitcher checks this.
