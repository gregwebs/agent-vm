# CP0: image-composition evidence and checker audit

**Evidence session:** 2026-10-02; `spikes/cp0/session-start.txt` records `2026-10-02T10:03:57Z`.
**Reconstruction snapshot:** `ec86bf869abac999c4548a4cef02975994571750`, branch `feat/228-cp1-identity-dag` (`git rev-parse HEAD`, `git branch --show-current`). The task described `feat/228-layer-dag`; this reconstruction did not switch branches or attribute the surviving experiment to a different commit.
**Landing path:** `docs/research/image-composition-cp0-evidence.md`, following this repository's dated research-record convention.

This is evidence, not an ADR amendment, an enforcement implementation, or a portability acceptance test. Sources below are repository-root-relative paths. Raw `spikes/cp0/` evidence is local/untracked; this document preserves the decisive counts, paths and commands, not the large OCI layouts. **Recorded** means an earlier experiment's surviving output; **rechecked** means read-only inspection or an in-memory test during reconstruction; **inferred** means a conclusion drawn from those sources. No OCI blob was read during reconstruction; no builds, Docker reconfiguration, colima restart, or spike-writing scripts were run.

Authorities: [ADR-0031](../adr/0031-tool-image-contract.md), [ADR-0032](../adr/0032-one-layer-kind.md), [image-composition specification](../specs/image-composition.md), and [domain vocabulary](../../CONTEXT.md). ADR-0031's table, incorporating ADR-0032, is normative.

**Scope of this record.** This reproduces the CP0 evidence record's analysis body,
its exact T3 path evidence (Appendix A) and its descriptor annotations
(Appendix B). The original document's Appendix C — an exhaustive per-path dump of
the S1 sibling-overlap arrays — is omitted for size; it remains in the untracked
`spikes/cp0/` evidence alongside the raw OCI layouts. T3 is the appendix the
[ADR-0035](../adr/0035-declared-system-packages.md) decision rests on.

## Verdict: U7 is raised

**Inference, high confidence:** strict T3 rejects every measured apt-based example, and even installing just `tree` above this base. This is not merely the already-known Chrome account-appending problem. Moving account declarations into the union account layer does not repair the package-manager writes, caches, logs, PAM changes, or upgraded base binaries.

**Minimal measured counterexample:** `spikes/cp0/probes/apt-min/Dockerfile` installs one package:

```dockerfile
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
RUN apt-get update \
 && apt-get install -y --no-install-recommends tree \
 && rm -rf /var/lib/apt/lists/*
```

A single protected path, **`/var/lib/dpkg/status`**, suffices to disprove T3 compliance. `lists/base.json`'s final 65,536-byte sample (byte offset 3,170,962) contains its final listed regular-file entry: size **223181**, SHA-256 **`6bc52618f9759dce758897aa8e8d4c82f89a37cd0a951a4396c667687d2372cf`**. The complete final own-layer sample from `lists/probe-apt-min.json` contains size **223712**, SHA-256 **`8b44ebdcddc172a30472c43d62bbe134cd062d62f2a46655d5a342434b180713`**. The latter entry is an ordinary non-directory write at exactly the same path; root-marker normalization bugs do not explain it. `t3/probe-apt-min.json` records `modifies-base-file`. `logs/probe-apt-min.log` independently records unpacking and setting up `tree`. These sizes/hashes are cached-list evidence, not newly hashed blob bytes.

An even byte-identical write, `/var/lib/dpkg/lock`, is forbidden by literal T3: identical contents are not an exception. The non-apt control adds only `/opt/probe/file` and reports no violations (`probes/apt-none/Dockerfile`, `t3/probe-apt-none.json`; final own-layer list sample).

### Recorded T3 findings, by recipe and cause

Every number in this table is computed from `spikes/cp0/t3/<name>.json:violations` and cross-checked against the corresponding `.violations.txt` where present. `probe-apt-none` has no text companion. Counts are **finding events**, not necessarily distinct paths. The cause names come from `summarize.py:CLASSES`: they are path-based explanatory classifications, not proof of which maintainer script wrote each file.

| Recipe / source | Findings | Distinct paths | apt/dpkg DB | Logs | debconf | ldconfig | Accounts | PAM | Repacked/upgraded base package files |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `images/tools/dsh` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `images/tools/pi` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `images/tools/codex` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `images/tools/opencode` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `images/tools/claude` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `images/tools/copilot` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `examples/layers/chrome-devtools` | 36 | 36 | 6 | 5 | 4 | 2 | 8 | 11 | 0 |
| `examples/layers/go-dev` | 336 | 336 | 22 | 5 | 2 | 2 | 0 | 0 | 305 |
| `examples/layers/rust-dev` | 337 | 337 | 23 | 5 | 2 | 2 | 0 | 0 | 305 |
| `examples/layers/wirenboard-cpp` | 363 | 347 | 29 | 9 | 8 | 4 | 8 | 0 | 305 |
| `probe-apt-min` (colima) | 9 | 9 | 5 | 4 | 0 | 0 | 0 | 0 | 0 |
| `dc-probe-apt-min` (agent-vm-dc, same recipe) | 9 | 9 | 5 | 4 | 0 | 0 | 0 | 0 | 0 |
| `probe-apt-none` (colima control) | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

The exact offending paths, grouped by cause and carrying own-layer ordinal and finding kind, are in Appendix A. There are no offending paths reported for the zero rows. No saved T3 audit exists for `dc-probe-apt-none` or its warm export; successful build/export is not a saved zero-violation check.

**Recorded and rechecked:** `go-dev`, `rust-dev` and `wirenboard-cpp` have exactly the same 305 package-file path/kind pairs. Their build logs explicitly show `libc6:arm64` and `libc-bin` upgraded from **`2.41-12+deb13u3`** to **`2.41-12+deb13u4`** (`logs/{go-dev,rust-dev,wirenboard-cpp}.log`, lines containing `Unpacking libc`). Chrome's log instead reports no upgrades. Thus a package-manager-state-only exemption would not repair the measured development recipes' base binary replacement.

### Recorded S1 findings

`spikes/cp0/s1-tools.json` contains **15** sibling pairs among the **6** shipped tool recipes: no non-exempt same-path overlaps. `s1-all.json` contains **45** pairs among those tools and the **4** examples, not the probes. Its non-exempt overlaps occur in exactly these pairs:

| Pair | Reported overlapping paths |
|---|---:|
| chrome-devtools × go-dev | 22 |
| chrome-devtools × rust-dev | 23 |
| chrome-devtools × wirenboard-cpp | 133 |
| go-dev × rust-dev | 5251 |
| go-dev × wirenboard-cpp | 5251 |
| rust-dev × wirenboard-cpp | 5326 |

Source: `s1-all.json:<pair>.overlaps` lengths; every other pair has none. Pairwise total **16006** is a sum of pair lengths, not a distinct global path count. Appendix A enumerates **T3** offending paths; S1 additionally includes newly introduced shared toolchain files.

Both S1 files sum to **3309** tmpfs-exempt pair/path occurrences: **551** each for claude/copilot, claude/dsh, claude/pi, copilot/dsh, copilot/pi, and **554** for dsh/pi; other pairs contribute none. Samples are `/tmp/node-compile-cache/v22.23.3-arm64-2b4477fa-0/...` (`tmpfs_exempt_sample`). This is **correctly exempt for S1**, not missing findings: ADR-0031 and `crates/agent-vm/src/guest_paths.rs:TMPFS_GUEST_PREFIXES` explicitly exempt `/tmp`, `/run`, `/dev/shm`, `/var/run`. Counts are occurrences per pair, not unique files. T3 has no corresponding tmpfs exemption. A missing non-tmpfs subtree overlap, however, is a checker defect, not an exemption.

### Candidate resolutions — no choice made here

| Candidate | Cost / changes required | What breaks or remains unresolved |
|---|---|---|
| Amend ADR-0031/0032 to exempt or specially reconcile package-manager state | Define precise state ownership and merging/reconstruction semantics; coordinate T3, S1 and destination/rebase checks; add negative fixtures. A broad allow-list is an explicit contract change. | Allowing apt/dpkg DB copies to win by order can lose other layers' installed-package records. State exemptions alone do not cover the measured libc replacements, ldconfig, PAM or account writes. Broad exceptions weaken additive/rebase guarantees. Generated accounts still require one owner. |
| Move system-package installation into the base recipe, leaving examples to add their private tool payloads | Maintain shared/custom base recipes containing the needed packages; move account identity to declared union accounts; ensure later recipes do not rerun apt over base state. Larger foundations and base changes amplify downstream work. Preserve the root's non-circular identity boundary. | Changes examples' try-and-adopt ergonomics and package-selection independence; potentially adds unwanted packages to all users of that foundation. It does not demonstrate that every post-install hook or private installer is additive; those must be rechecked. |
| Narrow what T3 protects (e.g. explicit launcher/account/critical paths rather than every base path) | Amend the authority, define an auditable protection set and destination checks, and test package upgrades against it. | Loses the current universal no-base-overwrite precondition for rebase. S1 still rejects unrelated examples sharing apt state/toolchain files unless independently redesigned; ordering siblings is not a legal resolution today. Critical libc/account changes can still hit a narrower set. |

**Scope inference:** CP3/CP4 cannot promise migration of these recipes under unchanged strict T3 merely by changing authoring syntax and account appends. An explicit decision is needed; this document deliberately does not select one.

## Adversarial methodology audit

### What was actually implemented and exercised

`spikes/cp0/audit.py` is a throwaway cached-list checker, not faithful implementation of the whole contract:

- `list` reads each selected image layer tar, records path/type/mode/uid/gid/link target and hashes regular-file bytes. This earlier experiment therefore paid decompression plus content hashing, more than a structural-header reader. Reconstruction did **not** rerun `list` or `extract.py`.
- `own_layers` checks only the cached config's `rootfs.diff_ids` prefix and slices by parent length. All saved audited artifact headers have the base's **12** diff IDs as a prefix; counts above come from that cut (`lists/*.json` header samples; `t3/*.json:t1_prefix_ok`). Every sampled header's manifest digest matches its stage's current `index.json`. This is provenance corroboration, not digest verification of blobs or completeness of entries.
- T1's pre-build final-`FROM ${BASE_IMAGE}` text check is absent. The checker additionally requires at least one own layer, stricter than T1's prefix wording. A failed prefix still does not stop T3/S1 processing.
- T3 (`base_fs`, `apply_layer`, `classify`) builds an effective base path map and scans all own-layer entries, not merely the final effective artifact. It reports even identical copy-ups and same-target symlink rewrites. Normal subdirectory whiteouts/opaques expand against the base, and non-directory replacement of a base directory is detected. Plain new children under base directories are allowed.
- S1 (`effects`, `s1_pairs`) intersects lexical non-directory-write/deletion sets, exempting only the documented tmpfs prefixes. Its input model assumes every supplied artifact is a sibling. There is no direct/transitive ancestry model, actual-parent attribution, or generated-account exemption/validation model. A union-account layer could be included in a protected foundation input, but the script does not distinguish or validate it.
- T5 (`resolve`, `cmd_t5`) exists: resolve the first existing PATH candidate through symlinks and check regular-file type, other-execute, and ancestor other-search bits. **No persisted `audit.py t5` invocation/result for the shipped set was found**, but all shipped build logs record successful **recipe-time T5** checks through the separate `images/recipe-contract/check-tool-access.py`. These are not T3/S1 checks; see the evidence below.
- T2 and T4 validation and S2, S3, S4 are absent. Capturing config/platform is not checking additive PATH, unchanged non-Env config, command shadowing, parent-relative Env/label merging, reserved env declarations, or sibling env collisions. T6/T7 remain documented obligations, not exercised validations.

**Enforcement readiness:** ADR-0031's T5 consequence and the aligned ADR-0032 implementation handoff in `docs/specs/image-composition.md` require running T5 against the shipped set before enforcement. **The recipe-time prerequisite was exercised successfully for the measured shipped set**, through a different, stronger checker than `audit.py t5`. The evidence does **not** establish a run of the new exported-list T5 enforcement implementation, its equivalence to the recipe checker, or full contract enforcement. T3/S1 zero arrays alone would not satisfy T5. Nor did this spike enforce “hard error / never index a failing artifact”: build/export occurs before the audit, findings are JSON, and `cmd_t3` does not fail its process on violations. Saved violating exports are expected evidence, not healthy validated product artifacts.

### Separate shipped recipe-time T5 evidence

Rechecked `images/tools/<name>/verify-<name>.sh` calls and byte equality of each `contract/check-tool-access.py` against `images/recipe-contract/check-tool-access.py` (`cmp -s`; all match). The canonical helper resolves command symlinks, rejects non-directory traversal, requires **all-class** execute/search bits `(mode & 0o111) == 0o111`, checks script readability and shebang interpreters, and rejects observed access ACLs. This is substantially stronger than the spike's other-execute-only model. It intentionally rejects a present-but-unsuitable first PATH candidate, so that behavior is a stricter repository policy, not evidence that a shipped command failed.

| Recipe | Exact saved successful access output (without BuildKit prefix) | Log source |
|---|---|---|
| dsh | `tool-access: ok /opt/agent-vm/dsh/node_modules/@deepseek-ai/dsh/lib/bin.js`; `tool-access: ok /opt/agent-vm/dsh/node_modules/pnpm/bin/pnpm.mjs` | `logs/dsh.log:42-43` |
| pi | `tool-access: ok /usr/local/bin/pi`; `tool-access: ok /opt/agent-vm/pi/node_modules/@earendil-works/pi-coding-agent/dist/bundle/cli.js` | `logs/pi.log:64-65` |
| codex | `tool-access: ok /opt/agent/.codex/packages/standalone/releases/0.159.3-aarch64-unknown-linux-musl/bin/codex` | `logs/codex.log:36` |
| opencode | `tool-access: ok /opt/agent/.opencode/bin/opencode` | `logs/opencode.log:44` |
| claude | `tool-access: ok /opt/agent/.local/share/claude/versions/2.1.286` | `logs/claude.log:86` |
| copilot | `tool-access: ok /usr/lib/node_modules/@github/copilot/npm-loader.js` | `logs/copilot.log:34` |

Pi also records `--content` readability checks for `/opt/agent-vm/pi-extensions/guest-credential-warning.js` and `/opt/agent-vm/pi-packages/node_modules/pi-claude-bridge/src/index.ts` (`logs/pi.log:66-67`; `verify-pi.sh:382-385`). These are selected required data checks, not a universal T7 audit. The successful recipe checks are build-time filesystem evidence, not a kernel run for every uid, a re-audit after export/stitch/rebase, or proof that `audit.py t5` is sound.

### Specific soundness findings

| Surface | Rechecked finding and implication |
|---|---|
| Root whiteouts/opaque markers; root dotfiles | **Concrete T3 false negative.** `norm` uses `name.lstrip('./')`, a character-set strip, not removal of an exact `./` prefix. `.wh.passwd` becomes `/wh.passwd`; `.wh..wh..opq` becomes `/wh..wh..opq`. The marker branches in `classify`, `effects` and `apply_layer` are bypassed. A root deletion/hide is silently treated as a new ordinary entry. Root dotfile aliases are also mangled; `.secret` and `new/../.secret` get different keys despite referring to the same root path. |
| Subdirectory deletion vs sibling-added content | **Concrete S1 false negative.** `effects` expands subtree deletion only against `base_paths`, not sibling writes. A whiteout `opt/.wh.new` or opaque `opt/new/.wh..wh..opq` misses another sibling's `/opt/new/child` when absent from the base. |
| File/directory prefix collisions | **Concrete S1 false negative.** One sibling writing non-directory `/opt/new` and another adding directory `/opt/new` plus `/opt/new/child` yields no exact-path non-directory intersection, despite destructive overlay interference. T3 detects this if `/opt/new` already exists as a base directory, but not if introduced only by siblings. |
| Base file/symlink ancestors | Ordinary new writes below a base non-directory ancestor are detected (`replaces-base-nondir-ancestor`), including a base symlink; this is conservative rather than proper alias resolution. Whiteout/opaque branches return before that ancestor check, so `opt/gen/.wh.x` below base regular file `/opt/gen` passes. Such inputs should at least be rejected as invalid/unsafe, not blessed. |
| Symlinks and hardlinks | T3 catches replacement/retargeting at an existing lexical base path. S1 does not resolve path aliases, so different lexical spellings through symlinked ancestors can miss physical collisions (some are independently caught by conservative T3). Own-layer symlink effects are not modelled between scanned entries. Hardlinks at protected destination paths are caught as non-directory writes, but new hardlink destinations do not account for source inode aliases; the effective FS model never resolves hardlinks. Merely adding a hardlink to a base file is not itself proved a T3 violation; metadata/shared-inode effects are unmodelled. |
| Modes / ownership / extended metadata | Non-directory copy-ups are violations even if bytes/mode/ownership match; planted chmod with identical bytes is detected. Shared directory mode/uid/gid changes are recorded but deliberately **not** violations. This matches T3's literal non-directory-entry restriction, not a stronger immutable-directory policy. No measured `shared-dir-metadata-changed` occurs in saved `t3/*.json`. Xattrs/ACLs/PAX metadata are not retained or validated. |
| Partial, stale or unrelated lists | `cmd_list` has no filtering or explicit truncation: it iterates tar entries. But checks trust the cached JSON: no completeness certificate, descriptor/diff-ID recomputation, layer-count/entry integrity guard, or fail-closed behavior for a mismatched prefix. Omitting an entry can produce zero findings. `pick_manifest` selects the first descriptor and first nested Linux image, not necessarily a requested tag/host architecture. Multi-entry `conc`/`shared-test` layouts are not suitable inputs without explicit selection. |
| Base changes after list capture | Saved audited headers match current single-image stage indexes, mitigating accidental layout mismatch in this evidence. This does not prove payload authenticity or list completeness. Files added in a later destination base are absent from the old map and require reconstruction/fresh T3 checks; the script does not implement the destination-rebase workflow. |
| Path boundaries and case | Normal subdirectory normalization is POSIX, case-sensitive, and tmpfs containment uses exact prefix or prefix plus `/`; `/tmp-not/a` is **not** exempt. Linux case sensitivity is appropriate. There is no malformed/escaping-path validation, and leading-dot stripping is unsound. |
| T5 limitations | Not an actual execution check. It can traverse a synthetic intermediate regular file as if it were a directory; it tests only other-search/execute bits rather than all owner/group identity cases; it does not check ACLs, scripts' readable/interpreter dependencies, or loaders. Returning on the first non-executable existing PATH candidate is stricter than execution search that could use a later candidate; the canonical recipe checker explicitly chooses this stricter policy too, so it is not uniquely a spike bug. Hardlink executables are falsely rejected rather than resolved. These gaps cannot be interpreted as shipped failures or passes without running a corrected check. |

**Planted tests, rechecked without disk writes:** executing `audit.py`'s definitions in memory with `PYTHONDONTWRITEBYTECODE=1 python3 -` gives `SELFTEST OK` for its own fixtures, yet misses the planted root whiteout and opaque, both producing `new-nondir, violation=False`. The planted sibling subtree whiteout, opaque and file/directory prefix collision each return `overlaps=[]`. Additional synthetic `cmd_t5` calls incorrectly return `T5=true` for an intermediate regular-file component and for a uid-1000-owned command with mode `0o1` (owner lacks execute), while correctly rejecting a `0o700` ancestor directory. These are model tests, not shipped-set or kernel execution tests. A normal `/etc/passwd` overwrite, identical-byte chmod, base-directory replacement, subdirectory base whiteout and subdirectory base opaque all fire. `/tmp/a` overlap is exempt and `/tmp-not/a` overlap is reported. Reproduction code and exact outputs are in the companion CP0 report.

**Applicability recheck:** persisted `t3/*.json:all` entries contain no root-level markers or root normalization mismatches. The only recorded own-layer marker is Pi's `tmp/.wh.node-compile-cache`, classified `whiteout-own-only`; its sibling-deletion effects are hidden by the correctly applicable tmpfs exemption. A separate prefix scan over the shipped tools' recorded `new-nondir` writes versus other tools' recorded paths found no non-tmpfs destructive prefix candidate. These are checks of the surviving classified inputs, not an independent full tar relist.

**Bottom line:** the shipped tools' zero result is trustworthy **for ordinary lexical base-path writes and exact same-path sibling non-directory overlaps in the recorded, complete-if-authentic lists**. The saved raw classified entries do not exercise the demonstrated root-marker/prefix gaps. It is untrustworthy **as a general enforcement checker for root whiteouts/opaques, sibling-added subtree deletions, file/directory prefix collisions, alias/shared-inode effects, incomplete/stale lists, real DAG ancestry, or S2–S4 compliance / the spike's T5 soundness**. Separate recipe-time T5 successes are real positive evidence, not a consequence of the zero T3/S1 result. The positive apt counterexample remains sound despite those specific false negatives.

## Builder, export, annotation and storage facts

### Builder coverage

Recorded `builder-docker-inspect.txt`: **`colima`**, driver **`docker`**, endpoint `colima`, BuildKit **`v0.30.0`**, containerd worker/executor labels. `builder-dc-inspect.txt`: **`agent-vm-dc`**, driver **`docker-container`**, endpoint `colima`, BuildKit **`v0.33.1`**, OCI worker, daemon flag `--allow-insecure-entitlement=network.host`.

`timings.txt` and corresponding log first lines attribute the base/cached base, all shipped tools, all examples and both controls to `colima`. `agent-vm-dc` built the non-apt control cold/warm and apt-min using the colima-exported base as an OCI parent context. Both builders successfully performed forced-zstd-request exports of the non-apt control. All audited list headers and inspected stage descriptors identify **linux/arm64**; neither advertised platform lists nor captured config establish a multi-platform T4 acceptance test.

**Measured narrow result:** docker-container can consume this exported local base via `oci-layout://` and export these simple children without a registry push. **Not established:** full shipped/default/DAG composition portability, independently building the local base under that driver, a cached declared catalog-layer parent, stitching/ingest/boot, or all required driver modes. This is not the acceptance-criterion portability verdict.

### Exact working invocation

Quoted from `spikes/cp0/build.sh` (do **not** rerun it for reconstruction; it removes its destination):

```bash
--parent) parent=(--build-context "agent-vm-parent=oci-layout://$2" --build-arg BASE_IMAGE=agent-vm-parent); shift 2;;
--compression) comp=",compression=$2,force-compression=true"; shift 2;;

docker buildx build --builder "$builder" --progress=plain \
  ${nocache[@]+"${nocache[@]}"} ${dockerfile[@]+"${dockerfile[@]}"} ${parent[@]+"${parent[@]}"} ${extra[@]+"${extra[@]}"} \
  --output "type=oci,dest=$dest,tar=false,name=agent-vm-cp0:$name$comp" \
  "$ctx" >"$log" 2>&1
```

`run-example.sh` supplies `--parent "$PWD/spikes/cp0/stage/base:probe"`; `run-tools.sh` supplies the same. Thus the actual parent alias option expands to:

```bash
--build-context "agent-vm-parent=oci-layout:///Users/claude/code/agent-vm/spikes/cp0/stage/base:probe" \
--build-arg BASE_IMAGE=agent-vm-parent
```

The logs' `OCI load from client` resolves base manifest **`sha256:6f09526411cc89b25444c9d6997124c7d8e1bf1646c65b593112a94bafcfdd7b`**, matching `stage/base/index.json`. The logged `docker.io/library/agent-vm-parent@sha256:...` spelling is BuildKit's alias display, not proof of a registry fetch. No bake entitlement/permission-portability claim follows from this buildx invocation.

### Annotation reality: the plan's equality assumption is wrong

Annotations are on **manifest descriptors inside `index.json`**, not necessarily top-level index or image-config annotations. For the requested output name `agent-vm-cp0:go-dev`, actual `stage/go-dev/index.json` is:

```json
{
  "io.containerd.image.name": "docker.io/library/agent-vm-cp0:go-dev",
  "org.opencontainers.image.ref.name": "go-dev",
  "org.opencontainers.image.created": "2026-10-02T10:15:31Z"
}
```

The first is a fully normalized image name; the second is only its tag component. They do **not** both equal the requested full ref, nor do they equal one another. If a downstream plan means tag by “ref name,” only the second equals it. The base was retagged to **`probe`**, not `base`: its current descriptor has `io.containerd.image.name=docker.io/library/agent-vm-cp0:probe`, `org.opencontainers.image.ref.name=probe`, `org.opencontainers.image.created=2026-10-02T10:06:53Z`; that is why parent context `base:probe` works. `build.sh` alone does not show the historical retag command. Exact values for every inspected stage descriptor are in Appendix B.

Inspected ordinary indexes are OCI indexes containing an OCI image-manifest descriptor with linux/arm64 platform, rather than a tar archive (`tar=false`). `stage/conc/index.json` has multiple tags; `shared-test/index.json` also has multiple descriptors. A tag is not a payload assertion: notably `shared-test`'s `apt-none` descriptor points at the same **`dcea64d...`** manifest as `probe-apt-min`, not the standalone non-apt control's **`aa39f634...`**. Do not use that tag as evidence for the control's contents or safe concurrent exports.

### Compression: verified gzip; zstd request/export exercised, codec not independently established

Recorded `logs/list.log` says all shipped tools and examples' layers use **gzip**. Sampled layer descriptors in `lists/*.json` use `application/vnd.oci.image.layer.v1.tar+gzip`; both minimal apt own-layer samples and the non-apt own-layer sample also explicitly say `compression=gzip`.

`timings.txt` records `compression=zstd,force-compression=true`, exit success, for `zstd-colima` and `zstd-agent-vm-dc`; their logs show a cached non-apt RUN and layer-export work. Their indexes reference distinct manifests **`1784ebb5064c5a6b26269a48f249fb34a79c5877796d7cef35a6d5f3a3f696ea`** and **`d889b8309a23863f2e73bc57979944be06a1ef0c0e73895d4a392159566ffc29`**, respectively. Thus **both exporters accepted and completed the forced-zstd request**. Inference: changed layer encoding is consistent with these changed manifests and smaller stat-only aggregate blob sizes, but the index itself does not declare layer compression.

`stage/zstd-noforce-{colima,agent-vm-dc}` has the **same manifest digest as each builder's ordinary non-apt export**, consistent with reuse rather than recompressing cached gzip. `logs/zstd-noforce.log` shows a colima cached RUN, fast export and the already-forced `1784ebb...` manifest; it cannot be unambiguously matched to the currently retained noforce indexes. Additional `zstd-noforce-nc-*` indexes exist with new digests and `zn` tags, but no saved matching invocation/log/timing proves their precise flags or codec. Directory names are not measurements.

There is **no saved zstd-layer list**. Under the explicit no-OCI-blob-read constraint, this reconstruction did not inspect the manifest blobs or compression magic. Accordingly actual zstd media types/payload decoding, all-layer recompression, zstd ingest/boot, size ratio and portability beyond successful request/export are **unestablished**, not silently inferred. The safe downstream claim is gzip checked, forced-zstd exporter options exercised successfully on both builders, actual codec still to verify.

### Hardlink/shared-layout evidence

`dedupe.sh` historically creates `shared/blobs/sha256` and `shared/oci-layout`, links new digest files there, compares equal-digest duplicate bytes with `cmp -s`, and relinks stage duplicates with `ln -f`. It was inspected, **not rerun**. Reconstruction used `os.stat` only: the base manifest file and its shared copy have identical device/inode and link count **3**. This proves hardlinkability on the current filesystem, not on arbitrary filesystems.

Current stat-only census: **75** shared digest filenames; **389** stage blob filenames; **220** stage names already share their shared-copy inode, **109** have a shared digest name but a different inode, and **60** have no shared digest name. Source command: iterate `stage/*/blobs/sha256/*` and compare `(st_dev, st_ino)` to `shared/blobs/sha256/<basename>`; no bytes read. Thus historical dedupe was not complete for all currently retained later experiments. `shared/` contains only `oci-layout` and `blobs`, **no `index.json`**: it is a shared blob pool, not an indexed composition cache or ingested/bootable image. Nothing here establishes atomic publication, locking, GC safety, cross-filesystem hardlinks, or safe direct concurrent export. The `conc` index alone is not a race stress test.

## Measured timings and gate cost

All wall-clock seconds below are from `spikes/cp0/timings.txt` via `build.sh`'s integer `date +%s` subtraction. They include build+export, not list hashing, T3/S1, dedupe, stitching, ingest or VM boot. Corresponding `logs/<artifact>.log` corroborate build/cache/export behavior.

| Artifact | Builder / driver | First measured run (s) | Warm repeat (s) | Cache qualification |
|---|---|---:|---:|---|
| base | colima / docker | 53 | 2 | First has explicit `--no-cache`; warm RUNs cached |
| dsh | colima / docker | 17 | — | First recorded; no forced cache disable |
| pi | colima / docker | 15 | — | First recorded; cached base, own build work |
| codex | colima / docker | 25 | — | Same qualification |
| opencode | colima / docker | 12 | — | Same qualification |
| claude | colima / docker | 37 | — | Same qualification |
| copilot | colima / docker | 16 | — | Same qualification |
| chrome-devtools | colima / docker | 51 | — | First recorded, cached base, own build work |
| go-dev | colima / docker | 99 | — | Same qualification |
| rust-dev | colima / docker | 70 | — | Same qualification |
| wirenboard-cpp | colima / docker | 79 | — | Same qualification |
| probe-apt-min | colima / docker | 6 | — | First recorded, parent cached |
| probe-apt-none | colima / docker | 2 | — | First recorded; RUN executed, not a warm repeat |
| probe-apt-none | agent-vm-dc / docker-container | 8 | 2 | First imports/extracts base; repeat cached |
| probe-apt-min | agent-vm-dc / docker-container | 6 | — | Parent already imported; not cold-builder timing |
| forced-zstd non-apt export | colima / docker | 8 | — | Cached RUN; recompression/export experiment |
| forced-zstd non-apt export | agent-vm-dc / docker-container | 6 | — | Cached RUN; recompression/export experiment |

“First recorded” is **not** a clean-machine cold cache. `cache-ids-before.txt` records pre-existing BuildKit cache IDs; no cache deletion happened during reconstruction. Even base `--no-cache` does not erase upstream image/network caches. Warm per-tool, per-example, dc base, noforce and whole-composition timings are not measured in `timings.txt`.

**Inference, arithmetic only:** base plus shipped tool build/export durations sum to **175 s = 53 + (17+15+25+12+37+16)**; adding the examples yields **474 s = 175 + (51+99+70+79)**. These are serial component-cost proxies on this host/cache state, not timings of a full integration gate, cold machine, parallel DAG, or alternate builder. A gate that also validates/stitches/ingests/boots must budget additional unmeasured work; neither the warm base's 2 s nor the dc control's 2 s bounds a warm complete gate. The examples currently cannot pass unchanged strict enforcement irrespective of budget.

## CP0 did not establish

- Classic Docker image-store support or failure. Containerd-worker evidence is not a classic-store test; colima was not restarted or reconfigured.
- A full docker-container portability verdict: shipped set, independent local-base build, declared/cached layer parent, composed config/manifest, ingest and VM boot were not exercised as an end-to-end acceptance test.
- An exported-list T5 enforcement run or equivalence to the stronger, successfully exercised shipped recipe-time T5 checks; T2/T4 enforcement, S2/S3/S4 compliance, T6 capability honesty or universal T7 readability. Selected Pi data readability checks do not prove T7 for everything.
- Actual zstd payload/media-type verification, decode/ingest/boot, exact noforce/nc flags, or reproducible compression ratios. Successful forced-zstd request/export is narrower evidence.
- Whole-gate timing, validation/list cost, stitch/archive/ingest/boot/download cost, truly cold machines, warm tools/examples, noforce timings, parallel speedups, or other architecture timings.
- A corrected checker's exact violation count over the OCI tar streams. Counts here are the surviving checker's reported events, with positive ordinary-path findings supported by cached inputs; not an independent full relist.
- Digest-authentic or completeness-certified cached lists, malformed-tar handling, hardlink/xattr/ACL fidelity, destination-rebase checks, ABI compatibility, or every generated-account/ancestry rule.
- Concurrent exporter safety, atomic index publication, shared-store locking/GC, cross-filesystem dedupe, deterministic assembly, or a usable shared image index. Extra stage indexes alone prove none of these.
- A resolution of U7. The candidates above require a policy decision and fresh validation; this record does not amend the contract or claim the examples cannot ever be redesigned.

## Appendix A — exact T3 paths and event kinds

Sources: `spikes/cp0/t3/<recipe>.json:violations`, verified in order against `.violations.txt`. Paths below are exact, not wildcard shorthand. `L0`, `L1`, etc. are zero-based **own-layer** ordinals. Kinds are the script's measured categories; attribution to causes is the path-based `summarize.py` inference. Repeated path lines represent separate events. The common package group is printed once and explicitly incorporated into each affected recipe; its path/kind sequence is identical in all three source outputs.

### Common package-file group (305 events; included in go-dev, rust-dev, wirenboard-cpp)

```text
L0 modifies-base-file /usr/bin/getconf
L0 modifies-base-file /usr/bin/getent
L0 modifies-base-file /usr/bin/iconv
L0 rewrites-base-symlink-same-target /usr/bin/ld.so
L0 modifies-base-file /usr/bin/ldd
L0 modifies-base-file /usr/bin/locale
L0 modifies-base-file /usr/bin/localedef
L0 modifies-base-file /usr/bin/pldd
L0 modifies-base-file /usr/bin/tzselect
L0 modifies-base-file /usr/bin/zdump
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ANSI_X3.110.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ARMSCII-8.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ASMO_449.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/BIG5.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/BIG5HKSCS.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/BRF.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/CP10007.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/CP1125.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/CP1250.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/CP1251.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/CP1252.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/CP1253.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/CP1254.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/CP1255.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/CP1256.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/CP1257.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/CP1258.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/CP737.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/CP770.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/CP771.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/CP772.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/CP773.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/CP774.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/CP775.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/CP932.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/CSN_369103.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/CWI.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/DEC-MCS.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/EBCDIC-AT-DE-A.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/EBCDIC-AT-DE.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/EBCDIC-CA-FR.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/EBCDIC-DK-NO-A.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/EBCDIC-DK-NO.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/EBCDIC-ES-A.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/EBCDIC-ES-S.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/EBCDIC-ES.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/EBCDIC-FI-SE-A.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/EBCDIC-FI-SE.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/EBCDIC-FR.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/EBCDIC-IS-FRISS.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/EBCDIC-IT.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/EBCDIC-PT.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/EBCDIC-UK.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/EBCDIC-US.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ECMA-CYRILLIC.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/EUC-CN.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/EUC-JISX0213.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/EUC-JP-MS.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/EUC-JP.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/EUC-KR.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/EUC-TW.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/GB18030.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/GBBIG5.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/GBGBK.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/GBK.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/GEORGIAN-ACADEMY.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/GEORGIAN-PS.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/GOST_19768-74.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/GREEK-CCITT.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/GREEK7-OLD.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/GREEK7.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/HP-GREEK8.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/HP-ROMAN8.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/HP-ROMAN9.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/HP-THAI8.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/HP-TURKISH8.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM037.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM038.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1004.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1008.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1008_420.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1025.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1026.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1046.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1047.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1097.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1112.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1122.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1123.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1124.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1129.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1130.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1132.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1133.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1137.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1140.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1141.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1142.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1143.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1144.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1145.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1146.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1147.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1148.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1149.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1153.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1154.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1155.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1156.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1157.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1158.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1160.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1161.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1162.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1163.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1164.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1166.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1167.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM12712.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1364.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1371.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1388.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1390.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM1399.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM16804.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM256.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM273.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM274.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM275.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM277.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM278.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM280.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM281.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM284.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM285.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM290.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM297.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM420.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM423.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM424.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM437.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM4517.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM4899.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM4909.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM4971.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM500.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM5347.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM803.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM850.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM851.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM852.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM855.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM856.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM857.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM858.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM860.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM861.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM862.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM863.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM864.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM865.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM866.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM866NAV.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM868.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM869.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM870.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM871.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM874.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM875.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM880.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM891.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM901.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM902.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM903.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM9030.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM904.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM905.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM9066.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM918.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM921.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM922.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM930.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM932.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM933.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM935.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM937.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM939.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM943.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IBM9448.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/IEC_P27-1.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/INIS-8.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/INIS-CYRILLIC.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/INIS.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ISIRI-3342.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ISO-2022-CN-EXT.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ISO-2022-CN.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ISO-2022-JP-3.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ISO-2022-JP.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ISO-2022-KR.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ISO-IR-197.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ISO-IR-209.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ISO646.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ISO8859-1.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ISO8859-10.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ISO8859-11.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ISO8859-13.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ISO8859-14.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ISO8859-15.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ISO8859-16.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ISO8859-2.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ISO8859-3.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ISO8859-4.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ISO8859-5.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ISO8859-6.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ISO8859-7.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ISO8859-8.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ISO8859-9.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ISO8859-9E.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ISO_10367-BOX.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ISO_11548-1.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ISO_2033.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ISO_5427-EXT.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ISO_5427.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ISO_5428.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ISO_6937-2.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/ISO_6937.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/JOHAB.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/KOI-8.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/KOI8-R.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/KOI8-RU.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/KOI8-T.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/KOI8-U.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/LATIN-GREEK-1.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/LATIN-GREEK.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/MAC-CENTRALEUROPE.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/MAC-IS.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/MAC-SAMI.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/MAC-UK.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/MACINTOSH.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/MIK.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/NATS-DANO.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/NATS-SEFI.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/PT154.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/RK1048.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/SAMI-WS2.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/SHIFT_JISX0213.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/SJIS.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/T.61.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/TCVN5712-1.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/TIS-620.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/TSCII.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/UHC.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/UNICODE.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/UTF-16.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/UTF-32.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/UTF-7.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/gconv/VISCII.so
L0 rewrites-base-file-identical-bytes /usr/lib/aarch64-linux-gnu/gconv/gconv-modules
L0 rewrites-base-file-identical-bytes /usr/lib/aarch64-linux-gnu/gconv/gconv-modules.cache
L0 rewrites-base-file-identical-bytes /usr/lib/aarch64-linux-gnu/gconv/gconv-modules.d/gconv-modules-extra.conf
L0 rewrites-base-file-identical-bytes /usr/lib/aarch64-linux-gnu/gconv/libCNS.so
L0 rewrites-base-file-identical-bytes /usr/lib/aarch64-linux-gnu/gconv/libGB.so
L0 rewrites-base-file-identical-bytes /usr/lib/aarch64-linux-gnu/gconv/libISOIR165.so
L0 rewrites-base-file-identical-bytes /usr/lib/aarch64-linux-gnu/gconv/libJIS.so
L0 rewrites-base-file-identical-bytes /usr/lib/aarch64-linux-gnu/gconv/libJISX0213.so
L0 rewrites-base-file-identical-bytes /usr/lib/aarch64-linux-gnu/gconv/libKSC.so
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1
L0 rewrites-base-file-identical-bytes /usr/lib/aarch64-linux-gnu/libBrokenLocale.so.1
L0 rewrites-base-file-identical-bytes /usr/lib/aarch64-linux-gnu/libanl.so.1
L0 modifies-base-file /usr/lib/aarch64-linux-gnu/libc.so.6
L0 rewrites-base-file-identical-bytes /usr/lib/aarch64-linux-gnu/libc_malloc_debug.so.0
L0 rewrites-base-file-identical-bytes /usr/lib/aarch64-linux-gnu/libdl.so.2
L0 rewrites-base-file-identical-bytes /usr/lib/aarch64-linux-gnu/libm.so.6
L0 rewrites-base-file-identical-bytes /usr/lib/aarch64-linux-gnu/libmemusage.so
L0 rewrites-base-file-identical-bytes /usr/lib/aarch64-linux-gnu/libmvec.so.1
L0 rewrites-base-file-identical-bytes /usr/lib/aarch64-linux-gnu/libnsl.so.1
L0 rewrites-base-file-identical-bytes /usr/lib/aarch64-linux-gnu/libnss_compat.so.2
L0 rewrites-base-file-identical-bytes /usr/lib/aarch64-linux-gnu/libnss_dns.so.2
L0 rewrites-base-file-identical-bytes /usr/lib/aarch64-linux-gnu/libnss_files.so.2
L0 rewrites-base-file-identical-bytes /usr/lib/aarch64-linux-gnu/libnss_hesiod.so.2
L0 rewrites-base-file-identical-bytes /usr/lib/aarch64-linux-gnu/libpcprofile.so
L0 rewrites-base-file-identical-bytes /usr/lib/aarch64-linux-gnu/libpthread.so.0
L0 rewrites-base-file-identical-bytes /usr/lib/aarch64-linux-gnu/libresolv.so.2
L0 rewrites-base-file-identical-bytes /usr/lib/aarch64-linux-gnu/librt.so.1
L0 rewrites-base-file-identical-bytes /usr/lib/aarch64-linux-gnu/libthread_db.so.1
L0 rewrites-base-file-identical-bytes /usr/lib/aarch64-linux-gnu/libutil.so.1
L0 rewrites-base-symlink-same-target /usr/lib/ld-linux-aarch64.so.1
L0 rewrites-base-file-identical-bytes /usr/lib/locale/C.utf8/LC_ADDRESS
L0 rewrites-base-file-identical-bytes /usr/lib/locale/C.utf8/LC_COLLATE
L0 rewrites-base-file-identical-bytes /usr/lib/locale/C.utf8/LC_CTYPE
L0 rewrites-base-file-identical-bytes /usr/lib/locale/C.utf8/LC_IDENTIFICATION
L0 rewrites-base-file-identical-bytes /usr/lib/locale/C.utf8/LC_MEASUREMENT
L0 rewrites-base-file-identical-bytes /usr/lib/locale/C.utf8/LC_MESSAGES/SYS_LC_MESSAGES
L0 rewrites-base-file-identical-bytes /usr/lib/locale/C.utf8/LC_MONETARY
L0 rewrites-base-file-identical-bytes /usr/lib/locale/C.utf8/LC_NAME
L0 rewrites-base-file-identical-bytes /usr/lib/locale/C.utf8/LC_NUMERIC
L0 rewrites-base-file-identical-bytes /usr/lib/locale/C.utf8/LC_PAPER
L0 rewrites-base-file-identical-bytes /usr/lib/locale/C.utf8/LC_TELEPHONE
L0 rewrites-base-file-identical-bytes /usr/lib/locale/C.utf8/LC_TIME
L0 modifies-base-file /usr/sbin/iconvconfig
L0 modifies-base-file /usr/sbin/ldconfig
L0 modifies-base-file /usr/sbin/zic
L0 rewrites-base-file-identical-bytes /usr/share/doc/libc-bin/copyright
L0 rewrites-base-file-identical-bytes /usr/share/doc/libc6/copyright
L0 rewrites-base-file-identical-bytes /usr/share/libc-bin/nsswitch.conf
```

### chrome-devtools

**account databases: 8 events.**

```text
L0 modifies-base-file /etc/group
L0 modifies-base-file /etc/group-
L0 modifies-base-file /etc/gshadow
L0 modifies-base-file /etc/gshadow-
L0 modifies-base-file /etc/passwd
L0 modifies-base-file /etc/passwd-
L0 modifies-base-file /etc/shadow
L0 modifies-base-file /etc/shadow-
```

**ldconfig cache: 2 events.**

```text
L0 modifies-base-file /etc/ld.so.cache
L0 modifies-base-file /var/cache/ldconfig/aux-cache
```

**PAM (pam-auth-update): 11 events.**

```text
L0 rewrites-base-file-identical-bytes /etc/pam.d/common-account
L0 rewrites-base-file-identical-bytes /etc/pam.d/common-auth
L0 rewrites-base-file-identical-bytes /etc/pam.d/common-password
L0 modifies-base-file /etc/pam.d/common-session
L0 rewrites-base-file-identical-bytes /etc/pam.d/common-session-noninteractive
L0 rewrites-base-file-identical-bytes /var/lib/pam/account
L0 rewrites-base-file-identical-bytes /var/lib/pam/auth
L0 rewrites-base-file-identical-bytes /var/lib/pam/password
L0 modifies-base-file /var/lib/pam/seen
L0 modifies-base-file /var/lib/pam/session
L0 rewrites-base-file-identical-bytes /var/lib/pam/session-noninteractive
```

**debconf cache: 4 events.**

```text
L0 modifies-base-file /var/cache/debconf/config.dat
L0 modifies-base-file /var/cache/debconf/config.dat-old
L0 modifies-base-file /var/cache/debconf/templates.dat
L0 modifies-base-file /var/cache/debconf/templates.dat-old
```

**dpkg/apt database: 6 events.**

```text
L0 modifies-base-file /var/lib/apt/extended_states
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/lock
L0 modifies-base-file /var/lib/dpkg/status
L0 modifies-base-file /var/lib/dpkg/status-old
L0 modifies-base-file /var/lib/dpkg/triggers/File
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/triggers/Lock
```

**package-manager logs: 5 events.**

```text
L0 modifies-base-file /var/log/alternatives.log
L0 modifies-base-file /var/log/apt/eipp.log.xz
L0 modifies-base-file /var/log/apt/history.log
L0 modifies-base-file /var/log/apt/term.log
L0 modifies-base-file /var/log/dpkg.log
```


### go-dev

**ldconfig cache: 2 events.**

```text
L0 modifies-base-file /etc/ld.so.cache
L0 modifies-base-file /var/cache/ldconfig/aux-cache
```

**upgraded/re-unpacked base package files: 305 events.** All paths/kinds are exactly the common group above, all at L0.

**debconf cache: 2 events.**

```text
L0 modifies-base-file /var/cache/debconf/templates.dat
L0 modifies-base-file /var/cache/debconf/templates.dat-old
```

**dpkg/apt database: 22 events.**

```text
L0 modifies-base-file /var/lib/apt/extended_states
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc-bin.conffiles
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc-bin.list
L0 modifies-base-file /var/lib/dpkg/info/libc-bin.md5sums
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc-bin.postinst
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc-bin.triggers
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc6:arm64.conffiles
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc6:arm64.list
L0 modifies-base-file /var/lib/dpkg/info/libc6:arm64.md5sums
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc6:arm64.postinst
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc6:arm64.postrm
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc6:arm64.preinst
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc6:arm64.shlibs
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc6:arm64.symbols
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc6:arm64.templates
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc6:arm64.triggers
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/lock
L0 modifies-base-file /var/lib/dpkg/status
L0 modifies-base-file /var/lib/dpkg/status-old
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/triggers/Lock
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/triggers/Unincorp
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/triggers/ldconfig
```

**package-manager logs: 5 events.**

```text
L0 modifies-base-file /var/log/alternatives.log
L0 modifies-base-file /var/log/apt/eipp.log.xz
L0 modifies-base-file /var/log/apt/history.log
L0 modifies-base-file /var/log/apt/term.log
L0 modifies-base-file /var/log/dpkg.log
```


### rust-dev

**ldconfig cache: 2 events.**

```text
L0 modifies-base-file /etc/ld.so.cache
L0 modifies-base-file /var/cache/ldconfig/aux-cache
```

**upgraded/re-unpacked base package files: 305 events.** All paths/kinds are exactly the common group above, all at L0.

**debconf cache: 2 events.**

```text
L0 modifies-base-file /var/cache/debconf/templates.dat
L0 modifies-base-file /var/cache/debconf/templates.dat-old
```

**dpkg/apt database: 23 events.**

```text
L0 modifies-base-file /var/lib/apt/extended_states
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc-bin.conffiles
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc-bin.list
L0 modifies-base-file /var/lib/dpkg/info/libc-bin.md5sums
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc-bin.postinst
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc-bin.triggers
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc6:arm64.conffiles
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc6:arm64.list
L0 modifies-base-file /var/lib/dpkg/info/libc6:arm64.md5sums
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc6:arm64.postinst
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc6:arm64.postrm
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc6:arm64.preinst
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc6:arm64.shlibs
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc6:arm64.symbols
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc6:arm64.templates
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc6:arm64.triggers
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/lock
L0 modifies-base-file /var/lib/dpkg/status
L0 modifies-base-file /var/lib/dpkg/status-old
L0 modifies-base-file /var/lib/dpkg/triggers/File
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/triggers/Lock
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/triggers/Unincorp
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/triggers/ldconfig
```

**package-manager logs: 5 events.**

```text
L0 modifies-base-file /var/log/alternatives.log
L0 modifies-base-file /var/log/apt/eipp.log.xz
L0 modifies-base-file /var/log/apt/history.log
L0 modifies-base-file /var/log/apt/term.log
L0 modifies-base-file /var/log/dpkg.log
```


### wirenboard-cpp

**ldconfig cache: 4 events.**

```text
L0 modifies-base-file /etc/ld.so.cache
L0 modifies-base-file /var/cache/ldconfig/aux-cache
L1 modifies-base-file /etc/ld.so.cache
L1 modifies-base-file /var/cache/ldconfig/aux-cache
```

**upgraded/re-unpacked base package files: 305 events.** All paths/kinds are exactly the common group above, all at L0.

**debconf cache: 8 events.**

```text
L0 modifies-base-file /var/cache/debconf/config.dat
L0 modifies-base-file /var/cache/debconf/config.dat-old
L0 modifies-base-file /var/cache/debconf/templates.dat
L0 modifies-base-file /var/cache/debconf/templates.dat-old
L1 modifies-base-file /var/cache/debconf/config.dat
L1 modifies-base-file /var/cache/debconf/config.dat-old
L1 modifies-base-file /var/cache/debconf/templates.dat
L1 modifies-base-file /var/cache/debconf/templates.dat-old
```

**dpkg/apt database: 29 events.**

```text
L0 modifies-base-file /var/lib/apt/extended_states
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc-bin.conffiles
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc-bin.list
L0 modifies-base-file /var/lib/dpkg/info/libc-bin.md5sums
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc-bin.postinst
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc-bin.triggers
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc6:arm64.conffiles
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc6:arm64.list
L0 modifies-base-file /var/lib/dpkg/info/libc6:arm64.md5sums
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc6:arm64.postinst
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc6:arm64.postrm
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc6:arm64.preinst
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc6:arm64.shlibs
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc6:arm64.symbols
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc6:arm64.templates
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/info/libc6:arm64.triggers
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/lock
L0 modifies-base-file /var/lib/dpkg/status
L0 modifies-base-file /var/lib/dpkg/status-old
L0 modifies-base-file /var/lib/dpkg/triggers/File
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/triggers/Lock
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/triggers/Unincorp
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/triggers/ldconfig
L1 modifies-base-file /var/lib/apt/extended_states
L1 rewrites-base-file-identical-bytes /var/lib/dpkg/lock
L1 modifies-base-file /var/lib/dpkg/status
L1 modifies-base-file /var/lib/dpkg/status-old
L1 rewrites-base-file-identical-bytes /var/lib/dpkg/triggers/Lock
L1 rewrites-base-file-identical-bytes /var/lib/dpkg/triggers/Unincorp
```

**package-manager logs: 9 events.**

```text
L0 modifies-base-file /var/log/alternatives.log
L0 modifies-base-file /var/log/apt/eipp.log.xz
L0 modifies-base-file /var/log/apt/history.log
L0 modifies-base-file /var/log/apt/term.log
L0 modifies-base-file /var/log/dpkg.log
L1 modifies-base-file /var/log/apt/eipp.log.xz
L1 modifies-base-file /var/log/apt/history.log
L1 modifies-base-file /var/log/apt/term.log
L1 modifies-base-file /var/log/dpkg.log
```

**account databases: 8 events.**

```text
L1 modifies-base-file /etc/group
L1 modifies-base-file /etc/group-
L1 modifies-base-file /etc/gshadow
L1 modifies-base-file /etc/gshadow-
L1 modifies-base-file /etc/passwd
L1 modifies-base-file /etc/passwd-
L1 modifies-base-file /etc/shadow
L1 modifies-base-file /etc/shadow-
```


### probe-apt-min

**dpkg/apt database: 5 events.**

```text
L0 rewrites-base-file-identical-bytes /var/lib/apt/extended_states
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/lock
L0 modifies-base-file /var/lib/dpkg/status
L0 modifies-base-file /var/lib/dpkg/status-old
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/triggers/Lock
```

**package-manager logs: 4 events.**

```text
L0 modifies-base-file /var/log/apt/eipp.log.xz
L0 modifies-base-file /var/log/apt/history.log
L0 modifies-base-file /var/log/apt/term.log
L0 modifies-base-file /var/log/dpkg.log
```


### dc-probe-apt-min

**dpkg/apt database: 5 events.**

```text
L0 rewrites-base-file-identical-bytes /var/lib/apt/extended_states
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/lock
L0 modifies-base-file /var/lib/dpkg/status
L0 modifies-base-file /var/lib/dpkg/status-old
L0 rewrites-base-file-identical-bytes /var/lib/dpkg/triggers/Lock
```

**package-manager logs: 4 events.**

```text
L0 modifies-base-file /var/log/apt/eipp.log.xz
L0 modifies-base-file /var/log/apt/history.log
L0 modifies-base-file /var/log/apt/term.log
L0 modifies-base-file /var/log/dpkg.log
```


### Zero-result recipes

`dsh`, `pi`, `codex`, `opencode`, `claude`, `copilot`, `probe-apt-none`: empty `violations` arrays; no offending paths reported. Sources: their individual `t3/*.json`. Do not extend that statement to unrecorded checks.

## Appendix B — exact descriptor annotations

Rechecked with `json.load(stage/<name>/index.json)`, iterating every `manifests` descriptor. Each row is sourced by its stage index; values below are exact. All rows use OCI image-manifest descriptor media type and linux/arm64 platform.

| Stage | `org.opencontainers.image.ref.name` | `io.containerd.image.name` | `org.opencontainers.image.created` |
|---|---|---|---|
| `base-warm` | `base-warm` | `docker.io/library/agent-vm-cp0:base-warm` | `2026-10-02T10:07:07Z` |
| `base` | `probe` | `docker.io/library/agent-vm-cp0:probe` | `2026-10-02T10:06:53Z` |
| `chrome-devtools` | `chrome-devtools` | `docker.io/library/agent-vm-cp0:chrome-devtools` | `2026-10-02T10:11:49Z` |
| `claude` | `claude` | `docker.io/library/agent-vm-cp0:claude` | `2026-10-02T10:09:24Z` |
| `codex` | `codex` | `docker.io/library/agent-vm-cp0:codex` | `2026-10-02T10:08:30Z` |
| `conc` | `c5` | `docker.io/library/agent-vm-cp0:c5` | `2026-10-02T10:21:49Z` |
| `conc` | `c4` | `docker.io/library/agent-vm-cp0:c4` | `2026-10-02T10:21:49Z` |
| `conc` | `c2` | `docker.io/library/agent-vm-cp0:c2` | `2026-10-02T10:21:49Z` |
| `conc` | `c1` | `docker.io/library/agent-vm-cp0:c1` | `2026-10-02T10:21:49Z` |
| `conc` | `c3` | `docker.io/library/agent-vm-cp0:c3` | `2026-10-02T10:21:49Z` |
| `conc` | `c6` | `docker.io/library/agent-vm-cp0:c6` | `2026-10-02T10:21:49Z` |
| `copilot` | `copilot` | `docker.io/library/agent-vm-cp0:copilot` | `2026-10-02T10:09:43Z` |
| `dc-probe-apt-min` | `dc-probe-apt-min` | `docker.io/library/agent-vm-cp0:dc-probe-apt-min` | `2026-10-02T10:20:17Z` |
| `dc-probe-apt-none-warm` | `dc-probe-apt-none-warm` | `docker.io/library/agent-vm-cp0:dc-probe-apt-none-warm` | `2026-10-02T10:20:12Z` |
| `dc-probe-apt-none` | `dc-probe-apt-none` | `docker.io/library/agent-vm-cp0:dc-probe-apt-none` | `2026-10-02T10:20:10Z` |
| `dsh` | `dsh` | `docker.io/library/agent-vm-cp0:dsh` | `2026-10-02T10:07:45Z` |
| `go-dev` | `go-dev` | `docker.io/library/agent-vm-cp0:go-dev` | `2026-10-02T10:15:31Z` |
| `opencode` | `opencode` | `docker.io/library/agent-vm-cp0:opencode` | `2026-10-02T10:08:46Z` |
| `pi` | `pi` | `docker.io/library/agent-vm-cp0:pi` | `2026-10-02T10:08:03Z` |
| `probe-apt-min` | `probe-apt-min` | `docker.io/library/agent-vm-cp0:probe-apt-min` | `2026-10-02T10:13:41Z` |
| `probe-apt-none` | `probe-apt-none` | `docker.io/library/agent-vm-cp0:probe-apt-none` | `2026-10-02T10:13:45Z` |
| `rust-dev` | `rust-dev` | `docker.io/library/agent-vm-cp0:rust-dev` | `2026-10-02T10:16:48Z` |
| `shared-test` | `apt-min` | `docker.io/library/agent-vm-cp0:apt-min` | `2026-10-02T10:21:22Z` |
| `shared-test` | `dc-none` | `docker.io/library/agent-vm-cp0:dc-none` | `2026-10-02T10:21:22Z` |
| `shared-test` | `apt-none` | `docker.io/library/agent-vm-cp0:apt-none` | `2026-10-02T10:21:32Z` |
| `wirenboard-cpp` | `wirenboard-cpp` | `docker.io/library/agent-vm-cp0:wirenboard-cpp` | `2026-10-02T10:18:39Z` |
| `zstd-agent-vm-dc` | `zstd-agent-vm-dc` | `docker.io/library/agent-vm-cp0:zstd-agent-vm-dc` | `2026-10-02T10:20:47Z` |
| `zstd-colima` | `zstd-colima` | `docker.io/library/agent-vm-cp0:zstd-colima` | `2026-10-02T10:20:41Z` |
| `zstd-noforce-agent-vm-dc` | `zn` | `docker.io/library/agent-vm-cp0:zn` | `2026-10-02T10:21:00Z` |
| `zstd-noforce-colima` | `zn` | `docker.io/library/agent-vm-cp0:zn` | `2026-10-02T10:20:58Z` |
| `zstd-noforce-nc-agent-vm-dc` | `zn` | `docker.io/library/agent-vm-cp0:zn` | `2026-10-02T10:21:10Z` |
| `zstd-noforce-nc-colima` | `zn` | `docker.io/library/agent-vm-cp0:zn` | `2026-10-02T10:21:08Z` |

