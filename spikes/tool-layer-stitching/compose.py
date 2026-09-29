#!/usr/bin/env python3
"""PROTOTYPE — throwaway. Tool-image composition by layer stitching (ADR-0029).

Answers "Prototype the full-fidelity composition" (gregwebs/agent-vm#210):

  1. plan    — input-addressed identity per tool image (parent identity,
               build-context hash, resolved version), independent of which
               other tools are selected; composed identity = hash(base,
               ordered tool identities).
  2. build   — one generated `docker buildx bake` file over the tool images
               NOT already in the shared OCI layout; parents are wired as
               `target:` (built in the same bake) or `oci-layout://` (cached).
  3. stitch  — new manifest = base layers + each tool's own layers above its
               parent, catalog order; PATH derived; other config drift and
               cross-tool path overlaps reported. Deterministic output.
  4. export  — the composed image as an OCI archive (for `docker load` /
               msb `load_archive`).

State lives in ./out/ (PROTOTYPE, wipe me). Every phase prints what it did.
"""
import argparse, gzip, hashlib, io, json, os, shutil, subprocess, sys, tarfile, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
OUT = HERE / "out"
LAYOUT = OUT / "layout"          # the ONE shared, content-addressed OCI layout
STAGE = OUT / "stage"            # one throwaway layout per bake export (see adopt())
TOOLS_DIR = REPO / "images" / "tools"

# The catalog, in declaration (= stitch) order. `parent` is the new declared
# edge (ADR-0029 Q3); None means the base. `version_arg` is the build arg the
# resolved version rides on (the "resolved version" identity input).
CATALOG = {
    "dsh":          dict(context=TOOLS_DIR / "dsh",      parent=None,     version_arg=None),
    "pi":           dict(context=TOOLS_DIR / "pi",       parent=None,     version_arg=None),
    "codex":        dict(context=TOOLS_DIR / "codex",    parent=None,     version_arg="AGENT_VERSION_CODEX"),
    "opencode":     dict(context=TOOLS_DIR / "opencode", parent=None,     version_arg="AGENT_VERSION_OPENCODE"),
    "claude":       dict(context=TOOLS_DIR / "claude",   parent=None,     version_arg="AGENT_VERSION_CLAUDE"),
    "copilot":      dict(context=TOOLS_DIR / "copilot",  parent=None,     version_arg="AGENT_VERSION_COPILOT"),
    # A user `layer = { path = … }` tool with a declared parent: it runs
    # `claude` at build time, which a FROM-base stage could not.
    "claude-extra": dict(context=HERE / "user-tool-claude-extra", parent="claude", version_arg=None),
    # Only selected explicitly (--tools …,broken): a build that fails.
    "broken":       dict(context=HERE / "user-tool-broken", parent=None, version_arg=None),
}

# Paths two tools may both write without it being a contract violation.
# Directory entries are always allowed (see overlaps()); these are files.
OVERLAP_ALLOW = set()

# Config fields a tool image may not change relative to its parent
# (PATH is handled separately — it is derived, not copied).
FROZEN_CONFIG = ["User", "WorkingDir", "Entrypoint", "Cmd", "StopSignal",
                 "ExposedPorts", "Volumes", "Labels"]

EPOCH = "1970-01-01T00:00:00Z"


def log(*a):
    print(*a, flush=True)


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# ---------------------------------------------------------------- identity --

def hash_context(d: Path) -> str:
    """Stand-in for layer::canonical_stream: relpath, exec bit, bytes."""
    h = hashlib.sha256()
    for p in sorted(d.rglob("*")):
        if p.is_file():
            rel = p.relative_to(d).as_posix()
            h.update(rel.encode() + b"\0" + (b"x" if os.access(p, os.X_OK) else b"-") + b"\0")
            h.update(p.read_bytes() + b"\0")
    return h.hexdigest()


def plan(tools, base_id, versions):
    """Identity per tool: hash(scheme, parent identity, context, version)."""
    ids = {}
    def ident(name):
        if name in ids:
            return ids[name]
        spec = CATALOG[name]
        parent_id = base_id if spec["parent"] is None else ident(spec["parent"])
        version = versions.get(name, "")
        ids[name] = sha(b"agent-vm-tool\0v2\0" + parent_id.encode() + b"\0"
                        + hash_context(spec["context"]).encode() + b"\0" + version.encode())
        return ids[name]
    for t in tools:
        ident(t)
    composed = sha(b"agent-vm-composed\0v1\0" + base_id.encode() + b"\0"
                   + "\0".join(ids[t] for t in tools).encode())
    return ids, composed


# ------------------------------------------------------------- oci layout --

def index():
    p = LAYOUT / "index.json"
    return json.loads(p.read_text()) if p.exists() else {"manifests": []}


def by_ref(ref):
    for m in index()["manifests"]:
        if m.get("annotations", {}).get("org.opencontainers.image.ref.name") == ref:
            return m
    return None


def blob(digest) -> bytes:
    algo, hexd = digest.split(":")
    return (LAYOUT / "blobs" / algo / hexd).read_bytes()


def put_blob(data: bytes) -> str:
    d = sha(data)
    p = LAYOUT / "blobs" / "sha256" / d
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists():
        p.write_bytes(data)
    return "sha256:" + d


def load_image(ref):
    desc = by_ref(ref)
    man = json.loads(blob(desc["digest"]))
    cfg = json.loads(blob(man["config"]["digest"]))
    return desc, man, cfg


def tool_tag(name, ident):
    return f"{name}-{ident[:24]}"


# ------------------------------------------------------------------ build --

def ensure_base(base_image, base_id):
    tag = f"base-{base_id[:24]}"
    if by_ref(tag):
        log(f"  base: cached in layout as {tag}")
        return tag
    log(f"  base: exporting {base_image} into the layout as {tag}")
    bake = {"target": {"base": {
        "context": str(HERE),
        "dockerfile-inline": f"FROM {base_image}\n",
        "output": [f"type=oci,dest={STAGE/tag},tar=false,name=agent-vm-tool:{tag}"]}}}
    run_bake(bake, ["base"])
    adopt(tag)
    return tag


def start_bake(bake, targets, name):
    OUT.mkdir(exist_ok=True)
    f = OUT / f"{name}.json"
    f.write_text(json.dumps(bake, indent=2))
    dirs = {t["context"] for t in bake["target"].values()} | {str(LAYOUT)}
    allows = [f"--allow=fs.read={d}" for d in sorted(dirs)] + [f"--allow=fs.write={STAGE}"]
    logf = OUT / f"{name}.log"
    proc = subprocess.Popen(["docker", "buildx", "bake", "-f", str(f), "--progress=plain",
                             "--provenance=false", "--sbom=false", *allows, *targets],
                            stdout=open(logf, "w"), stderr=subprocess.STDOUT)
    return proc, logf


def run_bake(bake, targets):
    """Bake's filesystem entitlements: every context outside the bake file's
    directory, and the layout it reads (oci-layout://) and writes, must be
    granted explicitly — a generated bake invocation has to pass these."""
    OUT.mkdir(exist_ok=True)
    dirs = {t["context"] for t in bake["target"].values()} | {str(LAYOUT)}
    allows = [f"--allow=fs.read={d}" for d in sorted(dirs)] + [f"--allow=fs.write={STAGE}"]
    f = OUT / "bake.json"
    f.write_text(json.dumps(bake, indent=2))
    cmd = ["docker", "buildx", "bake", "-f", str(f), "--progress=plain",
           "--provenance=false", "--sbom=false", *allows, *targets]
    t0 = time.time()
    r = subprocess.run(cmd, capture_output=True, text=True)
    (OUT / "bake.log").write_text(r.stdout + r.stderr)
    if r.returncode != 0:
        sys.stderr.write(r.stderr[-4000:])
        sys.exit(f"bake failed ({' '.join(targets)}); see {OUT/'bake.log'}")
    return time.time() - t0


def build_missing(tools, ids, base_tag, versions, soft_fail):
    missing = [t for t in tools if not by_ref(tool_tag(t, ids[t]))]
    for t in tools:
        log(f"  {t:13} {tool_tag(t, ids[t])}  {'BUILD' if t in missing else 'cached'}")
    if not missing:
        return [], 0.0
    targets = {}
    for t in missing:
        spec = CATALOG[t]
        p = spec["parent"]
        if p is None:
            ctx = f"oci-layout://{LAYOUT}:{base_tag}"
        elif p in missing:
            ctx = f"target:{p}"
        else:
            ctx = f"oci-layout://{LAYOUT}:{tool_tag(p, ids[p])}"
        args = {"BASE_IMAGE": "agent-vm-parent"}
        if spec["version_arg"]:
            args[spec["version_arg"]] = versions.get(t, "")
        if soft_fail:
            args["AGENT_INSTALL_SOFT_FAIL"] = "1"
        targets[t] = {
            "context": str(spec["context"]),
            "args": args,
            "contexts": {"agent-vm-parent": ctx},
            "output": [f"type=oci,dest={STAGE/tool_tag(t, ids[t])},tar=false,name=agent-vm-tool:{tool_tag(t, ids[t])}"],
        }
    # One `bake` per independent group (a root tool plus the tools that
    # declare it, transitively, as parent), run concurrently. A single bake
    # over every target CANCELS its siblings when one target fails, so their
    # exports never land and ADR-0029's "images already built stay cached"
    # would be false. `target:` parents must share an invocation, hence groups.
    def root(t):
        p = CATALOG[t]["parent"]
        return root(p) if p in missing else t
    groups = {}
    for t in missing:
        groups.setdefault(root(t), []).append(t)
    t0 = time.time()
    procs = {r: start_bake({"target": {t: targets[t] for t in g}}, g, f"bake-{r}")
             for r, g in groups.items()}
    failed = []
    for r, (proc, logf) in procs.items():
        proc.wait()
        if proc.returncode == 0:
            for t in groups[r]:
                adopt(tool_tag(t, ids[t]))
        else:
            failed += groups[r]
            log(f"  FAILED group {groups[r]} (see {logf})")
    if failed:
        sys.exit(f"launch fails: tool image(s) {failed} did not build; "
                 f"{[t for t in missing if t not in failed]} built and are cached")
    return missing, time.time() - t0


def adopt(tag):
    """Move one staged export into the shared store. Concurrent bake exports
    into ONE layout race in its ingest/ dir when they share a blob (a tool and
    its declared parent: 2/5 failures in a toy repro), so each target exports
    to its own staging layout and this — the single writer — hardlinks blobs
    in (content-addressed, so already-present blobs are skipped) and owns
    index.json."""
    st = STAGE / tag
    linked = skipped = 0
    for f in (st / "blobs").rglob("*"):
        if f.is_file():
            dst = LAYOUT / f.relative_to(st)
            if dst.exists():
                skipped += 1
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            os.link(f, dst)
            linked += 1
    desc = json.loads((st / "index.json").read_text())["manifests"][0]
    register(desc["digest"], desc["size"], tag)
    shutil.rmtree(st)
    log(f"  adopted {tag}: {linked} new blob(s), {skipped} already in the store")


# ----------------------------------------------------------------- stitch --

def layer_entries(desc):
    """(path, is_dir) for every entry of a layer blob, incl. whiteouts."""
    data = blob(desc["digest"])
    mt = desc["mediaType"]
    if mt.endswith("gzip"):
        data = gzip.decompress(data)
    elif mt.endswith("zstd"):
        from compression import zstd
        data = zstd.decompress(data)
    out = []
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        for m in tf:
            out.append(("/" + m.name.lstrip("./").rstrip("/"), m.isdir()))
    return out


def split_path(env):
    for e in env or []:
        if e.startswith("PATH="):
            return e[5:].split(":")
    return []


def stitch(tools, ids, base_tag, composed_id):
    _, bman, bcfg = load_image(base_tag)
    base_layers = bman["layers"]
    base_path = split_path(bcfg["config"].get("Env"))

    layers, diff_ids, history = list(base_layers), list(bcfg["rootfs"]["diff_ids"]), list(bcfg.get("history", []))
    path_prefix = []
    problems = []
    own_by_tool = {}

    for t in tools:
        _, man, cfg = load_image(tool_tag(t, ids[t]))
        p = CATALOG[t]["parent"]
        pref = base_tag if p is None else tool_tag(p, ids[p])
        _, pman, pcfg = load_image(pref)
        n = len(pman["layers"])
        # C1 analogue: the parent's layers are a strict prefix of the tool's.
        if [l["digest"] for l in man["layers"][:n]] != [l["digest"] for l in pman["layers"]]:
            sys.exit(f"{t}: parent {pref}'s layers are not a prefix of its own — cannot stitch")
        if p is not None and (p not in tools or tools.index(p) > tools.index(t)):
            sys.exit(f"{t}: declared parent {p} must be in the tool set, earlier in stitch order")
        own = man["layers"][n:]
        own_by_tool[t] = own
        layers += own
        diff_ids += cfg["rootfs"]["diff_ids"][n:]
        # history: only the entries after the parent's (empty_layer ones included)
        history += cfg.get("history", [])[len(pcfg.get("history", [])):]
        # PATH: derived — directories the tool added over its parent, prepended in stitch order.
        added = [d for d in split_path(cfg["config"].get("Env")) if d not in split_path(pcfg["config"].get("Env"))]
        path_prefix = added + [d for d in path_prefix if d not in added]
        # Any other config drift is a contract violation (reported, not fatal, in the prototype).
        for k in FROZEN_CONFIG:
            if cfg["config"].get(k) != pcfg["config"].get(k):
                problems.append(f"config: {t} changes {k}: {pcfg['config'].get(k)!r} -> {cfg['config'].get(k)!r}")
        other_env = {e for e in cfg["config"].get("Env", []) if not e.startswith("PATH=")} ^ \
                    {e for e in pcfg["config"].get("Env", []) if not e.startswith("PATH=")}
        if other_env:
            problems.append(f"config: {t} changes ENV {sorted(other_env)}")

    path = path_prefix + [d for d in base_path if d not in path_prefix]
    cfg = json.loads(json.dumps(bcfg))
    cfg["created"] = EPOCH
    cfg["config"]["Env"] = [("PATH=" + ":".join(path)) if e.startswith("PATH=") else e for e in cfg["config"]["Env"]]
    cfg["rootfs"]["diff_ids"] = diff_ids
    cfg["history"] = history
    cfg_bytes = json.dumps(cfg, sort_keys=True, separators=(",", ":")).encode()
    cfg_digest = put_blob(cfg_bytes)
    man = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
           "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                      "digest": cfg_digest, "size": len(cfg_bytes)},
           "layers": layers}
    man_bytes = json.dumps(man, sort_keys=True, separators=(",", ":")).encode()
    man_digest = put_blob(man_bytes)
    return man_digest, len(man_bytes), cfg, man, own_by_tool, problems, path


def overlaps(tools, own_by_tool, base_tag):
    """Paths written by more than one tool's own layers. Directory entries in
    every writer are allowed; so are OVERLAP_ALLOW files."""
    writers = {}
    for t in tools:
        seen = {}
        for d in own_by_tool[t]:
            for path, is_dir in layer_entries(d):
                seen[path] = seen.get(path, True) and is_dir
        for path, is_dir in seen.items():
            writers.setdefault(path, []).append((t, is_dir))
    flagged = {p: [t for t, _ in w] for p, w in writers.items()
               if len(w) > 1 and not all(d for _, d in w) and p not in OVERLAP_ALLOW}
    dirs = sum(1 for w in writers.values() if len(w) > 1 and all(d for _, d in w))
    # Informational (rebase question): how many base paths each tool rewrites.
    _, bman, _ = load_image(base_tag)
    base_files = {p for d in bman["layers"] for p, is_dir in layer_entries(d) if not is_dir}
    base_touch = {t: sorted({p for d in own_by_tool[t] for p, is_dir in layer_entries(d)
                             if not is_dir and (p in base_files or os.path.basename(p).startswith(".wh."))})
                  for t in tools}
    return flagged, dirs, base_touch


# ----------------------------------------------------------------- export --

def export_archive(man_digest, man_size, man, ref, dest: Path):
    """Deterministic OCI archive with just this image (mtime 0, sorted)."""
    idx = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
           "manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json",
                          "digest": man_digest, "size": man_size,
                          "platform": {"architecture": "arm64" if os.uname().machine == "arm64" else "amd64", "os": "linux"},
                          "annotations": {"io.containerd.image.name": "docker.io/library/" + ref,
                                          "org.opencontainers.image.ref.name": ref}}]}
    files = {"oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
             "index.json": json.dumps(idx, sort_keys=True, separators=(",", ":")).encode()}
    digests = [man_digest, man["config"]["digest"]] + [l["digest"] for l in man["layers"]]
    with tarfile.open(dest, "w", format=tarfile.PAX_FORMAT) as tf:
        def add(name, data=None, path=None):
            ti = tarfile.TarInfo(name); ti.mtime = 0; ti.mode = 0o644; ti.uid = ti.gid = 0
            if path is not None:
                ti.size = path.stat().st_size
                with open(path, "rb") as f:
                    tf.addfile(ti, f)
            else:
                ti.size = len(data); tf.addfile(ti, io.BytesIO(data))
        for name in sorted(files):
            add(name, data=files[name])
        for d in sorted(set(digests)):
            algo, h = d.split(":")
            add(f"blobs/{algo}/{h}", path=LAYOUT / "blobs" / algo / h)
    return sha(dest.read_bytes())


def register(man_digest, man_size, tag):
    idx = index()
    idx["manifests"] = [m for m in idx["manifests"]
                        if m.get("annotations", {}).get("org.opencontainers.image.ref.name") != tag]
    idx["manifests"].append({"mediaType": "application/vnd.oci.image.manifest.v1+json",
                             "digest": man_digest, "size": man_size,
                             "annotations": {"org.opencontainers.image.ref.name": tag}})
    idx.setdefault("schemaVersion", 2)
    LAYOUT.mkdir(parents=True, exist_ok=True)
    (LAYOUT / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')
    (LAYOUT / "index.json").write_text(json.dumps(idx, indent=2))


# ------------------------------------------------------------------- main --

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools", default=",".join(CATALOG))
    ap.add_argument("--base", default="agent-vm-base:dev")
    ap.add_argument("--version", action="append", default=[], help="tool=resolved-version")
    ap.add_argument("--soft-fail", action="store_true")
    ap.add_argument("--no-overlaps", action="store_true")
    a = ap.parse_args()
    tools = a.tools.split(",")
    versions = dict(v.split("=", 1) for v in a.version)
    t_all = time.time()

    base_id = subprocess.check_output(["docker", "image", "inspect", "-f", "{{.Id}}", a.base], text=True).strip().removeprefix("sha256:")
    ids, composed_id = plan(tools, base_id, versions)
    ctag = f"composed-{composed_id[:24]}"
    log(f"== plan  base={a.base} ({base_id[:19]})  tools={tools}")
    log(f"   composed identity {ctag}")
    if by_ref(ctag):
        log("   composed image cached — nothing to build or stitch (launch makes zero Docker build calls)")

    log("== build")
    LAYOUT.mkdir(parents=True, exist_ok=True)
    base_tag = ensure_base(a.base, base_id)
    built, bake_secs = build_missing(tools, ids, base_tag, versions, a.soft_fail)
    log(f"   built {len(built)} tool image(s) {built} in {bake_secs:.1f}s")

    log("== stitch")
    t0 = time.time()
    man_digest, man_size, cfg, man, own, problems, path = stitch(tools, ids, base_tag, composed_id)
    register(man_digest, man_size, ctag)
    stitch_secs = time.time() - t0
    log(f"   manifest {man_digest}  ({stitch_secs:.2f}s)")
    log(f"   layers: base {len(man['layers']) - sum(len(v) for v in own.values())}"
        + "".join(f" + {t} {len(v)}" for t, v in own.items()) + f" = {len(man['layers'])}")
    size = sum(l["size"] for l in man["layers"])
    log(f"   compressed size {size/1e6:.0f} MB (base {sum(l['size'] for l in man['layers'][:len(man['layers']) - sum(len(v) for v in own.values())])/1e6:.0f} MB"
        + "".join(f", {t} {sum(l['size'] for l in v)/1e6:.0f} MB" for t, v in own.items()) + ")")
    log(f"   PATH={':'.join(path)}")
    for p in problems:
        log(f"   CONTRACT: {p}")
    if not problems:
        log("   config: no drift beyond PATH")

    if not a.no_overlaps:
        log("== overlaps")
        t0 = time.time()
        flagged, dirs, base_touch = overlaps(tools, own, base_tag)
        log(f"   {dirs} shared directory entries (allowed); {len(flagged)} flagged file overlaps ({time.time()-t0:.1f}s)")
        for p, ws in sorted(flagged.items()):
            log(f"   OVERLAP {p}: {' < '.join(ws)}  (last wins)")
        for t, ps in base_touch.items():
            if ps:
                log(f"   base-rewrite {t}: {len(ps)} base file(s), e.g. {ps[:4]}")

    log("== export")
    ref = f"agent-vm-composed:{composed_id[:24]}"
    arc = OUT / "composed.tar"
    d = export_archive(man_digest, man_size, man, ref, arc)
    log(f"   {arc} sha256={d[:16]}…  ref={ref}")
    (OUT / "last.json").write_text(json.dumps({"ref": ref, "manifest": man_digest, "tools": tools,
                                               "built": built, "archive_sha256": d}, indent=2))
    log(f"== total {time.time()-t_all:.1f}s")


if __name__ == "__main__":
    main()
