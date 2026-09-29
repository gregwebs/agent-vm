#!/usr/bin/env bash
# PROTOTYPE — throwaway. One command: build, stitch, run and boot the composed
# tool image (ADR-0029), then measure a one-tool bump, a different tool set,
# and a failing tool. Needs docker+buildx (docker driver) and `agent-vm` on
# PATH; state lives in ./out (wipe it freely).
set -euo pipefail
cd "$(dirname "$0")"
BASE=${BASE:-agent-vm-base:dev}
ALL=dsh,pi,codex,opencode,claude,copilot,claude-extra
CHECK='echo PATH=$PATH; for c in dsh pi codex opencode claude copilot claude-extra; do printf "%-13s " $c; timeout 60 $c --version 2>&1 | head -1 || echo FAIL; done'

echo "######## 1. compose all seven (six builtins + claude-extra, parent=claude)"
python3 compose.py --base "$BASE" --tools "$ALL" | grep -v '^#' | grep -v OVERLAP
python3 - <<'EOF'
import collections, re, subprocess
out = subprocess.run(["python3", "compose.py", "--tools", "dsh,pi,codex,opencode,claude,copilot,claude-extra"],
                     capture_output=True, text=True).stdout
c = collections.Counter()
for l in out.splitlines():
    m = re.match(r"\s+OVERLAP (\S+): (.*)  \(last wins\)", l)
    if m:
        c[("/".join(m[1].split("/")[:3]), m[2])] += 1
for (p, w), n in c.most_common():
    print(f"   overlap summary: {n} files under {p}/ written by {w}")
EOF
REF=$(jq -r .ref out/last.json)

echo "######## 2. docker load + run"
docker load -i out/composed.tar
docker run --rm "$REF" bash -c "$CHECK"

echo "######## 3. msb load_archive + boot in agent-vm (no project layer)"
time agent-vm msb load -i out/composed.tar
PROJ=$(mktemp -d); LAYER=$PWD/project-layer
(cd "$PROJ" && agent-vm shell --image "$REF" -y -- bash -c "$CHECK; id -u" </dev/null)

echo "######## 4. project tooling layer on top (via the local registry: the launcher pulls its chain root)"
R=127.0.0.1:5000/$REF
docker tag "$REF" "$R" && docker push -q "$R"
(cd "$PROJ" && agent-vm shell --image "$R" --layer "$LAYER" -y -- bash -c 'claude-extra; project-hello' </dev/null)

echo "######## 5. one-tool bump (codex): only codex rebuilds; re-ingest"
python3 compose.py --base "$BASE" --tools "$ALL" --no-overlaps --version "codex=bump-$(date +%s)" | grep -E 'BUILD|built|manifest|total'
time agent-vm msb load -i out/composed.tar

echo "######## 6. a different tool set reuses every cached tool image"
python3 compose.py --base "$BASE" --tools dsh,claude,claude-extra --no-overlaps | grep -E 'BUILD|cached|built|layers:|total'

echo "######## 7. a failing tool fails the launch; siblings still cached"
V=f-$(date +%s)
python3 compose.py --base "$BASE" --tools dsh,codex,claude,claude-extra,broken --no-overlaps --version codex=$V | grep -E 'BUILD|adopted|FAILED|launch fails' || true
python3 compose.py --base "$BASE" --tools dsh,codex,claude,claude-extra --no-overlaps --version codex=$V | grep -E 'BUILD|cached|built'
