#!/bin/bash
# Wall-clock `create` per libkrunfw variant. Interleaved across variants to
# cancel host drift; drop_caches between rounds; mean/stdev. QUIET host only.
#
# `--memory` sets the RESOURCE CEILING, not boot memory: since ADR-0070 every
# launch boots at the 512 MiB boot commitment whatever the ceiling says, so the
# two experiments below compare ceilings (1 GiB vs 4 GiB reserved) and not boot
# RAM. The 1 GiB / 2 GiB / 4 GiB create figures recorded in LAUNCH-PROFILE.md
# were taken before ADR-0070, when boot memory equalled `--memory`; they are
# historical. A boot-memory comparison can no longer be asked with `--memory`
# on this branch — every arm boots at 512 MiB, so it would only measure host
# virtio-mem bookkeeping for the reserved region.
set -u
export PATH="/home/boger/work/board/tmp/agent-vm/.agent-vm-rust/rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:$PATH"
export MSB_PATH=/home/boger/work/board/tmp/agent-vm/vendor/microsandbox/target/release/msb
AGENTVM=/home/boger/work/board/tmp/agent-vm/target/release/agent-vm
LIBSO=/home/boger/work/board/tmp/agent-vm/vendor/microsandbox/target/release/libkrunfw.so.5.2.1
VAR=/tmp/variants
PROJ=/root/profproj
VARIANTS=(stock stock_kvm heavy_nonf heavy_legacy heavy heavy_deferred)
ROUNDS=${1:-10}

cd "$PROJ" || exit 1
swap() { cp "$VAR/libkrunfw-$1.so.5.2.1" "$LIBSO" || exit 1; }
create() { local mem="$1"; AGENT_VM_PROFILE=1 "$AGENTVM" --memory "$mem" shell true 2>&1 \
  | sed 's/\x1b\[[0-9;]*m//g' | grep -oE 'create:[[:space:]]+[0-9.]+s' | grep -oE '[0-9.]+'; }
mstat() { tr ' ' '\n' <<<"$1" | awk 'NF{n++;v=$1;s+=v;ss+=v*v;if(mn==""||v<mn)mn=v;if(v>mx)mx=v} END{if(!n){print "no data";exit} m=s/n;d=ss/n-m*m;if(d<0)d=0;printf "mean=%.3f sd=%.3f min=%.3f max=%.3f n=%d",m,sqrt(d),mn,mx,n}'; }

echo "### boot check (each variant must run a command) ###"
for v in "${VARIANTS[@]}"; do
  swap "$v"; o=$(AGENT_VM_PROFILE=1 "$AGENTVM" shell echo OK_$v 2>&1)
  echo "$o" | grep -q "OK_$v" && echo "  $v: boots OK" || { echo "  $v: *** FAILED ***"; echo "$o"|tail -3; }
done

declare -A S
echo; echo "### interleaved, ceiling 1 GiB / 2 vCPU (boot memory is 512 MiB since ADR-0070), $ROUNDS rounds, drop_caches per round ###"
for c in $(seq 1 "$ROUNDS"); do
  sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
  for v in "${VARIANTS[@]}"; do swap "$v"; S[$v]="${S[$v]:-} $(create 1)"; done
  echo "  round $c done"
done

declare -A S4
echo; echo "### heavy vs heavy_deferred @ ceiling 4 GiB, 6 rounds (boot memory stays 512 MiB; does deferred help at a wider reserved region?) ###"
for c in $(seq 1 6); do
  sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
  for v in heavy heavy_deferred; do swap "$v"; S4[$v]="${S4[$v]:-} $(create 4)"; done
done

echo; echo "================= RESULTS: create wall-seconds @1GiB ceiling ================="
for v in "${VARIANTS[@]}"; do printf "%-16s %s\n" "$v" "$(mstat "${S[$v]}")"; done
echo "------- raw @1GiB ceiling -------"
for v in "${VARIANTS[@]}"; do printf "%-16s%s\n" "$v" "${S[$v]}"; done
echo; echo "================= @4GiB ceiling heavy vs deferred ================="
for v in heavy heavy_deferred; do printf "%-16s %s\n" "$v" "$(mstat "${S4[$v]}")"; done
swap heavy; echo "(restored heavy .so)"
