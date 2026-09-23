# agent-vm launch profiling — findings

Host: AMD EPYC, 16 vCPU, nested virt (`/dev/kvm`, `kvm_amd.nested=1`). Image cached.
All headline numbers are **wall-clock**, from interleaved A/Bs (host drift cancels),
`drop_caches` between rounds where noted. Measured with `AGENT_VM_PROFILE=1`.

## Guest-kernel boot floor

`create` ≈ guest kernel boot (`build()` is ~3µs; `entering VM → agentd core.ready`).
The console (`hvc0`) attaches ~1.3s in, so early boot isn't visible in `kernel.log`;
the A/B below is the real attribution. Five+1 kernels built from one tree
(configs grepped, not assumed), 10 interleaved rounds @1 GiB, `drop_caches` per round:

| kernel | config | create mean ± sd | Δ |
|---|---|---|---|
| stock | upstream libkrunfw (no KVM, no netfilter) | 1.488 ± 0.10 s | — |
| stock+KVM | + CONFIG_KVM/KVM_INTEL/KVM_AMD | 1.587 ± 0.15 s | **+99 ms (KVM)** |
| heavy_nonf | KVM, netfilter off (+mqueue) | 1.615 ± 0.12 s | ≈ stock+KVM ✓ |
| heavy_legacy | + conntrack/NAT/iptables-legacy/bridge | 1.677 ± 0.03 s | **+62 ms (conntrack)** |
| heavy (current) | + full nf_tables/XT/IPv6/VLAN | 1.680 ± 0.03 s | +3 ms (nf_tables ≈ 0) |
| heavy+deferred | heavy + DEFERRED_STRUCT_PAGE_INIT | 1.632 ± 0.03 s | no help |

**The nested-virt kernel rebuild adds only ~190ms total to boot** (KVM ~100ms,
conntrack/iptables ~62ms, nf_tables ~3ms). So it's a real but *minor* cost:

- **KVM (~100ms)** is *required* for nested virt — irremovable.
- **conntrack/iptables-legacy (~62ms)** is the unavoidable cost of docker bridge+SNAT
  (the conntrack hashtable auto-sizes from RAM). With `CONFIG_MODULES is not set` +
  `nomodule`, it can't be made a module — it's built-in or absent. Drop it only if you
  don't need docker networking by default.
- **nf_tables/XT/IPv6/VLAN (~3ms)** — droppable, but saves essentially nothing. Not
  worth the docker-iptables-nft→legacy fallback risk.

### Two levers that do NOT work (verified, don't pursue)

- **`CONFIG_DEFERRED_STRUCT_PAGE_INIT=y`**: no help at 1 GiB, slightly *worse* at 4 GiB.
  Its `defer_init()` heuristic only defers past a 128 MB section threshold after low
  zones init; a 1–4 GiB single-node guest has nothing to defer (it targets TB-scale RAM).
- **`split_irqchip`**: ~515ms swing in the runtime's `boot_time_ms` metric but **zero
  wall-clock effect** (1.91s vs 1.88s create). `boot_time_ms` excludes ~0.9s of early
  boot and is a misleading proxy — rank kernels on wall-clock `create` only. vCPU count:
  also negligible (1/2/4 ≈ 1.84/1.84/1.89s).

## Other real levers

- **Guest memory** (real wall-clock, but EPT/page-materialization under nested virt, not
  struct-page init): create ≈ 1.49s @1G / 1.68–1.92s @2G / 2.9s @4G. Lower the default
  (`AGENT_VM_MEMORY_GIB`, currently 2) for sessions that don't need 2 GiB (~0.2s+).
- **Chrome-MCP CA `certutil` (~270ms)** stays off the launch critical path: the opt-in
  `examples/layers/chrome-devtools/agent-vm-chrome-mcp` wrapper imports the per-install
  CA when the MCP starts, rather than synchronously before every agent exec. Chromium
  honours its per-user NSS DB rather than only the system CA bundle, so the work is
  skipped entirely unless the Chrome DevTools layer is selected.

## Reproduce

```bash
cd <github-remote repo>
AGENT_VM_PROFILE=1 agent-vm shell true     # prints pre-boot phases + create/run/stop
# kernel A/B: build variants from libkrunfw-src (one tree, grep each .config), swap the
# .so next to msb, measure interleaved with drop_caches — see measure_variants.sh.
```
