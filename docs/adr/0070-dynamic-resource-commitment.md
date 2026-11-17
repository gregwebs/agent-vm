# ADR-0070: Dynamic resource commitment within `--memory` and `--cpus` ceilings

## Status

Proposed ([#645](https://github.com/gregwebs/agent-vm/issues/645),
[#646](https://github.com/gregwebs/agent-vm/issues/646),
[#647](https://github.com/gregwebs/agent-vm/issues/647)). Amends
[ADR-0018](0018-machine-checked-boundary-contracts.md) (adds the pure
resource-commitment sizing kernels to the verified surface).

## Context

`--memory` (`AGENT_VM_MEMORY_GIB`) and `--cpus` (`AGENT_VM_CPUS`) previously set
a fixed boot allocation (`memory_mib == max_memory_mib`, `cpus == max_cpus`).
Coding agents have bursty resource profiles: an idle prompt or network wait
needs well under 512 MiB and 1 vCPU, while a Rust build or test run inside the
same session needs multiple vCPUs and several GiB of RAM. Fixed sizing forces a
choice between starving bursts (OOM or slow builds at 2 GiB) and pinning high
commitment across every idle session.

`microsandbox` and `msb_krun` support live resize within boot-time ceilings:

- **Memory (`virtio-mem`)**: `SandboxBuilder::memory(boot_mib).max_memory(max_memory_mib)`
  boots at `boot_mib` and attaches a `virtio-mem` device (2 MiB block
  granularity) covering `boot_mib ..= max_memory_mib`. `SetMemoryTarget` adjusts
  `target_mib` within `[boot_mib, max_memory_mib]` in ~5–50 ms; it cannot shrink
  below `boot_mib`.
- **CPU (`virtio_msb_cpu`)**: `SandboxBuilder::cpus(boot_cpus).max_cpus(max_cpus)`
  attaches the CPU resize controller whenever `max_cpus > boot_cpus`.
  `SetCpuTarget` enforces the online vCPU ceiling (`1 ..= max_cpus`) host-side
  immediately (< 1 ms) and onlines/offlines guest vCPUs asynchronously in
  ~5–30 ms.
- **Metrics (`microsandbox-metrics`)**: `SandboxBuilder::metrics_sample_interval`
  sets the `virtio-balloon` stats interval and the sleep between
  `run_metrics_sampler` snapshots, which publish `cpu_percent`, `memory_bytes`,
  `memory_available_bytes` and `memory_limit_bytes` to a lock-free shared-memory
  slot.

The sampler sleeps for the interval and *then* takes a snapshot, so the achieved
period is the interval plus snapshot time plus scheduling delay. A window whose
snapshot pairing is skewed reuses the previous CPU reading
(`crates/runtime/lib/runner/metrics.rs:143-181`). The interval therefore
*requests* samples and guarantees neither a rate nor freshness. The launch
requests 200 ms (nominal 5 Hz; the SDK default is 1 s), and its steady-state
cost is unmeasured.

## Decision

### Terms

- **Resource ceiling**: a session's boot-time maximum vCPU and memory capacity
  (`max_cpus`, `max_memory_mib`), set by `--cpus` / `AGENT_VM_CPUS` and
  `--memory` / `AGENT_VM_MEMORY_GIB`. The design lets live resize grow and
  shrink a running guest's **resource commitment** within this ceiling, never
  beyond it. Live resize does not run yet: until #646/#647, a session stays at
  its **boot commitment** and the ceiling only reserves capacity.
- **Boot commitment**: the initial online vCPUs and memory (`cpus`,
  `memory_mib`) a session starts with at VM creation: `min(1, max_cpus)` vCPUs
  and `min(512 MiB, max_memory_mib)` RAM. Because `virtio-mem` only plugs and
  unplugs blocks above it and `virtio_msb_cpu` scales online vCPUs down to `1`,
  it is also the session's lower bound. Both devices are attached at creation
  and the launcher does not drive them yet (#646/#647), so a session does not
  leave its boot commitment.
- **Resource commitment**: the online vCPU count and usable guest memory target
  currently enforced for a running session, between its **boot commitment** and
  its **resource ceiling**. Until #646/#647 it is the boot commitment.

[CONTEXT.md](../../CONTEXT.md#sandbox-resources) holds the same three
definitions; this ADR decides the mechanism.

### D1. `--memory` and `--cpus` define the resource ceiling

**Status: implemented ([#645](https://github.com/gregwebs/agent-vm/issues/645)).**

1. `--memory <GIB>` (`AGENT_VM_MEMORY_GIB`) sets `max_memory_mib` and defaults
   to **8 GiB** (`8192 MiB`).
2. `--cpus <N>` (`AGENT_VM_CPUS`) sets `max_cpus` and defaults to **2 vCPUs**.
3. Every launch route (`tool`, `shell`, and `run` / `--` direct commands) boots
   at the **boot commitment**:
   - `boot_cpus = min(1, max_cpus)` (`1` vCPU for every valid `max_cpus >= 1`),
   - `boot_memory_mib = min(512, max_memory_mib)` (`512 MiB` for every GiB ceiling).
4. `agent-vm setup`'s verification probe is not a launch route and keeps its
   fixed `1` vCPU / `512 MiB` configuration.
5. Every launch route configures
   `.metrics_sample_interval(Duration::from_millis(200))`.
6. `--memory 0`, `--cpus 0` and a `--memory` whose MiB value overflows `u32` are
   refused, memory first, while parsing the launch: before the MSB prologue
   (runtime unpack, `msb --version`) and every later side effect. Status is 125
   on direct routes and 1 otherwise.
7. The validated ceiling is carried in `Dispatch::Launch` and never recomputed.

### D2. In-process 200 ms monitor and live-resize loop

**Status: decided, unimplemented.** D1.5's interval is configured by #645; the
monitor itself is delivered by
[#646](https://github.com/gregwebs/agent-vm/issues/646) (memory) and
[#647](https://github.com/gregwebs/agent-vm/issues/647) (CPU).

1. The monitor consumes the samples D1.5 configures.
2. When `max_cpus > boot_cpus` or `max_memory_mib > boot_memory_mib`, the
   launcher spawns an in-process background task after `Sandbox::create` and
   stops it before teardown (alongside `LiveSession`).
3. Every **200 ms** tick reads the sandbox's shared-memory metrics snapshot
   directly (`all_sandbox_metrics_local` / `verified_metrics`, avoiding per-tick
   SQLite queries) and calls `sandbox.modify()...apply().await` only when the
   desired commitment `(target_cpus, target_mib)` changes.

### D3. Target-headroom memory tracking

**Status: decided, unimplemented**; delivered by
[#646](https://github.com/gregwebs/agent-vm/issues/646).

Linux does not pause page faults waiting for `virtio-mem`, so the guest must
retain enough free plugged headroom to absorb allocations during a 200 ms poll +
plug window:

1. When `memory_available_bytes` is reported (`used_mib = (memory_limit_bytes - memory_available_bytes) / MiB`):
   ```text
   headroom_mib = max(256, used_mib / 4)
   desired_mib  = clamp(round_up_128_mib(used_mib + headroom_mib), boot_memory_mib, max_memory_mib)
   ```
   When `used_mib <= 256`, `used_mib + headroom_mib <= 512`, keeping an idle
   guest at the `512 MiB` floor.
2. When `memory_available_bytes` is `None` (early boot or a guest without
   `virtio-balloon`), memory commitment is left unchanged for that tick.
3. **Scale-up**: Immediate (1 tick = 200 ms) whenever `desired_mib > current_target_mib`.
   An urgent scale-up may supersede an in-flight scale-down.
4. **Scale-down**: Requires `desired_mib < current_target_mib` for **50
   consecutive ticks (10 s)** and requires `memory_limit_bytes` to have
   converged to `current_target_mib`.

### D4. Sustained-saturation CPU tracking

**Status: decided, unimplemented**; delivered by
[#647](https://github.com/gregwebs/agent-vm/issues/647).

Because scheduler and timer skew cause a 100%-pegged vCPU to report `95%–100%`
`cpu_percent` in `msb_krun`, saturation of `C` committed vCPUs is measured at
`C * 95%`, with a 10%-per-vCPU hysteresis gap on scale-down to prevent
oscillation:

1. **Scale-up (`C -> C + 1`, up to `max_cpus`)**: Requires
   `cpu_percent >= C * 95.0` for **10 consecutive ticks (2 s)**, resetting the
   counter after stepping up.
2. **Scale-down (`C -> C - 1`, down to `1`)**: Requires
   `cpu_percent <= (C - 1) * 85.0` for **5 consecutive ticks (1 s)**, resetting
   the counter after stepping down.

**Measured on the S1 host (macOS 27.0.0 arm64, Apple M1 Pro, HVF; 2026-11-16):
this tracking cannot be built on `cpu_percent` as it stands.** The 200 ms
interval is configured and reaches the runtime correctly (the boot notice and
the `machine` argv carry the same geometry, verified by the real-VM run), but
the runtime's sampler publishes **no fresh CPU reading at either interval**.
With `"log_level": "debug"` in `$MSB_HOME/config.json`, `runtime.log` rejected
**284 of 284** pairing windows at 200 ms (mean spread 12.3 ms against the 10.7 ms
allowed) and **13 of 13** at the 1 s default (62.5 ms against 53 ms). Every
window is skewed, so every published `cpu_percent` is the carried-over reading.
[#646](https://github.com/gregwebs/agent-vm/issues/646)/#647 must therefore
validate or fix the sampler's snapshot pairing before relying on `cpu_percent`
for saturation detection. The interval is also not free: idle CPU cost measured
**8.05 % mean** over three 60-sample rounds, against **4.86 %** for `main`'s 1 s
default — ≈ +3 percentage points, on a shared host, so indicative rather than a
benchmark.

### D5. Observability, failure degradation and boundary contract

1. **Boot notice**: Displays `<boot_mib>..=<max_memory_mib> MiB` and
   `<boot_cpus>..=<max_cpus> vCPU` when ceiling exceeds floor, collapsing to a
   single number on either axis when `boot == max` (e.g. `--cpus 1` prints
   `1 vCPU`).
2. **Silent live transitions**: Live resizes and any transient metrics or
   `modify` errors log at `tracing::debug!` only and never write to stderr or
   fail the session.
3. **Boundary contract ([ADR-0018](0018-machine-checked-boundary-contracts.md))**
   ([#645](https://github.com/gregwebs/agent-vm/issues/645)):
   `crates/agent-vm/src/resources.rs` holds the pure launch sizing decision as a
   `verus!` kernel (`launch_sizing`, with `memory_ceiling_mib`, `boot_cpus` and
   `boot_memory_mib`) and `ResourceCeiling` as its trusted adapter. What S1
   proves: GiB→MiB is exact or refused for every `u32` and never overflows; a
   zero ceiling on either axis is refused; the memory refusal precedes the CPU
   one; and on acceptance `1 <= boot_cpus <= max_cpus`,
   `boot_cpus == min(1, max_cpus)`, `1 <= boot_memory_mib <= max_memory_mib`
   and `boot_memory_mib == min(512, max_memory_mib)`.

## Alternatives rejected

- **Shelling out to `msb metrics` and `msb modify`.** Rejected: spawning
  subprocesses at 5 Hz adds process and SQLite overhead for operations the
  in-process SDK already owns.
- **A 256 MiB memory floor.** Rejected: Node.js/agent startup bursts can allocate
  several hundred MiB within a single 200 ms window before `virtio-mem` finishes
  plugging blocks; 512 MiB provides a safer initial cushion while still saving
  93.75% of the 8 GiB default ceiling when idle.
- **Polling faster than 200 ms.** Not chosen: no measurement shows a shorter
  interval is needed for the controller, and its sampler cost is unmeasured.
  Revisit with data.
- **0.1 fractional vCPU floor.** Rejected: `microsandbox` and `msb_krun` expose
  integer online vCPU counts (`u8 >= 1`), and an idle vCPU in `libkrun` already
  sleeps in `HLT`/`WFI` at ~0% host CPU.

## Consequences

- Default launches reserve an 8 GiB / 2 vCPU ceiling and boot at the 512 MiB /
  1 vCPU boot commitment. The scaling mechanisms and their timings are decided
  in D2-D4 — memory in 200 ms steps, vCPUs after 2 s of full saturation,
  reclamation after 1 s for CPU and 10 s for memory — but they are
  **unimplemented until [#646](https://github.com/gregwebs/agent-vm/issues/646)
  and [#647](https://github.com/gregwebs/agent-vm/issues/647)**.
- **Interim (S1 only, until #646/#647):** nothing grows a session above its boot
  commitment, so every session runs at 512 MiB and 1 vCPU whatever
  `--memory`/`--cpus` say. The ceiling only reserves capacity.
- `SandboxConfig` golden fixtures reflect `cpus: 1`, `memory_mib: 512`,
  `max_cpus: 2`, `max_memory_mib: 8192`, and `metrics_sample_interval_ms: 200`.
- Guest `/dev/shm` is a default-sized tmpfs (`agentd` `init.rs:210-218`), so it
  gets half the **boot** memory (≈ 256 MiB) and does not grow with `virtio-mem`.
  Tracked as [#651](https://github.com/gregwebs/agent-vm/issues/651).
- Guest `/tmp` does **not** share that limitation: it is not a tmpfs and carries
  no `size=`, being a directory on the `overlay` root — measured at 16052 MiB,
  invariant across `--memory` under a 479 MiB boot memory. Recorded so the
  question is closed, not left pending.
- The host-resident sampler covers boot RAM only (`msb_krun_vmm`
  `builder.rs:3082-3085`, `metrics.rs:42-122`). Once memory is plugged,
  `memory_host_resident_bytes` undercounts, and #646/#647 must not base decisions
  or user-facing figures on it unchanged.
- The default shape adds virtio-mem and, for `--cpus >= 2`, msb-cpu. Each takes a
  device slot (see `ARCHITECTURE.md` *Split irqchip and the virtio-IRQ ceiling*).
