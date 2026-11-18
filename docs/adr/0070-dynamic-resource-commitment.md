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
  beyond it. Memory does this today; the CPU axis still stays at its **boot
  commitment** and its ceiling only reserves capacity.
- **Boot commitment**: the initial online vCPUs and memory (`cpus`,
  `memory_mib`) a session starts with at VM creation: `min(1, max_cpus)` vCPUs
  and `min(512 MiB, max_memory_mib)` RAM. Because `virtio-mem` only plugs and
  unplugs blocks above it and `virtio_msb_cpu` scales online vCPUs down to `1`,
  it is also the session's lower bound. Both devices are attached at creation;
  the launcher drives the memory one (D2/D3) and not yet the CPU one (#647).
- **Resource commitment**: the online vCPU count and usable guest memory target
  currently enforced for a running session, between its **boot commitment** and
  its **resource ceiling**. The memory half is live (D3); the CPU half is the
  boot commitment until #647.

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

**Status: memory implemented (#646); CPU pending (#647).** D1.5's interval is
configured by #645; the monitor's memory half runs today, and the same task will
carry the CPU half once #654 repairs `cpu_percent`.

1. The monitor consumes the samples D1.5 configures.
2. When `max_cpus > boot_cpus` or `max_memory_mib > boot_memory_mib`, the
   launcher spawns one in-process background task immediately after
   `Sandbox::create`, and `LaunchTeardown` owns the only handle to it: every
   teardown operation — stop, kill, reap, remove and the before-remove hook —
   aborts and joins the task first, so no exit can resize a VM that is already
   stopping. The join is bounded by its own 2 s deadline, and every teardown
   step's outer deadline is its own budget **plus** that same allowance
   (`EXEC_MONITOR_JOIN_ALLOWANCE`), so a hook that joins first still gives its
   operation the whole budget: a join that came out of the operation's deadline
   would turn into `remove: timed out` with the VM left behind (#258). The legacy
   direct-stop exit uses the same bound, so the monitor join is never the
   unbounded await on any path. An early return that never
   reaches a teardown still aborts through the guard's `Drop`, which cannot await
   and is a fallback, not evidence of a completed join. The CPU axis is currently the task's allocation predicate
   only: a CPU-only spare capacity starts a task that never requests a resize.
3. Every **200 ms** tick reads metrics through the SDK's
   `all_sandbox_metrics_local` and calls `sandbox.modify()...apply().await` only
   when the desired target changes.
   **Amended by operator decision D1 of #646** (see the implementation spec): the
   original text here claimed this read avoids per-tick SQLite queries. It does
   not — the pinned implementation runs its own catalog `SELECT`s before the
   cached slot, and the operator explicitly accepted that cost ("the cost of
   accessing sqlite is minimal") rather than changing the SDK or reading the
   registry directly. Growth remaining free of per-tick writes is *not* a
   performance claim; it is a rule about not sending resize commands.
4. Only one `apply` is awaited at a time. A normal policy change is one live
   apply. A changed-target request made while recovering from an unknown outcome
   is at most two serialized applies (D5).

### D3. Target-headroom memory tracking

**Status: implemented (#646).**

Linux does not pause page faults waiting for `virtio-mem`, so the guest must
retain enough free plugged headroom to absorb allocations during a 200 ms poll +
plug window:

1. When `memory_available_bytes` is reported,
   `used_mib = ceil((memory_limit_bytes - memory_available_bytes) / MiB)` — the
   ceiling, not a truncation, so a fraction of a MiB of use cannot hide below the
   headroom:
   ```text
   headroom_mib = max(256, used_mib / 4)
   desired_mib  = clamp(round_up_128_mib(used_mib + headroom_mib), boot_memory_mib, max_memory_mib)
   ```
   When `used_mib <= 256`, `used_mib + headroom_mib <= 512`, keeping an idle
   guest at the `512 MiB` floor. Quantization precedes clamping, so an unaligned
   ceiling or floor is preserved as itself rather than being rounded to a step.
2. When `memory_available_bytes` is absent **or greater than the reported
   limit** — early boot, a guest without `virtio-balloon`, or the transitional
   window after a shrink — memory commitment is left unchanged for that tick and
   the low-demand run resets. No other memory field is substituted.
3. **Scale-up**: Immediate (1 tick = 200 ms) whenever `desired_mib > current_target_mib`.
   An urgent scale-up supersedes an in-flight scale-down, because the decision
   baseline is the accepted target rather than actual RAM.
4. **Scale-down**: Requires `desired_mib < current_target_mib` for **50
   consecutive ticks** (a nominal 10 s, since the interval guarantees no rate)
   and requires `memory_limit_bytes` to have converged to `current_target_mib` —
   exact byte equality, since a downsize can report `Applied` while the guest
   still holds more. The counter saturates at 50 and the run survives changes to
   the *value* of the lower demand; once 50 have accumulated, the first converged
   tick adopts the latest lower target.
5. **Equal demand, a missing row or a metrics error** reset the run and hold the
   target: an interrupted observation sequence is not evidence of consecutive low
   demand.
6. The numeric form of all of the above is a Verus kernel (the boundary contract
   in D5); the sampling, the SDK calls and the authority transitions are trusted
   shell with deterministic tests.

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
[#654](https://github.com/gregwebs/agent-vm/issues/654) owns repairing that
snapshot pairing and is #647's remaining prerequisite: the CPU controller cannot
be built on this reading, and #646 does not use it at all. S2 consumes only
`memory_limit_bytes` and `memory_available_bytes`; `cpu_percent` is untouched. The interval is also not free: idle CPU cost measured
**8.05 % mean** over three 60-sample rounds, against **4.86 %** for `main`'s 1 s
default — ≈ +3 percentage points, on a shared host, so indicative rather than a
benchmark.

### D5. Observability, failure degradation and boundary contract

1. **Boot notice**: Displays `<boot_mib>..=<max_memory_mib> MiB` and
   `<boot_cpus>..=<max_cpus> vCPU` when ceiling exceeds floor, collapsing to a
   single number on either axis when `boot == max` (e.g. `--cpus 1` prints
   `1 vCPU`).
2. **Silent live transitions**: Live resizes and any transient metrics or
   `modify` errors log at `tracing::debug!` only, under the
   `agent_vm::resources` target, and never write to stderr or fail the session.
   Normal output is unchanged: the default `warn` filter shows none of it.
   Opt-in debug tracing still reaches the launcher's existing stderr subscriber,
   which is what makes `RUST_LOG=agent_vm::resources=debug` useful; nothing here
   changes the global tracing configuration. No monitor event is emitted at
   `info` or above, and no notice sink is involved.
3. **Boundary contract ([ADR-0018](0018-machine-checked-boundary-contracts.md))**
   ([#645](https://github.com/gregwebs/agent-vm/issues/645),
   [#646](https://github.com/gregwebs/agent-vm/issues/646)):
   `crates/agent-vm/src/resources.rs` holds the pure decisions as `verus!`
   kernels and the rest as trusted adapters. What S1 proves: GiB→MiB is exact or
   refused for every `u32` and never overflows; a zero ceiling on either axis is
   refused; the memory refusal precedes the CPU one; and on acceptance
   `1 <= boot_cpus <= max_cpus`, `boot_cpus == min(1, max_cpus)`,
   `1 <= boot_memory_mib <= max_memory_mib` and
   `boot_memory_mib == min(512, max_memory_mib)`.
   What S2 adds, all verified for **every** `u64`/`u32` input (no `requires`
   narrowing):
   - `memory_desired_mib` — `clamp(round_up_128(ceil_used + max(256, ceil_used/4)), boot, max)`
     exactly, with no overflow in any intermediate; in-range results and the
     unclamped case are `128`-aligned, and a clamped endpoint is not forced to be.
   - `memory_tick` — the complete transition table of D3 point 3-5: immediate
     growth, hold with a reset on equal/missing/invalid demand, and adoption only
     when the incremented, saturated run reaches 50 *and* the limit has converged
     to the decision baseline. The counter never exceeds 50.
   - `memory_target_in_bounds` — exactly `boot <= target <= max`; the single
     interval test used by two trusted decoders.
   - `memory_rebase` — which baseline a tick decides against: the accepted target
     while confirmed, an observed live limit while recovering, with a baseline
     change resetting the dwell and an unchanged one preserving it. Selecting the
     numeric baseline and resetting or preserving the run is **proved**, not
     delegated to the adapter.
   - `memory_recovery_seed` — a `128`-aligned in-range value differing from both
     the observed baseline and the desired target, drawn from the three
     candidates at the floor. With aligned, adjustable bounds at most two values
     are excluded, so a seed always exists for every production ceiling.
4. **Unknown-outcome recovery (operator-authorized amendment to D2/D3).** Neither
   a `modify` error nor an unusable receipt proves the VM was left unchanged: live
   mutation precedes fallible persistence. So:
   - `resize_status.enforced` is the primary authority. A valid receipt makes the
     reported target the accepted one — even when it differs from the request.
   - Any error, or a missing/malformed/out-of-range/duplicate/negative receipt,
     switches to **Recovering**, which retains the last receipt as *history only*
     and rebases every later decision on the observed live limit from the same
     SDK metrics call. An observation is never recorded as an accepted target, and
     recovery is never cleared just because one observation arrived or the desired
     value happens to match it.
   - A changed-target request made while recovering first persists a *distinct*
     `NextStart` configuration seed and then applies the desired target live. The
     seed is a configuration-repair value, not a policy target: `NextStart`
     writes desired configuration without touching live RAM, so no live bounce can
     transiently shrink the guest. This defeats **saved-config equality**: after a
     failed shrink, a plain `.memory(desired)` equal to the persisted desired value
     is classified as an applied plan with **no** memory status, so repeating it
     can never produce a receipt. At most two serialized applies are needed per
     qualifying tick.
   - Quiescence is not starvation. Equal desired/observed emits no call at all; a
     growth that silently took effect is left alone until a genuine policy change,
     which repairs and confirms.
   - **Bounded retry, not a per-tick storm.** Scale-up is immediate, so a
     *persistently* failing growth (host out of memory, a runtime without live
     resize, a paused sandbox) would otherwise be re-asked every 200 ms at two
     SDK applies each.
     What is damped is **one ask's identity**: its target, its direction, and the
     authority it is made under. Three rules, and nothing else, define the gate:
     1. The **first** repeat of an ask that made no progress is **immediate**. One
        transient failure never slows recovery, and the no-effect traces above
        depend on the next-tick retry.
     2. Only a **second and later consecutive** no-progress result at the *same*
        ask waits, and only in **observed ticks**: the delay grows linearly from
        5 ticks to a 50-tick cap (nominal 1 s..10 s, but the unit is monitor ticks,
        because the interval guarantees no rate). A changed ask never inherits
        that count.
     3. A **different ask is never delayed**: another target, the opposite
        direction, or a different authority. That is exactly what keeps immediate
        growth, urgent reversal of an unconverged shrink, and recovery's
        same-tick repair outside the gate.
     Its relation to D5.4's progress requirement is why rule 1 exists. That
     requirement is that a **valid tick which changes what the controller can see**
     — a recovered observation, a changed baseline, a reversal — must be able to
     issue its request on that tick; each of those changes the ask's identity, so
     none is ever suppressed. What can be delayed is only the *N*th repeat of an
     ask numerically and directionally identical to the one that just failed under
     the same authority, and even that resumes on its own within the capped delay,
     so a recovered I/O path is never starved for good. The gate is I/O pacing, not
     a policy decision: it cannot widen the proved target interval, and the
     decision it gates is still the proved kernel's.
     An `Accepted` receipt whose `enforced` target is *below* the ask counts as no
     progress for the same reason — the runtime reported success and did not
     deliver — so it is re-asked on the same bounded schedule rather than at 5 Hz.
     The controller keeps retrying by itself in every case.
   - **Two stalls that no rule removes.** (i) A shrink needs the reported limit to
     have converged to the target: if the guest never converges, the low counter
     saturates at 50 and reclamation holds indefinitely, with only the absence of
     events to show it. (ii) A growth the runtime reports as accepted while the
     configured limit lags (`Converging`) is not re-asked until a genuine change,
     because the accepted target is the authority — a lost plug is therefore not
     retried until demand or the baseline moves. Both are consequences of the
     convergence rule and the authority rule, and neither grows memory nor storms.
     Repeated faults may repeat recovery attempts indefinitely; the two-apply
     bound is per tick, not per session lifetime.
   - **Durable seed:** after-persist failure, a rejected prepare or an interrupted
     monitor can leave the seed saved indefinitely, including after the launcher
     exits. On the original VM the saved/live divergence is numerically bounded
     but its duration is not; restarting **that retained record** reloads the seed
     and can change its boot floor, so 512 MiB at boot is a *fresh launch*
     promise. A plain live request equal to the seed can be a statusless no-op, so
     a genuine change reseeds again; a hold never repairs or rolls back
     configuration, and abort/join is not transaction rollback.
   The invariant is enforced by the driver's branch structure and the stateful
   model tests, not by the numeric proof: the seed kernel proves
   numeric safety and distinctness, while provenance, persistence and liveness
   stay trusted.

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
- **Observation-only recovery (no configuration reseed).** Rejected: it cannot
  make progress after a failed shrink whose old desired memory is still saved.
  The SDK treats a patch equal to the saved desired memory as no planned change,
  so a plain live apply that matches it returns an applied plan with no status —
  forever, while the VM's real commitment stays where the failed shrink left it.
  Observation alone therefore recovers *bookkeeping* but not *resizing*.
- **A live "bounce" through the repair seed** (apply the seed live, then the
  desired target). Rejected: it can transiently shrink the guest below what it is
  using, especially near the ceiling. `NextStart` persists the same configuration
  repair without touching live RAM.
- **Treating a `modify` error as proof of no effect.** Rejected: live mutation
  precedes fallible persistence, so the error leaves the outcome unknown. Assuming
  no effect either records a false target or starves growth behind a stale one.

## Consequences

- Default launches reserve an 8 GiB / 2 vCPU ceiling and boot at the 512 MiB /
  1 vCPU boot commitment. Memory then follows D3 (immediate growth, reclamation
  after 50 lower-demand ticks plus convergence, 200 ms polling). All of those
  timings are **nominal**: actual sample and monitor timing is not guaranteed, and
  no wall-clock latency or OOM-safety property follows from them.
- **Interim (S2):** memory scales, vCPUs do not. Every session keeps `1` online
  vCPU whatever `--cpus` says, so the CPU ceiling still only reserves capacity
  until [#647](https://github.com/gregwebs/agent-vm/issues/647), itself blocked on
  [#654](https://github.com/gregwebs/agent-vm/issues/654).
- The monitor is one in-process task per session, owned by the launch's teardown,
  and it holds the only handle that stops it. Teardown stops it before any
  lifecycle operation, so a resize cannot be dispatched against a VM that is
  already stopping; abort/join proves local cessation only, because a delivered
  request is not cancellable and guest convergence continues.
- Recovery can persist a `NextStart` memory seed that outlives the launcher (D5.4),
  so a retained sandbox record may start above 512 MiB. Nothing rolls it back, and
  a plain live request equal to it can be an applied no-op. 512 MiB at boot is a
  **fresh launch** guarantee.
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
  `memory_host_resident_bytes` undercounts, so neither S2's controller nor any
  user-facing figure uses it. Decisions rest on the guest-reported limit and
  availability, and the host's own accounting of a session can differ from its
  commitment.
- The default shape adds virtio-mem and, for `--cpus >= 2`, msb-cpu. Each takes a
  device slot (see `ARCHITECTURE.md` *Split irqchip and the virtio-IRQ ceiling*).
