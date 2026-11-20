# ADR-0070: Dynamic resource commitment within `--memory` and `--cpus` ceilings

## Status

**Accepted and implemented** ([#645](https://github.com/gregwebs/agent-vm/issues/645),
[#646](https://github.com/gregwebs/agent-vm/issues/646),
[#647](https://github.com/gregwebs/agent-vm/issues/647); D3's cushion amended by
[#712](https://github.com/gregwebs/agent-vm/issues/712)). Both axes are live:
memory commitment (D3) and CPU commitment (D4). Amends
[ADR-0018](0018-machine-checked-boundary-contracts.md) (adds the pure
resource-commitment sizing, memory hysteresis, recovery-baseline, recovery-seed,
CPU-rate and CPU-policy kernels to the verified surface).

**Native evidence is partial, and says so.** Live memory growth and one live CPU
step (1→2, from nine distinct highs) were observed on a real VM. A native
**multi-step** CPU climb or shrink — the `1→2→3→4` and `4→3→2→1` sequences — has
never been observed: the sustained-demand native runs were interrupted, and the
calibration gates are recorded INCONCLUSIVE/BLOCKED under S-G. The "host supply"
explanation for that was **withdrawn** after controlled measurement showed the
per-row rate both under- and over-reading a pegged vCPU at short intervals, so the
honest statement is "not observed", not "blocked by the host". The CPU policy's
evidence for scale-down and for consecutive steps is the deterministic
injected-observation tests, not a live trial. See `verifications.md` for the
recorded runs.

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
requests 200 ms (nominal 5 Hz; the SDK default is 1 s). Shared-host measurements
found additional idle cost, and the residency walk alone took about 11.5 ms per
tick for a 1 GiB guest; neither is a general performance guarantee (D4).

## Decision

### Terms

- **Resource ceiling**: a session's boot-time maximum vCPU and memory capacity
  (`max_cpus`, `max_memory_mib`), set by `--cpus` / `AGENT_VM_CPUS` and
  `--memory` / `AGENT_VM_MEMORY_GIB`. The design lets live resize grow and
  shrink a running guest's **resource commitment** within this ceiling, never
  beyond it. Both steps, memory and vCPU, are live (D3, D4).
- **Boot commitment**: the initial online vCPUs and memory (`cpus`,
  `memory_mib`) a session starts with at VM creation: `min(1, max_cpus)` vCPUs
  and `min(512 MiB, max_memory_mib)` RAM. Because `virtio-mem` only plugs and
  unplugs blocks above it and `virtio_msb_cpu` scales online vCPUs down to `1`,
  it is also the session's lower bound. Both devices are attached at creation
  and the launcher drives both (D2-D4).
- **Resource commitment**: the online vCPU count and usable guest memory target
  currently enforced for a running session, between its **boot commitment** and
  its **resource ceiling**. Both halves are live: memory (D3) and vCPUs (D4).

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
carry the CPU half when #647 is implemented; #654 repaired the runtime's CPU
pairing at 200 ms.

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

The monitor is one task over **one** metrics read per tick and one serial apply
owner, not one controller per axis. Memory is evaluated first from the row and
never awaits a lifecycle query. Simultaneously **admitted** proposals — not
proposals the driver could make if it waited — are combined into one
`sandbox.modify()` builder and one live `.apply()` (S-E below); an axis with no
proposal, an unusable sample or a damped request never blocks the other. A
recovering axis may additionally need one configuration-only `NextStart` apply, so
recovery is bounded by at most one prepare plus one live apply per tick. The
operation is not atomic, and no receipt makes it so.

Both axes damp a repeated failing request on the same schedule: the first repeat
is immediate, later repeats wait `min(50, 5*(attempts-1))` polls, and a changed
ask never inherits the count. CPU additionally keeps an **outstanding-demand**
record that its corrective retry does not touch, so a re-confirmation that
returns enforcement to the baseline cannot erase the guest's unmet demand or its
deadline (D4.1).

### D3. Target-headroom memory tracking

**Status: implemented (#646), amended by
[#712](https://github.com/gregwebs/agent-vm/issues/712): the cushion is a 2048 MiB
reserve** (see *The cushion is a reserve* below).

Linux does not pause page faults waiting for `virtio-mem`, so the guest must
retain enough free plugged headroom to absorb allocations during the whole
reaction chain: the 200 ms poll that observes the demand, the balloon sample that
poll reads, the live apply, and the guest's own plug. Demand arrives as a **rate**
over that chain's *duration*, so the cushion must cover rate × chain — an amount a
fraction of what is already resident cannot supply (see *The cushion is a reserve*
below).

1. When `memory_available_bytes` is reported,
   `used_mib = ceil((memory_limit_bytes - memory_available_bytes) / MiB)` — the
   ceiling, not a truncation, so a fraction of a MiB of use cannot hide below the
   headroom:
   ```text
   headroom_mib = max(2048, used_mib / 4)
   desired_mib  = clamp(round_up_128_mib(used_mib + headroom_mib), boot_memory_mib, max_memory_mib)
   ```
   Quantization precedes clamping, so an unaligned ceiling or floor is preserved
   as itself rather than being rounded to a step. `max_memory_mib` still clamps, so
   a ceiling at or below the reserve holds the commitment at the ceiling from the
   first usable tick, and a session that has used nothing still commits the reserve
   (`2048 MiB`) then.
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

#### The cushion is a reserve (amendment)

D3 originally kept `max(256 MiB, 25% of used)` free, which is a *level*: at a
1.2 GiB build it holds ≈ 300 MiB, so each tick's target moves by only ≈ 1.25×
that tick's growth in use. Measured by the operator on this stack (2026-11-20,
macOS 27.2.1 arm64, one vCPU, macOS dev bundle), a guest program that `malloc`s,
touches every page and holds all of them:

| anon demand | `max(256, used/4)` | `max(2048, used/4)` |
|---|---|---|
| 0.31 GiB/s (64 MiB / 200 ms) | survived | survived |
| 0.63 GiB/s (64 MiB / 100 ms) | OOM-killed at ≈ 2 GiB | survived to 3 GiB |
| 1.25 GiB/s (64 MiB / 50 ms) | OOM-killed at ≈ 0.5 GiB | survived to 3 GiB |
| ≈ 4 GiB/s (tight 8 MiB loop) | OOM-killed at ≈ 384 MiB | survived; 2 GiB held in 0.5 s |

Ramps at 2.0–3.1 GiB/s were run only with the reserve, where they also survived.

Provenance: the demand table above, the ramps, the plug latencies below, the
≈ 2.5 GiB/s absorption calculation and the 3.3/1.3 GiB RSS measurement are operator
measurements from [#712](https://github.com/gregwebs/agent-vm/issues/712) on the
2026-11-20 stack named above, not this branch's own evidence. Only the 1.25 GiB/s
row was re-run on the tree this amendment lands on, recorded in #712's PR body.

The plug is not the limit: a 3.5 GiB target jump reached the guest in ~210 ms and
a 7.7 GiB one in ~1.1 s. What fails is the *cushion* — the demand inside one
reaction chain (a 200 ms poll, the balloon sample that poll reads, the apply, the
plug) exceeds the free memory a level rule keeps, and a level rule cannot buy
more because it only ever asks for ≈ 25% of what is already resident. A 2048 MiB
reserve absorbs ≈ 2.5 GiB/s across a 0.8 s chain, with growth landing in time, and
is clamped by the ceiling. The commitment is not host memory: `virtio-mem`
allocates on touch and a guest that frees pages returns them, so an unused reserve
becomes resident only once the guest reaches it. One measurement, anon memory
touched then freed: 3.3 GiB host RSS while a guest held 3 GiB, 1.3 GiB after —
nearly free, not free. What the guest actually touches does cost host memory,
whatever the policy. `used` is the reported limit minus
`memory_available_bytes`. Clean page cache is reclaimable, so it counts as
available, and on this stack so does dirty page cache: a guest writing 1.5 GiB
of file data (`dd if=/dev/zero of=/root/big bs=1M count=1536`, as root) raised
`Cached` by 1.5 GiB while derived `used` moved 85 → 89 MiB and the target stayed
at 2176 MiB; a second run of the same 1.5 GiB write sampled 266 MiB of it dirty
mid-write and ended with `MemAvailable` within 12 MiB of where it started. File
pages are available to the guest either way. What raises `used` is memory the
guest cannot hand back — anonymous and shared memory — and boot shows that
direction: the `Dockerfile.dev` image raises derived use by ≈ 1.66 GiB with no
user write, taking the target 2176 → 3840 MiB, and the target rejoins the lower
demand only after the 50-tick dwell. The cache-as-host-cost case is **not
measured**. The cost is a higher commitment: a session that has used anything
commits **at least** 2176 MiB (2.125 GiB, ≈ 2.1 GiB), ≈ 72–73% below the 8 GiB
ceiling — 2176 MiB while use is up to 128 MiB, 2304 MiB (2.25 GiB) at the ≈ 141
MiB of residual use a settled guest has — rather than the 512 MiB floor.

### D4. Sustained-saturation CPU tracking

**Status: implemented** ([#647](https://github.com/gregwebs/agent-vm/issues/647)).
The two counts, both thresholds and the 200 ms interval are unchanged from the
decision; the operator superseded "consecutive ticks" with "consecutive **distinct
observations**" (S-F) because duplicates are routine at this interval.

Saturation is measured at `C * 95%` — a margin against ordinary measurement noise
and the guest's own idle work, **not** compensation for a scheduling skew (S-A:
after the pairing repair, per-row agreement was median 0.11–0.16 percentage
points, maximum 1.56, across four native runs) — with a 10%-per-vCPU hysteresis
gap on scale-down to prevent oscillation:

1. **Scale-up (`C -> C + 1`, up to `max_cpus`)**: Requires
   `cpu_percent >= C * 95.0` for **10 consecutive distinct observations (nominal
   2 s)**, resetting the counter after stepping up.
2. **Scale-down (`C -> C - 1`, down to `1`)**: Requires
   `cpu_percent <= (C - 1) * 85.0` for **5 consecutive distinct observations
   (nominal 1 s)**, resetting the counter after stepping down.

**Runtime CPU pairing repaired by
[#654](https://github.com/gregwebs/agent-vm/issues/654).** The #645 S1 run on
2026-11-16 (macOS 27.0.0 arm64, Apple M1 Pro, HVF) recorded rejection of **284 of
284** pairing windows at 200 ms (mean spread 12.3 ms against the 10.7 ms allowed)
and **13 of 13** at the 1 s default (62.5 ms against 53 ms). Follow-up
measurements on the same host (2026-11-17/18, `msb 0.7.13`) reproduced a stale
`0.0 %` at 200 ms while `vcpu_time_ns` advanced at about 80 % of wall time, but
found **fresh** 1 s readings of 76.3 % at info and 67.4 % at debug, each matching
its cumulative counter delta — so "no fresh reading at any interval" was not
universal, and the earlier 1 s rejection came from a different scan width.

The systematic spread was the VMM's host-resident page-map scan, not a scheduling
floor. `aggregate_snapshot()` runs the walk that `msb_krun_vmm` installs, and that
walk measured 11.45–11.52 ms on an idle 1 GiB guest (stable to ±0.05 ms across
ticks) and 12.3 ms with the guest pegged, while the same call with no sampler
registered is 42 ns (p99 over 200 000 calls). Load barely moved it and removing
the walk made it 10⁵ cheaper; the bracket contained the scan. The runtime now
brackets the cheap aggregate read for CPU pairing and takes residency separately,
so the 5 % guard remains a gross-stall backstop instead of measuring the scan's
width. That repairs the carried-over reading #645 observed; it removes #654, not
the [#647](https://github.com/gregwebs/agent-vm/issues/647) CPU
controller, and #646 still consumes only `memory_limit_bytes` and
`memory_available_bytes`. Native verification of the landed fix
(`vendor/microsandbox` `25c29e17`; 1 GiB / 1 vCPU at 200 ms) published rows whose
per-row agreement with the counter delta had a median of 0.11–0.16 percentage
points (max 1.56) across four runs, idle ≈ 0.13 % and busy ≈ 97 %.

The interval is still not free: idle CPU measured **8.05 % mean** over three
60-sample rounds at 200 ms against **4.86 %** for `main`'s 1 s default — ≈ +3
percentage points, on a shared host, so indicative rather than a benchmark — and
the page walk alone costs about 11.5 ms per tick for a 1 GiB guest (D5.5).

#### D4.1 Measurement, eligibility and recovery (implemented)

- **Conversion.** A rate is a conservative integer tenths interval
  `[floor(10r), ceil(10r)]`. Scale-up compares its lower endpoint with
  `C * 950`, scale-down its upper endpoint with `(C-1) * 850`, so `94.999%` cannot
  round into saturation and `85.001%` cannot round into low load. The interval is
  produced by a proved decoder over the raw `f32` bits; the host's floating-point
  meaning, the SDK percentage units and the delivery of a genuine observation stay
  trusted.
- **Distinct observations (S-F).** A **duplicate** row (same runtime timestamp as
  the epoch high-water) neither counts nor resets a run and never dispatches or
  probes, even with an expired retry. A **gap** (absent row or lookup error), a
  usable-but-absent/zero/invalid rate, and an observed non-running or unavailable
  lifecycle reset both runs. A **regressed** timestamp resets the evidence,
  increments a regression streak and never lowers the high-water.
- **Epoch and the one correction.** The high-water never decreases inside an
  epoch; the sole exception is the operator-approved re-anchor after **100
  consecutive regressed polls** (20 s nominal), which adopts that poll's timestamp,
  clears the streak and both runs, invalidates the lifecycle cache and discards
  the row. Equal timestamps interrupt the streak, so alternating replay cannot
  force a correction. Re-anchoring can re-admit at most one previously consumed
  row per correction streak, because re-admission advances the high-water and an
  equal timestamp is then a duplicate. This assumes one monitor owns the slot, that
  samples carry host UTC and that corrections coalesce within 20 s; it is bounded
  replay resistance, not perfect rejection. Uptime and vCPU time are not row
  identities, and neither is enforcement authority.
- **The published zero is ambiguous (S-B, corrected).** `0.0` can be a computed
  zero delta or the registry's encoding of an absent rate, and the SDK field is a
  non-optional `f32`. It proves neither absence nor idleness: it makes **no demand
  decision**, resets both runs and holds the commitment, on any row and whatever
  the lifecycle cache's age. A guest publishing exactly
  `0.0` therefore cannot be reclaimed by demand policy — idle reclamation at
  exactly zero is unavailable by design — while a small positive rate can shrink.
  Corrective recovery is not a demand decision and still proceeds (below).
- **Lifecycle eligibility (N1).** Demand work needs a usable positive rate on a
  distinct row; corrective recovery needs only a distinct row. The query is lazy:
  one bounded `pause_state()` probe (50 ms await bound) at most once per 1 s TTL,
  measured from attempt start and cached including failures, with zero probes on
  duplicates, gaps, fixed bounds or rows where CPU needs nothing, and TTL expiry
  alone never starts one. An admitted memory request has dispatch priority: CPU is
  deferred and its evidence reset rather than making memory wait. The cache is
  **not a pause fence**: a pause/resume wholly inside one TTL is undetectable, and
  a row captured before, or a control request delivered after, a Running reply can
  still race. The bound is that the next receipt resolves the race — a usable
  receipt confirms enforcement and resets the runs; an error enters Recovering
  with its evidence reset and no rollback claim. No failure is ever read as "no
  effect".
- **Authority.** Only a usable live receipt's **enforced** value establishes CPU
  authority. The catalog's `cpus`, the adjacent report value, the saved desired
  value, `cpu_percent`, guest `nproc` and pause state are never authority. The
  SDK writes the *requested* CPU into active config even when the receipt's
  enforced value differs, so active config is not authority either.
- **Rate-independent corrective recovery.** After an ambiguous outcome the driver
  re-confirms the last receipt-accepted CPU on the next distinct, running row at
  **any** rate — including a long run of published zeros — through a durable
  configuration seed and one live apply, damped by a correction retry whose
  identity is the target alone. It deliberately does not consult the demand
  kernel, and it does not clear outstanding demand: only a receipt that moves
  enforcement toward the demand's anchor, or genuine new demand evidence, does
  that. Genuine new demand evidence is a changed direction or target, or a
  continuing same-direction observation — up is still demanded while the
  conservative lower endpoint reaches `C * 95` below the ceiling, down while the
  upper endpoint reaches `(C-1) * 85` above the floor. A deadband or boundary hold
  on a positive distinct eligible observation therefore **ends** the demand and its
  deadline, while a zero, gap, duplicate, regression, pause, cache invalidation or
  correction alone never does. A successful correction therefore costs at most one
  prepare and one live apply and cannot reset the demand's no-progress count or
  deadline.
- **Single-step scope.** The proved single-step property covers policy proposals
  from valid accepted states, not external mutations or ambiguous I/O. Observed
  `actual` may differ from `requested` without failure: guest convergence is
  asynchronous and trusted.

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
   - `memory_desired_mib` — `clamp(round_up_128(ceil_used + max(2048, ceil_used/4)), boot, max)`
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
   What S3 adds, again verified for **every** input:
   - `cpu_rate_tenths` — `[min(255000, n/d), min(255000, n/d + (n%d != 0))]`
     exactly, `None` iff a zero numerator or denominator, every intermediate
     widened; `hi - lo <= 1` and `hi > 0` for every `u32` pair.
   - `cpu_rate_from_bits` — the specified IEEE-754 piecewise mapping, not merely
     bounds: reject sign/`NaN`/infinity/`+0`, saturate at `25500%`, report positive
     tiny values as `[0,1]`, otherwise divide the exact significand by the exact
     power of two, with the shift bounds and `×10` overflow-freedom proved.
   - `cpu_target_in_bounds` — exactly `1 <= boot <= target <= max`.
   - `cpu_tick` — the complete ordered transition table: invalid bounds, a
     normalized out-of-interval current, no/invalid rate, the high run at 9,
     the low run at 4, and every floor- or ceiling-inhibited hold; `high <= 9`,
     `low <= 4`, at most one nonzero, an in-range result and a one-step move from a
     valid state.
   - `cpu_recovery_seed` — in-range and distinct from the re-confirm target,
     `boot` first and then `boot + 1`, `Some` iff such a value exists, so the
     two-value `1..=2` interval works for either target.
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
     promise. A live request equal to the seed can be a statusless no-op while the
     saved configuration already holds it, so a genuine change reseeds again; a hold
     never repairs or rolls back configuration, and abort/join is not transaction
     rollback. In production that collision is out of reach: `--memory` counts whole
     GiB with a 2048 MiB reserve, so every live ask is at least 1024 MiB while the
     candidates are 512, 640 and 768. The candidate sequence remains the kernel's
     guarantee that a seed differs from both the observed baseline and the target.
   These rules are memory's; the CPU axis keeps the unknown-outcome rule and its
   own durable demand separately (D4.1). A change of authority does **not** clear
   the CPU axis's outstanding demand or its deadline: only progress, or genuinely
   new demand evidence, does.
   The invariant is enforced by the driver's branch structure and the stateful
   model tests, not by the numeric proof: the seed kernel proves
   numeric safety and distinctness, while provenance, persistence and liveness
   stay trusted.
5. **CPU sample degradation.** CPU rate math pairs the cumulative vCPU counter with
   the bracket midpoint of the cheap aggregate read. Residency is a separate
   observation outside that bracket, still taken off the async workers; paused
   samples omit residency, and a stopped sandbox keeps publishing its last sample
   (`ReleaseMode::Stale`). A published `0.0` is **ambiguous**, not a distinct
   third state: the runtime can compute a genuine zero delta, and the registry also
   encodes an absent rate as zero (S-B). Neither origin proves idleness, so `0.0`
   makes no demand decision. Exactly-zero guests therefore cannot be reclaimed by
   demand policy; small positive rates can. A genuinely
   unreliable pairing window still carries the last trustworthy percentage, or
   publishes zero before any trustworthy rate exists. A published row therefore
   spans three instants: cumulative counters at the cheap read, residency up to
   one page walk later, and `sampled_at` at the write. `cpu_percent` describes the
   interval between two cheap reads and is exact for that interval; the lag
   between it and `sampled_at` is one walk (≈ 11.5 ms at 1 GiB, up to the walk's
   duration on a large guest), which the CPU controller treats as lag rather than
   bias.

   Lifecycle eligibility is a separate, lazy observation (D4.1). It is a
   *detection* mechanism with a stated bound, **not** a pause fence: a pause and
   resume wholly inside one 1 s TTL is unobservable, and no public check makes row
   capture, pause, probe reply and apply delivery atomic. A missed pause can only
   produce an apply that succeeds (a legal modification of a sandbox that is
   running again) or fails and enters Recovering with its evidence reset; it cannot
   produce a persistent wrong authority, because no failure is read as "no
   effect". The same holds for a row captured before a pause and admitted after
   resume. The
   upper-filesystem staleness window shrinks by the same walk. This is a runtime
   sampling correction, not a shared-memory ABI or a controller policy change.

## Alternatives rejected

- **Shelling out to `msb metrics` and `msb modify`.** Rejected: spawning
  subprocesses at 5 Hz adds process and SQLite overhead for operations the
  in-process SDK already owns.
- **A 256 MiB memory floor.** Rejected: Node.js/agent startup bursts can allocate
  several hundred MiB within a single 200 ms window before `virtio-mem` finishes
  plugging blocks; 512 MiB provides a safer initial cushion. Boot is 512 MiB,
  93.75% below the 8 GiB default ceiling; once the D3 monitor settles, a session
  that has used anything commits at least 2176 MiB (≈ 2.1 GiB), ≈ 72–73% below
  it.
- **A 256 MiB / 25%-of-use cushion above the boot floor** (the original D3). Kept
  the idle commitment at 512 MiB but could not survive a link-class burst; see
  "The cushion is a reserve". Rejected for OOM safety, not for cost.
- **A cushion only while the guest is busy** (a reserve that decays once demand
  stops, or one that applies only above a use threshold). Rejected: the burst it
  has to survive can *start* the busy period — a cached `cargo build` that only
  relinks, or the first tool call of a session — and by the time the decayed
  cushion is refilled the guest is already out of memory.
- **Jumping to the ceiling instead of adding a reserve.** Rejected: it survives
  bursts, but a session that alternates work and idleness would plug and unplug
  the whole ceiling every dwell period. The price of that churn is **not
  measured**, and the plug is not the limit anyway (see above).
- **Polling faster than 200 ms.** Not chosen: no measurement shows a shorter
  interval is needed for the controller, and the per-tick residency walk already
  has measurable cost (D4). Separating that scan's cadence from the CPU rate needs
  explicit staleness semantics before a faster interval is worth considering.
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

- Default launches set an 8 GiB / 2 vCPU ceiling and boot at the 512 MiB /
  1 vCPU boot commitment — 93.75% below the ceiling at boot. Memory then follows
  D3 (immediate growth, reclamation after 50 lower-demand ticks plus convergence,
  200 ms polling), keeping a 2048 MiB reserve free — so once the monitor settles,
  a session that has used anything commits **at least** 2176 MiB (2.125 GiB,
  ≈ 2.1 GiB), ≈ 72–73% below the ceiling rather than at the 512 MiB floor.
  (2048 MiB / 75% is only the formula's zero-use floor: any use at all, even one
  byte, puts the target at 2176 MiB, and the ≈ 141 MiB of residual use a settled
  guest has puts it at 2304 MiB = 2.25 GiB.) All of those timings are
  **nominal**: actual sample and monitor timing is not guaranteed, and no
  wall-clock latency or OOM-safety property follows from them. The reserve is
  what a burst needs inside one reaction chain; it is not a guarantee that a
  burst cannot outrun the monitor.
- **Both axes are live (S3).** Memory follows D3; vCPUs follow D4: one step up on
  the 10th consecutive distinct observation at `C * 95%`, one step down on the 5th
  at `(C-1) * 85%`, within `1..=max_cpus`. The 2 s / 1 s figures assume a distinct
  observation at every nominal 200 ms poll; they are dwell in observations, not
  deadlines, and lengthen with duplicates or a slower publication period. CPU
  cannot promise convergence to an arbitrary target: the metric under-reports on a
  contended host (operator evidence M5/M6) and the accepted policy is to settle at
  a sustainable commitment rather than compensate. Exactly-zero guests are not
  reclaimed by demand policy (D4.1).
- **Native multi-step scaling is unverified.** One live 1→2 step and live memory
growth were observed natively; a multi-step CPU climb or any native shrink was
never observed, and no attested integrated run covers the final tree (S-G:
BLOCKED/INCONCLUSIVE). Sustained demand at short sample intervals also
both under- and over-reads a pegged vCPU — 87, 93, 82, 120, 106, 106, 100, 51, 97
percent at capacity 4 and 86, 98, 100, 82, 100 at capacity 1, on the runtime's
**default** interval — so the per-row rate is noisy independent of capacity.
That is a runtime measurement concern to report, not a reason to tune 95/85, 10/5
or the 200 ms cadence. The deterministic injected-observation tests are what
establish the CPU policy.
- The monitor is one in-process task per session, owned by the launch's teardown,
  and it holds the only handle that stops it. Teardown stops it before any
  lifecycle operation, so a resize cannot be dispatched against a VM that is
  already stopping; abort/join proves local cessation only, because a delivered
  request is not cancellable and guest convergence continues.
- Recovery can persist a `NextStart` memory **or CPU** seed that outlives the
  launcher, so a retained record can also start at a different vCPU count than the
  fresh-launch boot commitment. The CPU seed is a repair value, never a policy
  target or a receipt.
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
