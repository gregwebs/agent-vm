//! Sandbox resource commitment ([ADR-0070] D1-D3): the **resource ceiling** the
//! launch options set, the **boot commitment** every launch route boots at, and the
//! **memory commitment** the in-process monitor adjusts between them.
//!
//! Two halves, split by ADR-0018. The `verus!` block holds the decisions — launch
//! sizing, then the memory target, hysteresis, recovery-baseline and recovery-seed
//! kernels — and is erased to ordinary Rust by a plain build. Everything after it is
//! the trusted shell: the SDK metrics and modify calls, the stream driver that owns
//! the authority, and the task guard the teardown joins.
//!
//! [ADR-0070]: ../../../docs/adr/0070-dynamic-resource-commitment.md

use std::future::Future;
use std::time::Duration;

use microsandbox::sandbox::SandboxBuilder;
use tracing::Instrument as _;
use vstd::prelude::*;

verus! {

/// The boot commitment's memory when the ceiling allows it. It is also the floor
/// live resize can never go below, because virtio-mem only plugs above it.
const BOOT_MEMORY_MIB: u32 = 512;
/// The boot commitment's online vCPUs, and the floor the CPU controller keeps.
const BOOT_CPUS: u8 = 1;
/// `u64` so the product of any `u32` GiB value cannot overflow before it is compared.
const MIB_PER_GIB: u64 = 1024;

const BYTES_PER_MIB: u64 = 1024 * 1024;
/// The allocation step `virtio-mem` can act on, and the quantum every live target is a
/// multiple of unless a clamped endpoint falls inside the interval. Quantizing before
/// clamping is deliberate: a ceiling or floor need not be a multiple of the step.
const MEMORY_STEP_MIB: u64 = 128;
/// The floor of the free-memory cushion kept above the guest's used MiB.
const MIN_MEMORY_HEADROOM_MIB: u64 = 256;
/// 50 ticks at [`METRICS_SAMPLE_INTERVAL`] is a nominal 10 s; the interval requests
/// samples and guarantees no period.
const MEMORY_LOW_TICKS: u32 = 50;

/// Why a launch's resource options cannot form a ceiling, in refusal precedence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
enum CeilingRefusal { ZeroMemory, MemoryOverflow, ZeroCpus }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Sizing { max_cpus: u8, max_memory_mib: u32, boot_cpus: u8, boot_memory_mib: u32 }

/// The memory interval a session may move within: `min(512, ceiling) ..= ceiling`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MemoryBounds { boot_memory_mib: u32, max_memory_mib: u32 }

/// A memory target and the count of consecutive lower-demand ticks behind it.
///
/// [`memory_tick`] returns a **proposal**; only the driver that performed the I/O may
/// treat a target as accepted, so this type never claims a resize happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MemoryState { current_target_mib: u32, low_ticks: u32 }

/// One metrics observation of the two fields the policy uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MemorySample { memory_limit_bytes: u64, memory_available_bytes: Option<u64> }

spec fn memory_fits(memory_gib: u32) -> bool { memory_gib as int * 1024 <= u32::MAX as int }

fn memory_ceiling_mib(memory_gib: u32) -> (r: Result<u32, CeilingRefusal>)
    ensures
        match r {
            Ok(mib) => memory_gib >= 1 && memory_fits(memory_gib)
                && mib as int == memory_gib as int * 1024,
            Err(CeilingRefusal::ZeroMemory) => memory_gib == 0,
            Err(CeilingRefusal::MemoryOverflow) => memory_gib >= 1 && !memory_fits(memory_gib),
            Err(CeilingRefusal::ZeroCpus) => false,
        },
{
    if memory_gib == 0 {
        return Err(CeilingRefusal::ZeroMemory);
    }
    let mib = memory_gib as u64 * MIB_PER_GIB;
    if mib > u32::MAX as u64 { Err(CeilingRefusal::MemoryOverflow) } else { Ok(mib as u32) }
}

fn boot_cpus(max_cpus: u8) -> (boot: u8)
    ensures
        boot == if max_cpus < BOOT_CPUS { max_cpus } else { BOOT_CPUS },
        max_cpus >= 1 ==> 1 <= boot <= max_cpus,
{
    if max_cpus < BOOT_CPUS { max_cpus } else { BOOT_CPUS }
}

fn boot_memory_mib(max_memory_mib: u32) -> (boot: u32)
    ensures
        boot == if max_memory_mib < BOOT_MEMORY_MIB { max_memory_mib } else { BOOT_MEMORY_MIB },
        max_memory_mib >= 1 ==> 1 <= boot <= max_memory_mib,
        max_memory_mib >= BOOT_MEMORY_MIB ==> boot == BOOT_MEMORY_MIB,
{
    if max_memory_mib < BOOT_MEMORY_MIB { max_memory_mib } else { BOOT_MEMORY_MIB }
}

/// The whole launch decision: refuse a zero or unrepresentable ceiling (memory
/// first), otherwise the ceiling exactly as given and the boot commitment within it.
fn launch_sizing(memory_gib: u32, cpus: u8) -> (r: Result<Sizing, CeilingRefusal>)
    ensures
        match r {
            Ok(s) => memory_gib >= 1 && memory_fits(memory_gib) && cpus >= 1
                && s.max_memory_mib as int == memory_gib as int * 1024
                && s.max_cpus == cpus
                && s.boot_cpus == BOOT_CPUS && s.boot_memory_mib == BOOT_MEMORY_MIB
                && 1 <= s.boot_cpus <= s.max_cpus
                && 1 <= s.boot_memory_mib <= s.max_memory_mib,
            Err(CeilingRefusal::ZeroMemory) => memory_gib == 0,
            Err(CeilingRefusal::MemoryOverflow) => memory_gib >= 1 && !memory_fits(memory_gib),
            Err(CeilingRefusal::ZeroCpus) => memory_gib >= 1 && memory_fits(memory_gib) && cpus == 0,
        },
{
    let max_memory_mib = memory_ceiling_mib(memory_gib)?;
    if cpus == 0 {
        return Err(CeilingRefusal::ZeroCpus);
    }
    Ok(Sizing {
        max_cpus: cpus,
        max_memory_mib,
        boot_cpus: boot_cpus(cpus),
        boot_memory_mib: boot_memory_mib(max_memory_mib),
    })
}

// ADR-0070 D3: the target-headroom decision. The specs below are int arithmetic so
// they state the formulas without the executable forms' overflow guards; the
// `ensures` of each kernel is what ties the two together.

spec fn spec_ceil_mib(bytes: int) -> int {
    (bytes + BYTES_PER_MIB as int - 1) / (BYTES_PER_MIB as int)
}

spec fn spec_headroom_mib(used_mib: int) -> int {
    if used_mib / 4 > MIN_MEMORY_HEADROOM_MIB as int { used_mib / 4 } else { MIN_MEMORY_HEADROOM_MIB as int }
}

spec fn spec_round_up_mib(raw_mib: int) -> int {
    ((raw_mib + MEMORY_STEP_MIB as int - 1) / (MEMORY_STEP_MIB as int)) * (MEMORY_STEP_MIB as int)
}

spec fn spec_rounded_mib(bytes: int) -> int {
    spec_round_up_mib(spec_ceil_mib(bytes) + spec_headroom_mib(spec_ceil_mib(bytes)))
}

spec fn memory_desired_spec(bounds: MemoryBounds, bytes: int) -> int {
    if bounds.boot_memory_mib as int > bounds.max_memory_mib as int {
        bounds.boot_memory_mib as int
    } else if spec_rounded_mib(bytes) < bounds.boot_memory_mib as int {
        bounds.boot_memory_mib as int
    } else if spec_rounded_mib(bytes) > bounds.max_memory_mib as int {
        bounds.max_memory_mib as int
    } else {
        spec_rounded_mib(bytes)
    }
}

/// `clamp(round_up_128(ceil(used) + max(256, ceil(used)/4)), boot, max)`.
///
/// Total over every input: reversed bounds are not a production shape, and returning
/// `boot` for them keeps the range clauses honest instead of narrowing the domain.
// The arithmetic stays in this spelling because it is the form the verifier checks:
// `div_ceil` and `is_multiple_of` carry no Verus specification, so using them would move
// the quantization outside the proved body.
#[allow(clippy::manual_div_ceil, clippy::manual_is_multiple_of)]
fn memory_desired_mib(bounds: MemoryBounds, used_bytes: u64) -> (target: u32)
    ensures
        target as int == memory_desired_spec(bounds, used_bytes as int),
        bounds.boot_memory_mib <= bounds.max_memory_mib ==> {
            &&& (bounds.boot_memory_mib as int) <= (target as int)
            &&& (target as int) <= (bounds.max_memory_mib as int)
        },
        (bounds.boot_memory_mib <= bounds.max_memory_mib
            && (bounds.boot_memory_mib as int) <= spec_rounded_mib(used_bytes as int)
            && spec_rounded_mib(used_bytes as int) <= (bounds.max_memory_mib as int)) ==> {
            &&& target as int == spec_rounded_mib(used_bytes as int)
            &&& target as int % (MEMORY_STEP_MIB as int) == 0
        },
        ((bounds.boot_memory_mib as int) < (target as int)
            && (target as int) < (bounds.max_memory_mib as int))
            ==> target as int % (MEMORY_STEP_MIB as int) == 0,
{
    let boot = bounds.boot_memory_mib;
    let max = bounds.max_memory_mib;
    if boot > max {
        return boot;
    }
    let whole = used_bytes / BYTES_PER_MIB;
    let used_mib = if used_bytes % BYTES_PER_MIB != 0 { whole + 1 } else { whole };
    proof {
        assert(used_mib as int == spec_ceil_mib(used_bytes as int));
    }
    let headroom_mib = if used_mib / 4 > MIN_MEMORY_HEADROOM_MIB { used_mib / 4 } else { MIN_MEMORY_HEADROOM_MIB };
    proof {
        assert(headroom_mib as int == spec_headroom_mib(spec_ceil_mib(used_bytes as int)));
    }
    let raw_mib = used_mib + headroom_mib;
    let rounded_mib = ((raw_mib + MEMORY_STEP_MIB - 1) / MEMORY_STEP_MIB) * MEMORY_STEP_MIB;
    proof {
        assert(rounded_mib as int == spec_rounded_mib(used_bytes as int));
    }
    if rounded_mib < u64::from(boot) {
        boot
    } else if rounded_mib > u64::from(max) {
        max
    } else {
        rounded_mib as u32
    }
}

/// The one interval test every accepted or observed target goes through.
fn memory_target_in_bounds(bounds: MemoryBounds, target_mib: u32) -> (accepted: bool)
    ensures accepted == (bounds.boot_memory_mib <= target_mib && target_mib <= bounds.max_memory_mib)
{
    bounds.boot_memory_mib <= target_mib && target_mib <= bounds.max_memory_mib
}

spec fn norm_target(bounds: MemoryBounds, target_mib: u32) -> int {
    if (target_mib as int) < (bounds.boot_memory_mib as int) {
        bounds.boot_memory_mib as int
    } else if (target_mib as int) > (bounds.max_memory_mib as int) {
        bounds.max_memory_mib as int
    } else {
        target_mib as int
    }
}

spec fn norm_low(low_ticks: u32) -> int {
    if (low_ticks as int) > (MEMORY_LOW_TICKS as int) { MEMORY_LOW_TICKS as int } else { low_ticks as int }
}

spec fn bounds_reversed(bounds: MemoryBounds) -> bool {
    bounds.boot_memory_mib as int > bounds.max_memory_mib as int
}

/// Availability is usable only when it is present and at most the limit. The runtime
/// reports a pair like this briefly after a shrink; `used` would underflow.
spec fn tick_usable(sample: MemorySample) -> bool {
    match sample.memory_available_bytes {
        Some(avail) => avail <= sample.memory_limit_bytes,
        None => false,
    }
}

spec fn tick_used_bytes(sample: MemorySample) -> int {
    match sample.memory_available_bytes {
        Some(avail) => sample.memory_limit_bytes as int - avail as int,
        None => 0,
    }
}

spec fn tick_base_target(bounds: MemoryBounds, state: MemoryState) -> int {
    if bounds_reversed(bounds) { bounds.boot_memory_mib as int } else { norm_target(bounds, state.current_target_mib) }
}

spec fn tick_base_low(bounds: MemoryBounds, state: MemoryState) -> int {
    if bounds_reversed(bounds) { 0 } else { norm_low(state.low_ticks) }
}

spec fn tick_desired(bounds: MemoryBounds, sample: MemorySample) -> int {
    memory_desired_spec(bounds, tick_used_bytes(sample))
}

spec fn tick_incremented_low(bounds: MemoryBounds, state: MemoryState) -> int {
    let base = tick_base_low(bounds, state);
    if base + 1 > MEMORY_LOW_TICKS as int { MEMORY_LOW_TICKS as int } else { base + 1 }
}

spec fn tick_converged(bounds: MemoryBounds, state: MemoryState, sample: MemorySample) -> bool {
    sample.memory_limit_bytes as int == tick_base_target(bounds, state) * (BYTES_PER_MIB as int)
}

spec fn tick_adopts(bounds: MemoryBounds, state: MemoryState, sample: MemorySample) -> bool {
    tick_incremented_low(bounds, state) == MEMORY_LOW_TICKS as int
        && tick_converged(bounds, state, sample)
}

spec fn memory_tick_target_spec(bounds: MemoryBounds, state: MemoryState, sample: MemorySample) -> int {
    let base = tick_base_target(bounds, state);
    let desired = tick_desired(bounds, sample);
    if !tick_usable(sample) {
        base
    } else if desired >= base {
        desired
    } else if tick_adopts(bounds, state, sample) {
        desired
    } else {
        base
    }
}

spec fn memory_tick_low_spec(bounds: MemoryBounds, state: MemoryState, sample: MemorySample) -> int {
    let base = tick_base_target(bounds, state);
    let desired = tick_desired(bounds, sample);
    if !tick_usable(sample) {
        0
    } else if desired >= base {
        0
    } else if tick_adopts(bounds, state, sample) {
        0
    } else {
        tick_incremented_low(bounds, state)
    }
}

/// ADR-0070 D3: one tick of the hysteresis.
///
/// Growth is immediate; reclamation needs 50 consecutive lower-demand ticks *and* a
/// limit that has converged to the current target, because a downsize reports
/// `Applied` while actual RAM may still be above the target. Any other tick holds the
/// baseline and resets the run: an interrupted observation sequence is not evidence
/// of consecutive low demand.
fn memory_tick(bounds: MemoryBounds, state: MemoryState, sample: MemorySample) -> (next: MemoryState)
    ensures
        next.current_target_mib as int == memory_tick_target_spec(bounds, state, sample),
        next.low_ticks as int == memory_tick_low_spec(bounds, state, sample),
        bounds.boot_memory_mib <= bounds.max_memory_mib ==> {
            &&& (bounds.boot_memory_mib as int) <= (next.current_target_mib as int)
            &&& (next.current_target_mib as int) <= (bounds.max_memory_mib as int)
        },
        next.low_ticks <= MEMORY_LOW_TICKS,
        !tick_usable(sample) ==> {
            &&& next.current_target_mib as int == tick_base_target(bounds, state)
            &&& next.low_ticks == 0
        },
        (tick_usable(sample) && tick_desired(bounds, sample) > tick_base_target(bounds, state)) ==> {
            &&& next.current_target_mib as int == tick_desired(bounds, sample)
            &&& next.low_ticks == 0
        },
        (tick_usable(sample) && tick_desired(bounds, sample) == tick_base_target(bounds, state)) ==> {
            &&& next.current_target_mib as int == tick_base_target(bounds, state)
            &&& next.low_ticks == 0
        },
        (tick_usable(sample) && tick_desired(bounds, sample) < tick_base_target(bounds, state)) ==> {
            ||| { &&& next.current_target_mib as int == tick_base_target(bounds, state)
                  &&& next.low_ticks as int == tick_incremented_low(bounds, state) }
            ||| { &&& next.current_target_mib as int == tick_desired(bounds, sample)
                  &&& next.low_ticks == 0 }
        },
        (tick_usable(sample) && tick_desired(bounds, sample) < tick_base_target(bounds, state)
            && tick_adopts(bounds, state, sample)) ==> {
            &&& next.current_target_mib as int == tick_desired(bounds, sample)
            &&& next.low_ticks == 0
        },
{
    let boot = bounds.boot_memory_mib;
    let max = bounds.max_memory_mib;
    if boot > max {
        return MemoryState { current_target_mib: boot, low_ticks: 0 };
    }
    let base = if state.current_target_mib < boot {
        boot
    } else if state.current_target_mib > max {
        max
    } else {
        state.current_target_mib
    };
    let low = if state.low_ticks > MEMORY_LOW_TICKS { MEMORY_LOW_TICKS } else { state.low_ticks };
    let Some(avail) = sample.memory_available_bytes else {
        return MemoryState { current_target_mib: base, low_ticks: 0 };
    };
    if avail > sample.memory_limit_bytes {
        return MemoryState { current_target_mib: base, low_ticks: 0 };
    }
    let used_bytes = sample.memory_limit_bytes - avail;
    let desired = memory_desired_mib(bounds, used_bytes);
    if desired >= base {
        return MemoryState { current_target_mib: desired, low_ticks: 0 };
    }
    let incremented = if low >= MEMORY_LOW_TICKS { MEMORY_LOW_TICKS } else { low + 1 };
    let converged = sample.memory_limit_bytes == u64::from(base) * BYTES_PER_MIB;
    if incremented == MEMORY_LOW_TICKS && converged {
        MemoryState { current_target_mib: desired, low_ticks: 0 }
    } else {
        MemoryState { current_target_mib: base, low_ticks: incremented }
    }
}

spec fn observed_in_bounds(bounds: MemoryBounds, observed_mib: u32) -> bool {
    bounds.boot_memory_mib <= observed_mib && observed_mib <= bounds.max_memory_mib
}

spec fn rebase_is_distinct_observation(bounds: MemoryBounds, state: MemoryState, observed_mib: Option<u32>) -> bool {
    match observed_mib {
        Some(observed) => observed_in_bounds(bounds, observed)
            && (observed as int) != norm_target(bounds, state.current_target_mib),
        None => false,
    }
}

spec fn rebase_is_equal_observation(bounds: MemoryBounds, state: MemoryState, observed_mib: Option<u32>) -> bool {
    match observed_mib {
        Some(observed) => observed_in_bounds(bounds, observed)
            && (observed as int) == norm_target(bounds, state.current_target_mib),
        None => false,
    }
}

spec fn rebase_observed_mib(observed_mib: Option<u32>) -> int {
    match observed_mib {
        Some(observed) => observed as int,
        None => 0,
    }
}

spec fn memory_rebase_target_spec(bounds: MemoryBounds, state: MemoryState, recovering: bool, observed_mib: Option<u32>) -> int {
    if bounds_reversed(bounds) {
        bounds.boot_memory_mib as int
    } else if !recovering {
        norm_target(bounds, state.current_target_mib)
    } else if rebase_is_distinct_observation(bounds, state, observed_mib) {
        rebase_observed_mib(observed_mib)
    } else {
        norm_target(bounds, state.current_target_mib)
    }
}

spec fn memory_rebase_low_spec(bounds: MemoryBounds, state: MemoryState, recovering: bool, observed_mib: Option<u32>) -> int {
    if bounds_reversed(bounds) {
        0
    } else if !recovering {
        norm_low(state.low_ticks)
    } else if rebase_is_equal_observation(bounds, state, observed_mib) {
        norm_low(state.low_ticks)
    } else {
        0
    }
}

/// Selects the decision baseline for the next [`memory_tick`] and says whether the low
/// run survives.
///
/// Confirmed operation keeps the accepted target: replacing it with actual RAM would
/// lose the urgent reversal of an unconverged shrink. Recovering operation has no
/// accepted target left, so a valid observation supplies the baseline — and any change
/// of baseline restarts the dwell, because 49 ticks measured against another commitment
/// are not 49 ticks of this one.
fn memory_rebase(bounds: MemoryBounds, state: MemoryState, recovering: bool, observed_mib: Option<u32>) -> (rebased: MemoryState)
    ensures
        rebased.current_target_mib as int == memory_rebase_target_spec(bounds, state, recovering, observed_mib),
        rebased.low_ticks as int == memory_rebase_low_spec(bounds, state, recovering, observed_mib),
        bounds.boot_memory_mib <= bounds.max_memory_mib ==> {
            &&& (bounds.boot_memory_mib as int) <= (rebased.current_target_mib as int)
            &&& (rebased.current_target_mib as int) <= (bounds.max_memory_mib as int)
        },
        rebased.low_ticks <= MEMORY_LOW_TICKS,
        !recovering ==> {
            &&& rebased.current_target_mib as int == tick_base_target(bounds, state)
            &&& rebased.low_ticks as int == tick_base_low(bounds, state)
        },
        (recovering && rebase_is_distinct_observation(bounds, state, observed_mib)) ==> {
            &&& rebased.current_target_mib as int == rebase_observed_mib(observed_mib)
            &&& rebased.low_ticks == 0
        },
        (recovering && rebase_is_equal_observation(bounds, state, observed_mib)) ==> {
            &&& rebased.current_target_mib as int == tick_base_target(bounds, state)
            &&& rebased.low_ticks as int == tick_base_low(bounds, state)
        },
        (recovering && !rebase_is_distinct_observation(bounds, state, observed_mib)
            && !rebase_is_equal_observation(bounds, state, observed_mib)) ==> {
            &&& rebased.current_target_mib as int == tick_base_target(bounds, state)
            &&& rebased.low_ticks == 0
        },
        bounds_reversed(bounds) ==> {
            &&& rebased.current_target_mib == bounds.boot_memory_mib
            &&& rebased.low_ticks == 0
        },
{
    let boot = bounds.boot_memory_mib;
    let max = bounds.max_memory_mib;
    if boot > max {
        return MemoryState { current_target_mib: boot, low_ticks: 0 };
    }
    let base = if state.current_target_mib < boot {
        boot
    } else if state.current_target_mib > max {
        max
    } else {
        state.current_target_mib
    };
    let low = if state.low_ticks > MEMORY_LOW_TICKS { MEMORY_LOW_TICKS } else { state.low_ticks };
    if !recovering {
        return MemoryState { current_target_mib: base, low_ticks: low };
    }
    let Some(observed) = observed_mib else {
        return MemoryState { current_target_mib: base, low_ticks: 0 };
    };
    if observed < boot || observed > max {
        return MemoryState { current_target_mib: base, low_ticks: 0 };
    }
    if observed == base {
        MemoryState { current_target_mib: base, low_ticks: low }
    } else {
        MemoryState { current_target_mib: observed, low_ticks: 0 }
    }
}

spec fn seed_first_mib(boot_memory_mib: u32) -> int {
    ((boot_memory_mib as int + MEMORY_STEP_MIB as int - 1) / (MEMORY_STEP_MIB as int)) * (MEMORY_STEP_MIB as int)
}

spec fn seed_candidate_mib(boot_memory_mib: u32, index: int) -> int {
    seed_first_mib(boot_memory_mib) + index * (MEMORY_STEP_MIB as int)
}

spec fn seed_candidate_eligible(bounds: MemoryBounds, baseline_mib: u32, desired_mib: u32, index: int) -> bool {
    &&& (bounds.boot_memory_mib as int) <= seed_candidate_mib(bounds.boot_memory_mib, index)
    &&& seed_candidate_mib(bounds.boot_memory_mib, index) <= (bounds.max_memory_mib as int)
    &&& seed_candidate_mib(bounds.boot_memory_mib, index) != (baseline_mib as int)
    &&& seed_candidate_mib(bounds.boot_memory_mib, index) != (desired_mib as int)
}

spec fn seed_any_eligible(bounds: MemoryBounds, baseline_mib: u32, desired_mib: u32) -> bool {
    seed_candidate_eligible(bounds, baseline_mib, desired_mib, 0)
        || seed_candidate_eligible(bounds, baseline_mib, desired_mib, 1)
        || seed_candidate_eligible(bounds, baseline_mib, desired_mib, 2)
}

spec fn seed_present(seed: Option<u32>) -> bool {
    match seed { Some(_) => true, None => false }
}

spec fn memory_recovery_seed_spec(bounds: MemoryBounds, baseline_mib: u32, desired_mib: u32) -> Option<int> {
    if bounds_reversed(bounds) {
        None
    } else if seed_candidate_eligible(bounds, baseline_mib, desired_mib, 0) {
        Some(seed_candidate_mib(bounds.boot_memory_mib, 0))
    } else if seed_candidate_eligible(bounds, baseline_mib, desired_mib, 1) {
        Some(seed_candidate_mib(bounds.boot_memory_mib, 1))
    } else if seed_candidate_eligible(bounds, baseline_mib, desired_mib, 2) {
        Some(seed_candidate_mib(bounds.boot_memory_mib, 2))
    } else {
        None
    }
}

/// The configuration-repair value a Recovering request saves before it live-applies.
///
/// The SDK classifies a live patch whose desired memory equals the saved desired memory
/// as an applied plan with no memory status, so a plain live apply can be a no-op after
/// a failed persistence left the saved value stale. Persisting a value that differs from
/// both the observed baseline and the desired target makes the following live apply a
/// real planned change, and `NextStart` does it without touching live RAM — a live bounce
/// through the seed could transiently shrink the guest below what it is using.
///
/// Three candidates suffice: with aligned, adjustable bounds at most two values are
/// excluded. It is a repair value, never a policy target or an accepted receipt.
fn memory_recovery_seed(bounds: MemoryBounds, baseline_mib: u32, desired_mib: u32) -> (seed: Option<u32>)
    ensures
        match seed {
            Some(chosen) => memory_recovery_seed_spec(bounds, baseline_mib, desired_mib) == Some::<int>(chosen as int),
            None => memory_recovery_seed_spec(bounds, baseline_mib, desired_mib) == None,
        },
        seed_present(seed) == seed_any_eligible(bounds, baseline_mib, desired_mib),
        match seed {
            Some(chosen) => {
                &&& (bounds.boot_memory_mib as int) <= (chosen as int)
                &&& (chosen as int) <= (bounds.max_memory_mib as int)
                &&& chosen as int % (MEMORY_STEP_MIB as int) == 0
                &&& chosen != baseline_mib
                &&& chosen != desired_mib
            },
            None => true,
        },
        (bounds.boot_memory_mib as int) % (MEMORY_STEP_MIB as int) == 0
            && (bounds.max_memory_mib as int) >= (bounds.boot_memory_mib as int) + 2 * (MEMORY_STEP_MIB as int)
            ==> seed_present(seed),
{
    let boot = bounds.boot_memory_mib;
    let max = bounds.max_memory_mib;
    if boot > max {
        return None;
    }
    let step = MEMORY_STEP_MIB;
    let boot64 = u64::from(boot);
    let remainder = boot64 % step;
    let delta = (step - remainder) % step;
    proof {
        assert((remainder as int) < (MEMORY_STEP_MIB as int));
        assert((delta as int) < (MEMORY_STEP_MIB as int));
    }
    let first = boot64 + delta;
    proof {
        assert(first as int == seed_first_mib(boot));
        assert((boot as int) <= (first as int));
        assert((first as int) <= (u32::MAX as u64 as int) + (MEMORY_STEP_MIB as int));
    }
    let second = first + step;
    proof {
        assert((second as int) == seed_candidate_mib(boot, 1));
    }
    let third = second + step;
    proof {
        assert((third as int) == seed_candidate_mib(boot, 2));
    }
    let baseline = u64::from(baseline_mib);
    let desired = u64::from(desired_mib);
    let ceiling = u64::from(max);
    let first_ok = first <= ceiling && first != baseline && first != desired;
    proof {
        assert(first_ok == seed_candidate_eligible(bounds, baseline_mib, desired_mib, 0));
    }
    if first_ok {
        return Some(first as u32);
    }
    let second_ok = second <= ceiling && second != baseline && second != desired;
    proof {
        assert(second_ok == seed_candidate_eligible(bounds, baseline_mib, desired_mib, 1));
    }
    if second_ok {
        return Some(second as u32);
    }
    let third_ok = third <= ceiling && third != baseline && third != desired;
    proof {
        assert(third_ok == seed_candidate_eligible(bounds, baseline_mib, desired_mib, 2));
        assert((boot as int) % (MEMORY_STEP_MIB as int) == 0
            && (max as int) >= (boot as int) + 2 * (MEMORY_STEP_MIB as int)
            ==> seed_any_eligible(bounds, baseline_mib, desired_mib)) by {
            if (boot as int) % (MEMORY_STEP_MIB as int) == 0 {
                assert(seed_first_mib(boot) == boot as int);
                assert(seed_candidate_mib(boot, 0) == boot as int);
                assert(seed_candidate_mib(boot, 1) == boot as int + 128);
                assert(seed_candidate_mib(boot, 2) == boot as int + 256);
            }
        };
    }
    if third_ok {
        return Some(third as u32);
    }
    None
}

} // verus!

/// How long a teardown hook waits for the monitor to finish after requesting the abort.
///
/// Deliberately far below every teardown step's own budget (5 s kill/reap/remove, 10 s
/// stop), so a slow join cannot consume the operation's deadline and leave the VM behind
/// (#258). An abort is normally prompt; when it is not, the task is already aborted and the
/// retained handle lets the next hook finish the join.
pub(crate) const MONITOR_JOIN_TIMEOUT: Duration = Duration::from_secs(2);

/// The first re-ask delay for a request that already failed, in monitor ticks (1 s).
///
/// Scale-up is immediate by design, so a *persistently* failing growth would otherwise be
/// re-asked every 200 ms — two SDK applies and a control connect each time. Only an
/// identical ask is damped; see [`MemoryRetry`].
const MEMORY_RETRY_FIRST_TICKS: u32 = 5;
/// The ceiling of that delay (10 s), so a transient failure still retries on its own.
const MEMORY_RETRY_MAX_TICKS: u32 = 50;

/// ADR-0070 D1: requests a 200 ms interval (nominal 5 Hz; the SDK default is 1 s).
/// The runtime sleeps this long between snapshots and reuses the previous CPU
/// reading for a skewed window, so it bounds neither the period nor freshness.
const METRICS_SAMPLE_INTERVAL: Duration = Duration::from_millis(200);

/// A launch's validated **resource ceiling** and the **boot commitment** derived
/// from it. Only [`ResourceCeiling::from_launch_options`] builds one, so a zero or
/// overflowing ceiling never reaches the sandbox builder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ResourceCeiling(Sizing);

impl ResourceCeiling {
    /// Trusted adapter over the proved `launch_sizing`: clap's integer parse is the
    /// measurement, and a refusal becomes fixed, value-free text.
    pub(crate) fn from_launch_options(memory_gib: u32, cpus: u8) -> anyhow::Result<Self> {
        launch_sizing(memory_gib, cpus)
            .map(Self)
            .map_err(|refusal| anyhow::anyhow!(refusal.message()))
    }

    /// Boot at the commitment with the ceiling reserved. `boot <= max` is proved,
    /// so neither `cpus()` nor `memory()` can silently raise the maximum.
    pub(crate) fn apply_to(&self, builder: SandboxBuilder) -> SandboxBuilder {
        let sizing = self.0;
        builder
            .cpus(sizing.boot_cpus)
            .max_cpus(sizing.max_cpus)
            .memory(sizing.boot_memory_mib)
            .max_memory(sizing.max_memory_mib)
            .metrics_sample_interval(METRICS_SAMPLE_INTERVAL)
    }

    /// `512..=8192 MiB, 1..=2 vCPU`; an axis whose boot equals its ceiling shows one number.
    pub(crate) fn notice_detail(&self) -> String {
        let sizing = self.0;
        format!(
            "{} MiB, {} vCPU",
            axis(sizing.boot_memory_mib, sizing.max_memory_mib),
            axis(sizing.boot_cpus, sizing.max_cpus),
        )
    }

    /// Whether any axis has room to move, so a session that cannot resize skips the task.
    fn monitor_needed(&self) -> bool {
        let sizing = self.0;
        sizing.max_memory_mib > sizing.boot_memory_mib || sizing.max_cpus > sizing.boot_cpus
    }

    fn memory_bounds(&self) -> MemoryBounds {
        let sizing = self.0;
        MemoryBounds {
            boot_memory_mib: sizing.boot_memory_mib,
            max_memory_mib: sizing.max_memory_mib,
        }
    }

    /// Start the in-process memory monitor and hand back the only handle that stops it.
    ///
    /// The CPU axis is deliberately ignored: this task reads memory only (#647 owns the
    /// CPU controller), so a CPU-only spare capacity still starts it and it simply never
    /// requests a resize.
    pub(crate) fn monitor(&self, sandbox: &microsandbox::Sandbox) -> ResourceMonitor {
        let span = tracing::debug_span!(
            target: "agent_vm::resources",
            "memory_commitment",
            sandbox = sandbox.name(),
        );
        if !self.monitor_needed() {
            return ResourceMonitor::idle(span);
        }
        if sandbox.backend().as_local().is_none() {
            span.in_scope(|| {
                tracing::debug!(
                    target: "agent_vm::resources",
                    event = "monitor_disabled",
                    reason = "the sandbox has no local backend, so its metrics cannot be read",
                    "memory monitor not started"
                )
            });
            return ResourceMonitor::idle(span);
        }
        let bounds = self.memory_bounds();
        let initial = MemoryControllerState {
            policy: MemoryState {
                current_target_mib: bounds.boot_memory_mib,
                low_ticks: 0,
            },
            authority: TargetAuthority::Confirmed,
            last_accepted_target_mib: bounds.boot_memory_mib,
            retry: MemoryRetry::default(),
        };
        let reader = sandbox.clone();
        let samples = memory_samples(move || {
            let sandbox = reader.clone();
            async move { read_memory_sample(&sandbox).await }
        });
        let modifier = sandbox.clone();
        let resize = move |request| {
            let sandbox = modifier.clone();
            async move { resize_memory(&sandbox, bounds, request).await }
        };
        let driving = drive_memory(bounds, initial, samples, resize);
        let task = tokio::spawn(
            async move {
                let _final_state = driving.await;
            }
            .instrument(span.clone()),
        );
        ResourceMonitor {
            task: tokio::sync::Mutex::new(Some(task)),
            span,
        }
    }
}

fn axis<T: PartialEq + std::fmt::Display>(boot: T, max: T) -> String {
    if boot == max {
        max.to_string()
    } else {
        format!("{boot}..={max}")
    }
}

impl CeilingRefusal {
    fn message(self) -> &'static str {
        match self {
            CeilingRefusal::ZeroMemory => "--memory must be at least 1 GiB",
            // Unchanged from the pre-#645 arithmetic, so existing tests read the same text.
            CeilingRefusal::MemoryOverflow => "--memory in GiB overflows u32 MiB",
            CeilingRefusal::ZeroCpus => "--cpus must be at least 1",
        }
    }
}

/// The log section every monitor event carries, so `RUST_LOG=agent_vm::resources=debug`
/// selects the controller and nothing else in the launcher.
const MONITOR_TARGET: &str = "agent_vm::resources";

/// Which value a policy decision compares against.
///
/// `resize_status.enforced` is the primary authority. A returned error or an unusable
/// receipt selects `Recovering` until a later receipt arrives, because neither the
/// pinned SDK error nor a rejected plan proves the VM was left unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TargetAuthority {
    Confirmed,
    Recovering,
}

/// What the driver knows between ticks.
///
/// `policy` is the accepted target under `Confirmed` and the latest observed live limit
/// under `Recovering`; `last_accepted_target_mib` is receipt history only and never
/// overwritten by an observation, so it cannot be mistaken for a current commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MemoryControllerState {
    policy: MemoryState,
    authority: TargetAuthority,
    last_accepted_target_mib: u32,
    retry: MemoryRetry,
}

/// Which way an ask moves the commitment, so a reversal is never queued behind a failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MemoryDirection {
    Up,
    Down,
}

/// The identity of one ask: what it was for, which way, and under which authority.
///
/// Identity is what the damping compares, and it deliberately contains no baseline: an
/// observation that drifts without changing what the guest needs must not reset the backoff,
/// or a noisy limit would re-open the per-tick storm the damping exists to prevent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MemoryAsk {
    target_mib: u32,
    direction: MemoryDirection,
    recovering: bool,
}

impl MemoryAsk {
    fn of(request: MemoryResizeRequest) -> Self {
        Self {
            target_mib: request.target_mib,
            direction: if request.target_mib >= request.baseline_mib {
                MemoryDirection::Up
            } else {
                MemoryDirection::Down
            },
            recovering: request.recovering,
        }
    }
}

/// Damping for an ask that is being repeated without effect.
///
/// Growth is immediate, so nothing else throttles a repeat: a persistent failure (host out of
/// memory, a runtime without live resize, a paused sandbox) or an `enforced` target below the
/// ask would be re-requested every 200 ms, at two SDK applies each. What is damped is the
/// **nth repeat of one identical ask** ([`MemoryAsk`]):
///
/// - the *first* repeat is always immediate, so one transient failure never slows recovery and
///   the plan's no-effect traces keep their next-tick retry;
/// - only a second and later consecutive no-progress result waits, linearly from
///   [`MEMORY_RETRY_FIRST_TICKS`] to [`MEMORY_RETRY_MAX_TICKS`], so the controller keeps
///   retrying by itself and cannot stall for good;
/// - a *different* ask — another target, the other direction, or a different authority — is
///   never delayed and does not inherit the count. That is what keeps immediate growth,
///   urgent reversal of an unconverged shrink, and recovery's same-tick repair intact, since
///   each of those changes the ask's identity.
///
/// It is shell bookkeeping, not a policy decision: it can only suppress a repeat of an ask
/// that already made no progress, never a change in what the guest needs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct MemoryRetry {
    /// The ask that last made no progress. Taken, not merely compared, on the next admit, so a
    /// changed ask cannot inherit this count.
    failed: Option<MemoryAsk>,
    /// How many consecutive attempts at `failed` have made no progress.
    attempts: u32,
    /// Ticks observed since the last attempt at `failed`.
    waited: u32,
}

impl MemoryRetry {
    /// The delay before re-asking the same ask.
    ///
    /// The **first** repeat is never delayed: one transient failure must not slow recovery,
    /// which is why the plan's no-effect traces retry on the very next observation. Only a
    /// second consecutive no-progress result starts the linear, capped backoff.
    fn delay(self) -> u32 {
        if self.attempts <= 1 {
            return 0;
        }
        (self.attempts - 1)
            .saturating_mul(MEMORY_RETRY_FIRST_TICKS)
            .min(MEMORY_RETRY_MAX_TICKS)
    }

    /// Whether this ask may go out now.
    ///
    /// A changed ask clears the record and is admitted, so it starts from zero rather than
    /// inheriting the previous ask's count.
    fn admit(&mut self, ask: MemoryAsk) -> bool {
        if self.failed != Some(ask) {
            *self = Self::default();
            return true;
        }
        if self.waited < self.delay() {
            return false;
        }
        // A fresh attempt at the same ask: the next wait is measured from here.
        self.waited = 0;
        true
    }

    /// The attempt made no progress: count it, so the next one waits longer.
    fn damp(&mut self, ask: MemoryAsk) {
        self.attempts = if self.failed == Some(ask) {
            self.attempts.saturating_add(1)
        } else {
            1
        };
        self.failed = Some(ask);
        self.waited = 0;
    }

    /// Progress: nothing left to damp.
    fn clear(&mut self) {
        *self = Self::default();
    }
}

/// One change the driver asks the SDK adapter for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MemoryResizeRequest {
    baseline_mib: u32,
    target_mib: u32,
    recovering: bool,
}

/// `Live` sends runtime control; `NextStart` only persists desired configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MemoryApplyMode {
    Live,
    NextStart,
}

/// A resize that did not produce an accepted target, split by what is known about the VM.
#[derive(Debug)]
enum MemoryResizeError {
    /// The apply call returned an error: the live effect is unknown, not absent.
    Modify(anyhow::Error),
    /// The call returned but its receipt was missing or unusable: also unknown.
    Unconfirmed(anyhow::Error),
}

impl MemoryResizeError {
    fn event(&self) -> &'static str {
        match self {
            MemoryResizeError::Modify(_) => "modify_error",
            MemoryResizeError::Unconfirmed(_) => "unconfirmed_resize_status",
        }
    }

    /// The whole anyhow chain, so the stage context and the underlying cause both appear.
    fn detail(&self) -> String {
        match self {
            MemoryResizeError::Modify(error) | MemoryResizeError::Unconfirmed(error) => {
                format!("{error:#}")
            }
        }
    }
}

/// ADR-0070 D2/D3: one sample stream through the policy, holding the authority that the
/// pure kernels cannot see.
///
/// Errors are handled here and never returned: a metrics gap, a failed apply or an
/// unusable receipt resets the low run, changes the authority and continues. Returning
/// the final state is what lets a finite test stream assert the exact outcome.
async fn drive_memory<S, R, F>(
    bounds: MemoryBounds,
    state: MemoryControllerState,
    samples: S,
    mut resize: R,
) -> MemoryControllerState
where
    S: futures::Stream<Item = anyhow::Result<Option<MemorySample>>>,
    R: FnMut(MemoryResizeRequest) -> F,
    F: std::future::Future<Output = Result<u32, MemoryResizeError>>,
{
    let mut state = state;
    let mut samples = std::pin::pin!(samples);
    while let Some(item) = futures::StreamExt::next(&mut samples).await {
        // Every item is one monitor tick, whatever it carries: the re-ask delay is measured
        // in opportunities to observe, not in wall-clock time. Only a recorded failure has a
        // delay to measure, so the counter stays at zero otherwise.
        if state.retry.failed.is_some() {
            state.retry.waited = state.retry.waited.saturating_add(1);
        }
        let sample = match item {
            Ok(Some(sample)) => sample,
            Ok(None) => {
                tracing::debug!(
                    target: MONITOR_TARGET,
                    event = "metrics_missing",
                    reason = "the metrics catalog has no live row for this sandbox yet",
                    "memory sample missing"
                );
                state.policy.low_ticks = 0;
                continue;
            }
            Err(error) => {
                tracing::debug!(
                    target: MONITOR_TARGET,
                    event = "metrics_error",
                    error = %format!("{error:#}"),
                    "memory metrics lookup failed"
                );
                state.policy.low_ticks = 0;
                continue;
            }
        };
        let recovering = state.authority == TargetAuthority::Recovering;
        let observed = if recovering {
            match observed_memory_target(bounds, sample.memory_limit_bytes) {
                Ok(observed) => Some(observed),
                Err(error) => {
                    tracing::debug!(
                        target: MONITOR_TARGET,
                        event = "invalid_recovery_limit",
                        error = %format!("{error:#}"),
                        last_accepted_target_mib = state.last_accepted_target_mib,
                        "recovery baseline unusable; holding"
                    );
                    state.policy = memory_rebase(bounds, state.policy, true, None);
                    continue;
                }
            }
        } else {
            None
        };
        let previous_mib = state.policy.current_target_mib;
        state.policy = memory_rebase(bounds, state.policy, recovering, observed);
        if let Some(observed_mib) = observed
            && observed_mib != previous_mib
        {
            tracing::debug!(
                target: MONITOR_TARGET,
                event = "memory_reconciled",
                observed_limit_mib = observed_mib,
                last_accepted_target_mib = state.last_accepted_target_mib,
                "recovery baseline moved to the observed live limit"
            );
        }
        let baseline_mib = state.policy.current_target_mib;
        let proposal = memory_tick(bounds, state.policy, sample);
        if proposal.current_target_mib == baseline_mib {
            state.policy.low_ticks = proposal.low_ticks;
            continue;
        }
        let target_mib = proposal.current_target_mib;
        let request = MemoryResizeRequest {
            baseline_mib,
            target_mib,
            recovering,
        };
        // The ask's identity, not just its number: a reversal or a change of authority is a
        // different ask and goes out at once.
        let ask = MemoryAsk::of(request);
        if !state.retry.admit(ask) {
            // The same ask, too soon after one that made no progress. Holding here changes
            // nothing else: a different ask is admitted on its own tick.
            state.policy.low_ticks = proposal.low_ticks;
            continue;
        }
        match resize(request).await {
            Ok(accepted) => {
                state.policy = MemoryState {
                    current_target_mib: accepted,
                    low_ticks: 0,
                };
                state.authority = TargetAuthority::Confirmed;
                state.last_accepted_target_mib = accepted;
                if accepted < target_mib {
                    // `enforced` is the authority even when it is below the ask, but a target
                    // the runtime reports as accepted and never reaches is not progress:
                    // re-asking it every tick would be the same storm as a hard failure.
                    state.retry.damp(ask);
                } else {
                    state.retry.clear();
                }
                tracing::debug!(
                    target: MONITOR_TARGET,
                    event = "memory_transition",
                    previous_target_mib = baseline_mib,
                    requested_target_mib = request.target_mib,
                    accepted_target_mib = accepted,
                    "memory commitment changed"
                );
            }
            Err(error) => {
                // An unknown outcome is not an acknowledgment, and it is not a hold: the
                // next valid sample supplies the baseline, so a partial effect still
                // recovers instead of starving behind a stale target.
                state.authority = TargetAuthority::Recovering;
                state.policy = MemoryState {
                    current_target_mib: baseline_mib,
                    low_ticks: 0,
                };
                state.retry.damp(ask);
                tracing::debug!(
                    target: MONITOR_TARGET,
                    event = error.event(),
                    error = %error.detail(),
                    requested_target_mib = request.target_mib,
                    last_accepted_target_mib = state.last_accepted_target_mib,
                    "memory resize did not report an accepted target"
                );
            }
        }
    }
    state
}

/// The production cadence: one read per 200 ms tick, first tick after one interval.
///
/// `MissedTickBehavior::Skip` is load-bearing. `Burst` would manufacture a rapid catch-up
/// after slow I/O, and 50 such ticks would look like 10 s of lower demand.
fn memory_samples<R, F>(
    read: R,
) -> impl futures::Stream<Item = anyhow::Result<Option<MemorySample>>> + Send
where
    R: FnMut() -> F + Send,
    F: std::future::Future<Output = anyhow::Result<Option<MemorySample>>> + Send,
{
    let mut ticker = tokio::time::interval_at(
        tokio::time::Instant::now() + METRICS_SAMPLE_INTERVAL,
        METRICS_SAMPLE_INTERVAL,
    );
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    futures::stream::unfold((ticker, read), |(mut ticker, mut read)| async move {
        ticker.tick().await;
        let item = read().await;
        Some((item, (ticker, read)))
    })
}

/// Trusted adapter: the one metrics route this controller uses.
///
/// `all_sandbox_metrics_local` runs its own catalog queries per call, which ADR-0070 D1
/// accepts as the cost of reading through the SDK instead of the registry. No fallback to
/// `memory_bytes`, host-resident bytes or another API: an absent row is an absent sample.
async fn read_memory_sample(
    sandbox: &microsandbox::Sandbox,
) -> anyhow::Result<Option<MemorySample>> {
    let Some(local) = sandbox.backend().as_local() else {
        anyhow::bail!("the sandbox has no local backend, so live metrics cannot be read");
    };
    let mut metrics = microsandbox::sandbox::all_sandbox_metrics_local(local).await?;
    Ok(metrics
        .remove(sandbox.name())
        .map(|metrics| memory_sample_of(&metrics)))
}

/// Copy the two fields the policy uses, and nothing that could stand in for them.
fn memory_sample_of(metrics: &microsandbox::sandbox::SandboxMetrics) -> MemorySample {
    MemorySample {
        memory_limit_bytes: metrics.memory_limit_bytes,
        memory_available_bytes: metrics.memory_available_bytes,
    }
}

/// Trusted decoder: an observed live limit in whole MiB inside the session's interval.
///
/// Recovery needs a baseline it can trust, so a fractional or out-of-range limit is
/// rejected rather than clamped; clamping would invent a commitment the VM never had.
fn observed_memory_target(bounds: MemoryBounds, limit_bytes: u64) -> anyhow::Result<u32> {
    if !limit_bytes.is_multiple_of(BYTES_PER_MIB) {
        anyhow::bail!("the observed limit of {limit_bytes} bytes is not a whole number of MiB");
    }
    let observed_mib = u32::try_from(limit_bytes / BYTES_PER_MIB).map_err(|_| {
        anyhow::anyhow!("the observed limit of {limit_bytes} bytes exceeds u32 MiB")
    })?;
    if !memory_target_in_bounds(bounds, observed_mib) {
        anyhow::bail!(
            "the observed limit {observed_mib} MiB is outside {}..={} MiB",
            bounds.boot_memory_mib,
            bounds.max_memory_mib
        );
    }
    Ok(observed_mib)
}

/// Trusted decoder for the SDK's enforced-target text, which is the only authority for an
/// accepted target. `requested` and `actual` are deliberately ignored: a downsize can be
/// reported `Applied` while the guest still holds more RAM than the target.
fn accepted_memory_target(
    plan: &microsandbox::sandbox::SandboxModificationPlan,
    bounds: MemoryBounds,
) -> anyhow::Result<u32> {
    if !plan.applied {
        anyhow::bail!("the modification plan was not applied");
    }
    let mut statuses = plan
        .resize_status
        .iter()
        .filter(|status| status.resource == microsandbox::sandbox::ResourceKind::Memory);
    let status = statuses
        .next()
        .ok_or_else(|| anyhow::anyhow!("the plan reported no memory resize status"))?;
    if statuses.next().is_some() {
        anyhow::bail!("the plan reported more than one memory resize status");
    }
    match status.state {
        microsandbox::sandbox::ResourceConvergenceState::Accepted
        | microsandbox::sandbox::ResourceConvergenceState::Converging
        | microsandbox::sandbox::ResourceConvergenceState::Applied => {}
        microsandbox::sandbox::ResourceConvergenceState::GuestRefused => {
            anyhow::bail!("the guest refused the memory resize")
        }
        microsandbox::sandbox::ResourceConvergenceState::Failed => {
            anyhow::bail!("the memory resize failed")
        }
    }
    let accepted_mib = status_text_mib(&status.enforced)?;
    if !memory_target_in_bounds(bounds, accepted_mib) {
        anyhow::bail!(
            "the enforced target {accepted_mib} MiB is outside {}..={} MiB",
            bounds.boot_memory_mib,
            bounds.max_memory_mib
        );
    }
    Ok(accepted_mib)
}

/// `"N MiB"` or `"N GiB"`, the two spellings the runtime's own formatter emits.
fn status_text_mib(text: &str) -> anyhow::Result<u32> {
    let unsupported =
        || anyhow::anyhow!("the enforced target {text:?} is not an \"N MiB\" or \"N GiB\" value");
    let (value, unit) = text.split_once(' ').ok_or_else(unsupported)?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(unsupported());
    }
    let value: u32 = value.parse().map_err(|_| unsupported())?;
    match unit {
        "MiB" => Ok(value),
        "GiB" => value
            .checked_mul(1024)
            .ok_or_else(|| anyhow::anyhow!("the enforced target {text:?} overflows MiB")),
        _ => Err(unsupported()),
    }
}

/// ADR-0070 D2 with the unknown-outcome amendment: one request through the SDK.
async fn resize_memory(
    sandbox: &microsandbox::Sandbox,
    bounds: MemoryBounds,
    request: MemoryResizeRequest,
) -> Result<u32, MemoryResizeError> {
    resize_memory_with(bounds, request, |mode, target_mib| {
        let sandbox = sandbox.clone();
        async move {
            let builder = sandbox.modify().memory(target_mib);
            let builder = match mode {
                MemoryApplyMode::Live => builder,
                MemoryApplyMode::NextStart => builder.next_start(),
            };
            builder.apply().await.map_err(anyhow::Error::new)
        }
    })
    .await
}

/// The apply seam: a recovering request repairs saved configuration before it moves RAM.
///
/// A live patch whose desired memory equals the persisted desired memory is classified as
/// an applied plan with no memory status, so repeating it after a failed persistence can
/// be a statusless no-op forever. Persisting a distinct `NextStart` seed first makes the
/// following live apply a real planned change. `NextStart` sends no runtime control, so the
/// seed never shrinks usable RAM the way a live bounce could.
async fn resize_memory_with<A, F>(
    bounds: MemoryBounds,
    request: MemoryResizeRequest,
    mut apply: A,
) -> Result<u32, MemoryResizeError>
where
    A: FnMut(MemoryApplyMode, u32) -> F,
    F: std::future::Future<Output = anyhow::Result<microsandbox::sandbox::SandboxModificationPlan>>,
{
    if request.recovering {
        let Some(seed_mib) = memory_recovery_seed(bounds, request.baseline_mib, request.target_mib)
        else {
            return Err(MemoryResizeError::Unconfirmed(anyhow::anyhow!(
                "recovery_prepare: no configuration seed in {}..={} MiB differs from both {} and {}",
                bounds.boot_memory_mib,
                bounds.max_memory_mib,
                request.baseline_mib,
                request.target_mib
            )));
        };
        // An error or a rejected plan may already have persisted the seed: the caller must
        // stay Recovering rather than assume the saved configuration is unchanged.
        let prepared = apply(MemoryApplyMode::NextStart, seed_mib)
            .await
            .map_err(|error| {
                MemoryResizeError::Modify(
                    error.context(format!("recovery_prepare: saving a {seed_mib} MiB seed")),
                )
            })?;
        if !prepared.applied {
            return Err(MemoryResizeError::Unconfirmed(anyhow::anyhow!(
                "recovery_prepare: saving a {seed_mib} MiB seed was not applied"
            )));
        }
        if !prepared.resize_status.is_empty() {
            return Err(MemoryResizeError::Unconfirmed(anyhow::anyhow!(
                "recovery_prepare: saving a {seed_mib} MiB seed reported a live resize status"
            )));
        }
    }
    let plan = apply(MemoryApplyMode::Live, request.target_mib)
        .await
        .map_err(|error| {
            MemoryResizeError::Modify(
                error.context(format!("live_apply: requesting {} MiB", request.target_mib)),
            )
        })?;
    accepted_memory_target(&plan, bounds).map_err(|error| {
        MemoryResizeError::Unconfirmed(error.context(format!(
            "live_apply: decoding the status for {} MiB",
            request.target_mib
        )))
    })
}

/// The launcher's only handle on the monitor task.
///
/// Owned by [`crate::session_control::LaunchTeardown`] rather than a bare `JoinHandle`, so
/// every teardown exit — ordinary, forced, failed or an early return — cancels and joins the
/// task before it can issue another resize. Stopping proves local cessation only: it cannot
/// undo a request already delivered, and request expiry is not remote cancellation.
pub(crate) struct ResourceMonitor {
    task: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    span: tracing::Span,
}

impl ResourceMonitor {
    fn idle(span: tracing::Span) -> Self {
        Self {
            task: tokio::sync::Mutex::new(None),
            span,
        }
    }

    /// Demand the task finished, and be idempotent about it.
    ///
    /// The handle stays in the slot until the join completes. Taking it first would let a
    /// teardown timeout that cancels this future detach the task with no later hook able to
    /// join it; this way a second `stop` finishes the same aborted join.
    pub(crate) async fn stop(&self) {
        let mut slot = self.task.lock().await;
        let Some(handle) = slot.as_mut() else {
            return;
        };
        handle.abort();
        let joined =
            std::future::poll_fn(|context| std::pin::Pin::new(&mut *handle).poll(context)).await;
        if let Err(error) = joined
            && !error.is_cancelled()
        {
            self.span.in_scope(|| {
                tracing::debug!(
                    target: MONITOR_TARGET,
                    event = "monitor_join_error",
                    error = %format!("{error:#}"),
                    "the memory monitor task did not finish cleanly"
                )
            });
        }
        *slot = None;
    }

    #[cfg(test)]
    pub(crate) fn from_task_for_tests(task: tokio::task::JoinHandle<()>) -> Self {
        Self {
            task: tokio::sync::Mutex::new(Some(task)),
            span: tracing::Span::none(),
        }
    }

    /// Test-only: whether a handle is still retained, which is what a cancelled `stop`
    /// must leave behind.
    #[cfg(test)]
    pub(crate) async fn retains_task(&self) -> bool {
        self.task.lock().await.is_some()
    }
}

impl Drop for ResourceMonitor {
    /// The fallback for an early return that never reached a teardown: it aborts, but it
    /// cannot await, so this is not evidence that the task has finished.
    fn drop(&mut self) {
        if let Some(handle) = self.task.get_mut().as_mut() {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Run `strategy` for exactly `CASES` cases, independent of the environment.
    ///
    /// `proptest!` reapplies `PROPTEST_CASES` after the config is written
    /// (`sugar.rs:160`), so pinning inside the macro is not enough; `TestRunner::new`
    /// takes the config as given.
    fn for_each_case<S: Strategy>(
        strategy: S,
        property: impl Fn(S::Value) -> Result<(), TestCaseError>,
    ) {
        const CASES: u32 = 256;
        let config = proptest::test_runner::Config {
            cases: CASES,
            ..Default::default()
        };
        proptest::test_runner::TestRunner::new(config)
            .run(&strategy, property)
            .expect("property holds for all cases");
    }

    const MIB: u64 = 1024 * 1024;

    fn bounds(boot_memory_mib: u32, max_memory_mib: u32) -> MemoryBounds {
        MemoryBounds {
            boot_memory_mib,
            max_memory_mib,
        }
    }

    /// `512..=8192 MiB`: the shape every adjustable production launch has.
    fn adjustable() -> MemoryBounds {
        bounds(512, 8192)
    }

    fn memory_state(current_target_mib: u32, low_ticks: u32) -> MemoryState {
        MemoryState {
            current_target_mib,
            low_ticks,
        }
    }

    /// A limit and the use inside it, both in whole MiB.
    fn sample(limit_mib: u64, used_mib: u64) -> MemorySample {
        assert!(used_mib <= limit_mib, "used {used_mib} exceeds {limit_mib}");
        MemorySample {
            memory_limit_bytes: limit_mib * MIB,
            memory_available_bytes: Some((limit_mib - used_mib) * MIB),
        }
    }

    /// Independently written in widened integer arithmetic, never the production formula.
    fn desired_oracle(boot_memory_mib: u32, max_memory_mib: u32, used_bytes: u64) -> u64 {
        let mib = MIB as u128;
        let used_mib = u128::from(used_bytes).div_ceil(mib);
        let headroom_mib = std::cmp::max(256, used_mib / 4);
        let raw_mib = used_mib + headroom_mib;
        let rounded_mib = raw_mib.div_ceil(128) * 128;
        let clamped = rounded_mib
            .max(u128::from(boot_memory_mib))
            .min(u128::from(max_memory_mib));
        u64::try_from(clamped).expect("the clamp keeps the value in range")
    }

    fn memory_resize_status(
        state: microsandbox::sandbox::ResourceConvergenceState,
        requested: &str,
        actual: &str,
        enforced: &str,
    ) -> microsandbox::sandbox::ResourceResizeStatus {
        microsandbox::sandbox::ResourceResizeStatus {
            resource: microsandbox::sandbox::ResourceKind::Memory,
            requested: requested.to_string(),
            actual: actual.to_string(),
            enforced: enforced.to_string(),
            state,
        }
    }

    fn cpu_resize_status() -> microsandbox::sandbox::ResourceResizeStatus {
        microsandbox::sandbox::ResourceResizeStatus {
            resource: microsandbox::sandbox::ResourceKind::Cpus,
            requested: "2".to_string(),
            actual: "1".to_string(),
            enforced: "2".to_string(),
            state: microsandbox::sandbox::ResourceConvergenceState::Accepted,
        }
    }

    /// A real SDK plan value: the decoder is tested against the type it decodes, not a
    /// test-local copy of it.
    fn modification_plan(
        applied: bool,
        resize_status: Vec<microsandbox::sandbox::ResourceResizeStatus>,
    ) -> microsandbox::sandbox::SandboxModificationPlan {
        microsandbox::sandbox::SandboxModificationPlan {
            sandbox: "resources-test".to_string(),
            status: "running".to_string(),
            applied,
            policy: microsandbox::sandbox::ModificationPolicy::NoRestart,
            changes: Vec::new(),
            conflicts: Vec::new(),
            warnings: Vec::new(),
            resize_status,
        }
    }

    fn refusal(memory_gib: u32, cpus: u8) -> CeilingRefusal {
        launch_sizing(memory_gib, cpus).expect_err("a refused ceiling")
    }

    fn sizing(memory_gib: u32, cpus: u8) -> Sizing {
        launch_sizing(memory_gib, cpus).expect("an accepted ceiling")
    }

    #[test]
    fn memory_ceiling_is_exact_or_refused_at_the_u32_boundary() {
        assert_eq!(refusal(0, 2), CeilingRefusal::ZeroMemory);
        assert_eq!(memory_ceiling_mib(1), Ok(1024));
        assert_eq!(memory_ceiling_mib(8), Ok(8192));
        assert_eq!(memory_ceiling_mib(4_194_303), Ok(4_294_966_272));
        assert_eq!(
            memory_ceiling_mib(4_194_304),
            Err(CeilingRefusal::MemoryOverflow)
        );
        assert_eq!(
            memory_ceiling_mib(u32::MAX),
            Err(CeilingRefusal::MemoryOverflow)
        );
    }

    #[test]
    fn boot_cpus_is_min_of_one_and_the_ceiling_for_every_u8() {
        for n in 0..=u8::MAX {
            assert_eq!(boot_cpus(n), n.min(BOOT_CPUS), "max_cpus {n}");
        }
    }

    #[test]
    fn boot_memory_is_min_of_512_and_the_ceiling() {
        for max in [0, 1, 511, 512, 513, 1024, 8192, u32::MAX] {
            assert_eq!(boot_memory_mib(max), max.min(BOOT_MEMORY_MIB), "max {max}");
        }
    }

    #[test]
    fn accepted_boundaries_size_exactly() {
        let mut accepted = 0;
        for gib in [1u32, 2, 8, 4_194_302, 4_194_303] {
            for cpus in [1u8, 2, 3, 4, u8::MAX] {
                let s = sizing(gib, cpus);
                assert_eq!(s.max_cpus, cpus, "{gib} GiB x {cpus} vCPU");
                assert_eq!(s.max_memory_mib as u64, u64::from(gib) * 1024);
                assert_eq!((s.boot_cpus, s.boot_memory_mib), (1, 512));
                accepted += 1;
            }
        }
        assert_eq!(accepted, 25);
    }

    #[test]
    fn accepted_inputs_size_exactly() {
        for_each_case((1u32..=4_194_303, 1u8..=u8::MAX), |(gib, cpus)| {
            let s = sizing(gib, cpus);
            prop_assert_eq!(s.max_cpus, cpus);
            prop_assert_eq!(s.max_memory_mib as u64, u64::from(gib) * 1024);
            prop_assert_eq!((s.boot_cpus, s.boot_memory_mib), (1, 512));
            Ok(())
        });
    }

    #[test]
    fn overflowing_memory_is_refused_whatever_the_cpus() {
        for_each_case((4_194_304u32..=u32::MAX, any::<u8>()), |(gib, cpus)| {
            prop_assert_eq!(refusal(gib, cpus), CeilingRefusal::MemoryOverflow);
            Ok(())
        });
    }

    #[test]
    fn refusal_precedence_rows() {
        assert_eq!(refusal(0, 0), CeilingRefusal::ZeroMemory);
        assert_eq!(refusal(0, u8::MAX), CeilingRefusal::ZeroMemory);
        assert_eq!(refusal(4_194_304, 0), CeilingRefusal::MemoryOverflow);
        assert_eq!(refusal(u32::MAX, 0), CeilingRefusal::MemoryOverflow);
        assert_eq!(refusal(1, 0), CeilingRefusal::ZeroCpus);
        assert_eq!(refusal(4_194_303, 0), CeilingRefusal::ZeroCpus);
    }

    #[test]
    fn zero_cpus_is_refused_for_every_representable_memory() {
        for_each_case((1u32..=4_194_303, Just(0u8)), |(gib, cpus)| {
            prop_assert_eq!(refusal(gib, cpus), CeilingRefusal::ZeroCpus);
            Ok(())
        });
    }

    #[test]
    fn zero_memory_wins_whatever_the_cpus() {
        for cpus in 0..=u8::MAX {
            assert_eq!(refusal(0, cpus), CeilingRefusal::ZeroMemory, "cpus {cpus}");
        }
    }

    #[test]
    fn refusal_text_is_fixed_and_names_the_flag() {
        let message = |gib, cpus| {
            ResourceCeiling::from_launch_options(gib, cpus)
                .expect_err("a refused ceiling")
                .to_string()
        };
        assert_eq!(message(0, 2), "--memory must be at least 1 GiB");
        assert_eq!(message(4_194_304, 2), "--memory in GiB overflows u32 MiB");
        assert_eq!(message(8, 0), "--cpus must be at least 1");
    }

    #[test]
    fn notice_detail_collapses_only_an_equal_axis() {
        let detail = |gib, cpus| {
            ResourceCeiling::from_launch_options(gib, cpus)
                .unwrap()
                .notice_detail()
        };
        assert_eq!(detail(8, 2), "512..=8192 MiB, 1..=2 vCPU");
        assert_eq!(detail(4, 1), "512..=4096 MiB, 1 vCPU");
        assert_eq!(detail(16, 4), "512..=16384 MiB, 1..=4 vCPU");
        assert_eq!(axis(3, 3), "3");
        assert_eq!(axis(1, 4), "1..=4");
    }

    #[tokio::test]
    async fn apply_to_boots_at_the_commitment_with_the_ceiling_reserved() {
        for (gib, cpus) in [(8, 2), (4, 1), (16, 4)] {
            let config = ResourceCeiling::from_launch_options(gib, cpus)
                .unwrap()
                .apply_to(
                    microsandbox::sandbox::Sandbox::builder("resources-test")
                        .image("example.invalid/resources-test:latest"),
                )
                .build()
                .await
                .expect("sandbox config");
            let value = serde_json::to_value(&config).expect("config serializes");
            assert_eq!(
                value["resources"],
                serde_json::json!({
                    "cpus": 1,
                    "memory_mib": 512,
                    "max_cpus": cpus,
                    "max_memory_mib": gib * 1024,
                }),
                "{gib} GiB x {cpus} vCPU"
            );
            assert_eq!(
                value["runtime"]["metrics_sample_interval_ms"],
                serde_json::json!(200),
                "{gib} GiB x {cpus} vCPU"
            );
        }
    }

    // ------------------------------------------------ ADR-0070 D3 pure decisions

    #[test]
    fn idle_memory_stays_at_512_through_256_mib_used() {
        for used_mib in 0..=256u64 {
            assert_eq!(
                memory_desired_mib(adjustable(), used_mib * MIB),
                512,
                "used {used_mib} MiB"
            );
        }
        let mut current = memory_state(512, 0);
        for tick in 0..100 {
            let next = memory_tick(adjustable(), current, sample(512, 128));
            assert_eq!(next, memory_state(512, 0), "tick {tick}");
            current = next;
        }
    }

    #[test]
    fn partial_mib_use_rounds_up_before_headroom() {
        assert_eq!(memory_desired_mib(adjustable(), 256 * MIB), 512);
        assert_eq!(memory_desired_mib(adjustable(), 256 * MIB + 1), 640);
        assert_eq!(memory_desired_mib(adjustable(), 0), 512);
        assert_eq!(memory_desired_mib(adjustable(), 1), 512);
        // The MiB boundary itself cannot move the floor: two whole MiB of use and the
        // minimum headroom still quantize below the boot commitment.
        assert_eq!(memory_desired_mib(adjustable(), MIB - 1), 512);
        assert_eq!(memory_desired_mib(adjustable(), MIB), 512);
        assert_eq!(memory_desired_mib(adjustable(), MIB + 1), 512);
    }

    #[test]
    fn memory_targets_quantize_before_clamping() {
        assert_eq!(memory_desired_mib(adjustable(), 400 * MIB), 768);
        assert_eq!(memory_desired_mib(adjustable(), 1024 * MIB), 1280);
        assert_eq!(memory_desired_mib(adjustable(), 2048 * MIB), 2560);
        // Clamp after quantizing, so an unaligned endpoint survives as itself.
        assert_eq!(memory_desired_mib(bounds(600, 8192), 64 * MIB), 600);
        assert_eq!(memory_desired_mib(bounds(512, 1000), 2048 * MIB), 1000);
    }

    #[test]
    fn memory_target_matches_independent_u128_oracle() {
        for_each_case(
            (any::<u64>(), any::<u32>(), any::<u32>()),
            |(used, a, b)| {
                let (boot, max) = (a.min(b), a.max(b));
                let target = memory_desired_mib(bounds(boot, max), used);
                prop_assert_eq!(u64::from(target), desired_oracle(boot, max, used));
                prop_assert!(boot <= target && target <= max);
                Ok(())
            },
        );
        // A deterministic sweep over every whole MiB with a sub-MiB remainder, because a
        // truncating used-MiB differs from the oracle's ceiling only at those offsets.
        for whole in 0u64..=2048 {
            for offset in [0, 1, MIB / 2, MIB - 1] {
                let used = whole * MIB + offset;
                assert_eq!(
                    u64::from(memory_desired_mib(adjustable(), used)),
                    desired_oracle(512, 8192, used),
                    "used {used} bytes"
                );
            }
        }
        for (used, expected) in [(0, 512u64), (u64::MAX, 8192), (u32::MAX as u64 * MIB, 8192)] {
            assert_eq!(
                u64::from(memory_desired_mib(adjustable(), used)),
                expected,
                "used {used}"
            );
        }
        // Equal endpoints collapse the interval; reversed ones return the floor.
        for used in [0, 1, 400 * MIB, u64::MAX] {
            assert_eq!(memory_desired_mib(bounds(512, 512), used), 512);
            assert_eq!(memory_desired_mib(bounds(1024, 512), used), 1024);
        }
        // Alignment holds only where the interval allows it.
        assert_eq!(memory_desired_mib(adjustable(), 400 * MIB) % 128, 0);
        assert_ne!(
            memory_desired_mib(bounds(512, 1000), 2048 * MIB) % 128,
            0,
            "a clamped ceiling need not be aligned"
        );
    }

    #[test]
    fn memory_rebase_matches_authority_and_baseline_contract() {
        let standard = adjustable();
        // Confirmed: the accepted baseline is kept, whatever the observation says.
        for observed in [Some(896), None] {
            assert_eq!(
                memory_rebase(standard, memory_state(1024, 49), false, observed),
                memory_state(1024, 49),
                "confirmed with {observed:?}"
            );
        }
        // Recovering with a changed observation: the observation becomes the baseline
        // and the low run starts over, so the following tick counts 1, not 50.
        let changed = memory_rebase(standard, memory_state(1024, 49), true, Some(896));
        assert_eq!(changed, memory_state(896, 0));
        assert_eq!(
            memory_tick(standard, changed, sample(896, 128)),
            memory_state(896, 1)
        );
        // Recovering with the same observation: the low run survives untouched.
        let stable = memory_rebase(standard, memory_state(1024, 49), true, Some(1024));
        assert_eq!(stable, memory_state(1024, 49));
        assert_eq!(
            memory_tick(standard, stable, sample(1024, 128)),
            memory_state(512, 0)
        );
        // Recovering with no usable observation: baseline kept, run discarded.
        for unusable in [None, Some(511), Some(8193)] {
            assert_eq!(
                memory_rebase(standard, memory_state(1024, 49), true, unusable),
                memory_state(1024, 0),
                "recovering with {unusable:?}"
            );
        }
        // Equal demand or no availability resets the run through the ordinary tick.
        assert_eq!(
            memory_tick(standard, memory_state(1024, 49), sample(1024, 700)),
            memory_state(1024, 0)
        );
        let quiet = MemorySample {
            memory_limit_bytes: 1024 * MIB,
            memory_available_bytes: None,
        };
        assert_eq!(
            memory_tick(standard, memory_state(1024, 49), quiet),
            memory_state(1024, 0)
        );
        // Extreme and reversed inputs, with independent branch expectations.
        assert_eq!(
            memory_rebase(standard, memory_state(u32::MAX, u32::MAX), false, None),
            memory_state(8192, 50)
        );
        assert_eq!(
            memory_rebase(standard, memory_state(0, 0), false, Some(4096)),
            memory_state(512, 0)
        );
        assert_eq!(
            memory_rebase(bounds(1024, 512), memory_state(768, 7), true, Some(768)),
            memory_state(1024, 0)
        );
    }

    #[test]
    fn memory_growth_scales_on_the_first_tick() {
        for prior_low in [0u32, 1, 49, 50] {
            assert_eq!(
                memory_tick(adjustable(), memory_state(512, prior_low), sample(512, 400)),
                memory_state(768, 0),
                "prior low run {prior_low}"
            );
        }
    }

    #[test]
    fn memory_scale_down_requires_50_consecutive_low_ticks() {
        let mut current = memory_state(1024, 0);
        for tick in 1..50 {
            current = memory_tick(adjustable(), current, sample(1024, 128));
            assert_eq!(current, memory_state(1024, tick), "tick {tick}");
        }
        assert_eq!(
            memory_tick(adjustable(), current, sample(1024, 128)),
            memory_state(512, 0),
            "the 50th consecutive low tick reclaims"
        );
    }

    #[test]
    fn memory_scale_down_waits_for_convergence_after_50_ticks() {
        let mut current = memory_state(1024, 0);
        for tick in 1..=75u32 {
            current = memory_tick(adjustable(), current, sample(1536, 128));
            assert_eq!(
                current,
                memory_state(1024, tick.min(50)),
                "a limit above the target never converges, tick {tick}"
            );
        }
        // A fractional-byte limit is not convergence either.
        let fractional = MemorySample {
            memory_limit_bytes: 1024 * MIB + 1,
            memory_available_bytes: Some((1024 - 128) * MIB),
        };
        assert_eq!(
            memory_tick(adjustable(), current, fractional),
            memory_state(1024, 50)
        );
        assert_eq!(
            memory_tick(adjustable(), current, sample(1024, 128)),
            memory_state(512, 0),
            "the first converged tick adopts once the run is complete"
        );
    }

    #[test]
    fn equal_or_missing_availability_resets_low_ticks() {
        let mut current = memory_state(1024, 0);
        for _ in 0..49 {
            current = memory_tick(adjustable(), current, sample(1024, 128));
        }
        assert_eq!(current, memory_state(1024, 49));
        // Equal demand resets: the next 49 lows do not reclaim, the 50th does.
        current = memory_tick(adjustable(), current, sample(1024, 700));
        assert_eq!(current, memory_state(1024, 0));
        for _ in 0..49 {
            current = memory_tick(adjustable(), current, sample(1024, 128));
        }
        assert_eq!(current, memory_state(1024, 49));
        // Missing availability resets the same way.
        let quiet = MemorySample {
            memory_limit_bytes: 1024 * MIB,
            memory_available_bytes: None,
        };
        current = memory_tick(adjustable(), current, quiet);
        assert_eq!(current, memory_state(1024, 0));
        for _ in 0..49 {
            current = memory_tick(adjustable(), current, sample(1024, 128));
        }
        assert_eq!(current, memory_state(1024, 49));
        assert_eq!(
            memory_tick(adjustable(), current, sample(1024, 128)),
            memory_state(512, 0)
        );
    }

    #[test]
    fn availability_above_limit_holds_and_resets() {
        for available in [512 * MIB + 1, u64::MAX] {
            let odd = MemorySample {
                memory_limit_bytes: 512 * MIB,
                memory_available_bytes: Some(available),
            };
            assert_eq!(
                memory_tick(adjustable(), memory_state(1024, 49), odd),
                memory_state(1024, 0),
                "availability {available}"
            );
        }
    }

    #[test]
    fn urgent_growth_supersedes_unconverged_memory_shrink() {
        // A confirmed downsize to 512 while the guest still holds 1024: growth is
        // immediate because the decision baseline is the accepted target, not actual RAM.
        let accepting = memory_state(1024, 49);
        assert_eq!(
            memory_tick(adjustable(), accepting, sample(1024, 800)),
            memory_state(1152, 0)
        );
        // And after the shrink is accepted, a high sample from the old limit still grows.
        assert_eq!(
            memory_tick(adjustable(), memory_state(512, 0), sample(1024, 800)),
            memory_state(1152, 0)
        );
    }

    #[test]
    fn changing_low_desired_values_keep_the_low_run() {
        let mut current = memory_state(1024, 0);
        for tick in 1..50u32 {
            // Alternate between two lower desired values: 640 and 512.
            let used_mib = if tick % 2 == 0 { 400 } else { 128 };
            current = memory_tick(adjustable(), current, sample(1024, used_mib));
            assert_eq!(current, memory_state(1024, tick), "tick {tick}");
        }
        // The 50th adopts the value proposed on that tick (used 128 -> 512), not the first.
        assert_eq!(
            memory_tick(adjustable(), current, sample(1024, 128)),
            memory_state(512, 0)
        );
        let mut current = memory_state(1024, 0);
        for tick in 1..50u32 {
            let used_mib = if tick % 2 == 0 { 128 } else { 400 };
            current = memory_tick(adjustable(), current, sample(1024, used_mib));
        }
        assert_eq!(
            memory_tick(adjustable(), current, sample(1024, 400)),
            memory_state(768, 0)
        );
    }

    #[test]
    fn arbitrary_memory_tick_inputs_are_bounded_without_wrapping() {
        for_each_case(
            (
                any::<u64>(),
                any::<Option<u64>>(),
                any::<u32>(),
                any::<u32>(),
                any::<u32>(),
            ),
            |(limit, available, a, b, current)| {
                let (boot, max) = (a.min(b), a.max(b));
                let bounds = bounds(boot, max);
                let baseline = current.clamp(boot, max);
                for low in [0u32, 1, 49, 50, u32::MAX] {
                    let sample = MemorySample {
                        memory_limit_bytes: limit,
                        memory_available_bytes: available,
                    };
                    let next = memory_tick(bounds, memory_state(current, low), sample);
                    prop_assert!(next.low_ticks <= 50);
                    prop_assert!(boot <= next.current_target_mib && next.current_target_mib <= max);
                    match available {
                        Some(available) if available <= limit => {
                            let desired = desired_oracle(boot, max, limit - available) as u32;
                            if desired > baseline {
                                prop_assert_eq!(next, memory_state(desired, 0));
                            } else if desired == baseline {
                                prop_assert_eq!(next, memory_state(baseline, 0));
                            } else {
                                prop_assert_eq!(next.current_target_mib, baseline);
                            }
                        }
                        _ => prop_assert_eq!(next, memory_state(baseline, 0)),
                    }
                }
                Ok(())
            },
        );
        // Extreme single rows, including a saturated low counter.
        let reversed = bounds(1024, 512);
        for low in [0u32, 49, 50, u32::MAX] {
            assert_eq!(
                memory_tick(reversed, memory_state(768, low), sample(512, 400)),
                memory_state(1024, 0)
            );
            let next = memory_tick(adjustable(), memory_state(8192, low), sample(8192, 8192));
            assert_eq!(next, memory_state(8192, 0));
        }
        // u32::MAX low ticks cannot overflow into an early reclaim.
        assert_eq!(
            memory_tick(
                adjustable(),
                memory_state(1024, u32::MAX),
                sample(1024, 128)
            ),
            memory_state(512, 0)
        );
    }

    #[test]
    fn accepted_memory_target_decodes_mib_and_gib() {
        for (enforced, expected) in [("768 MiB", 768u32), ("1 GiB", 1024), ("2 GiB", 2048)] {
            let plan = modification_plan(
                true,
                vec![memory_resize_status(
                    microsandbox::sandbox::ResourceConvergenceState::Accepted,
                    "64 MiB",
                    "512 MiB",
                    enforced,
                )],
            );
            assert_eq!(
                accepted_memory_target(&plan, adjustable()).expect("an accepted target"),
                expected,
                "{enforced}"
            );
        }
        // Every nonnegative state is acceptable, including a downsize marked Applied whose
        // actual value is still the larger one: `enforced` is the authority.
        for state in [
            microsandbox::sandbox::ResourceConvergenceState::Accepted,
            microsandbox::sandbox::ResourceConvergenceState::Converging,
            microsandbox::sandbox::ResourceConvergenceState::Applied,
        ] {
            let plan = modification_plan(
                true,
                vec![memory_resize_status(
                    state, "512 MiB", "1024 MiB", "512 MiB",
                )],
            );
            assert_eq!(
                accepted_memory_target(&plan, adjustable()).expect("an accepted target"),
                512,
                "{state:?}"
            );
        }
        // A CPU row alongside the memory row is ignored, not counted as a duplicate.
        let plan = modification_plan(
            true,
            vec![
                cpu_resize_status(),
                memory_resize_status(
                    microsandbox::sandbox::ResourceConvergenceState::Converging,
                    "768 MiB",
                    "512 MiB",
                    "768 MiB",
                ),
            ],
        );
        assert_eq!(
            accepted_memory_target(&plan, adjustable()).expect("an accepted target"),
            768
        );
    }

    #[test]
    fn unconfirmed_memory_resize_status_is_rejected() {
        let memory = |enforced: &str| {
            memory_resize_status(
                microsandbox::sandbox::ResourceConvergenceState::Accepted,
                "768 MiB",
                "512 MiB",
                enforced,
            )
        };
        // Each row pairs the plan with the cause its diagnostic must name, so this pins the
        // reason as well as the rejection: a decoder that answered every row with one generic
        // message would still fail here.
        type Row = (
            &'static str,
            &'static str,
            microsandbox::sandbox::SandboxModificationPlan,
        );
        let rows: Vec<Row> = vec![
            (
                "applied=false",
                "was not applied",
                modification_plan(false, vec![memory("768 MiB")]),
            ),
            (
                "no memory row",
                "no memory resize status",
                modification_plan(true, vec![]),
            ),
            (
                "cpu only",
                "no memory resize status",
                modification_plan(true, vec![cpu_resize_status()]),
            ),
            (
                "duplicate memory rows",
                "more than one memory resize status",
                modification_plan(true, vec![memory("768 MiB"), memory("768 MiB")]),
            ),
            (
                "empty text",
                "is not an \"N MiB\" or \"N GiB\" value",
                modification_plan(true, vec![memory("")]),
            ),
            (
                "unknown unit",
                "is not an \"N MiB\" or \"N GiB\" value",
                modification_plan(true, vec![memory("768 MB")]),
            ),
            (
                "signed",
                "is not an \"N MiB\" or \"N GiB\" value",
                modification_plan(true, vec![memory("-768 MiB")]),
            ),
            (
                "non-ASCII digits",
                "is not an \"N MiB\" or \"N GiB\" value",
                modification_plan(true, vec![memory("\u{667}\u{66b}\u{678} MiB")]),
            ),
            (
                "no space",
                "is not an \"N MiB\" or \"N GiB\" value",
                modification_plan(true, vec![memory("768MiB")]),
            ),
            (
                "overflowing GiB",
                "overflows MiB",
                modification_plan(true, vec![memory("4194304 GiB")]),
            ),
            (
                "over the ceiling",
                "outside 512..=8192 MiB",
                modification_plan(true, vec![memory("8193 MiB")]),
            ),
            (
                "under the floor",
                "outside 512..=8192 MiB",
                modification_plan(true, vec![memory("511 MiB")]),
            ),
            (
                "guest refused",
                "guest refused",
                modification_plan(
                    true,
                    vec![memory_resize_status(
                        microsandbox::sandbox::ResourceConvergenceState::GuestRefused,
                        "768 MiB",
                        "512 MiB",
                        "768 MiB",
                    )],
                ),
            ),
            (
                "failed",
                "resize failed",
                modification_plan(
                    true,
                    vec![memory_resize_status(
                        microsandbox::sandbox::ResourceConvergenceState::Failed,
                        "768 MiB",
                        "512 MiB",
                        "768 MiB",
                    )],
                ),
            ),
        ];
        for (label, cause, plan) in rows {
            let error = accepted_memory_target(&plan, adjustable())
                .expect_err(&format!("{label} must be rejected"));
            let diagnostic = format!("{error:#}");
            assert!(
                diagnostic.contains(cause),
                "{label} must name {cause:?}, got {diagnostic:?}"
            );
        }
        // The unconfirmed rows above are also what the driver turns into Recovering; the
        // stream rows assert that transition, and the receipt history here is untouched
        // because decoding has no access to it.
    }

    // ------------------------------------------------ ADR-0070 D2 driver seams

    /// One scripted answer per policy request, so a control cannot invent one.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ScriptedAnswer {
        Accept(u32),
        Fail,
    }

    #[derive(Default)]
    struct PolicyLog {
        requests: Vec<MemoryResizeRequest>,
        answers: std::collections::VecDeque<ScriptedAnswer>,
    }

    type SharedPolicyLog = std::rc::Rc<std::cell::RefCell<PolicyLog>>;

    fn policy_log(answers: impl IntoIterator<Item = ScriptedAnswer>) -> SharedPolicyLog {
        std::rc::Rc::new(std::cell::RefCell::new(PolicyLog {
            requests: Vec::new(),
            answers: answers.into_iter().collect(),
        }))
    }

    fn confirmed(current_target_mib: u32, low_ticks: u32) -> MemoryControllerState {
        MemoryControllerState {
            policy: memory_state(current_target_mib, low_ticks),
            authority: TargetAuthority::Confirmed,
            last_accepted_target_mib: current_target_mib,
            retry: MemoryRetry::default(),
        }
    }

    fn recovering(
        baseline_mib: u32,
        low_ticks: u32,
        last_accepted_target_mib: u32,
    ) -> MemoryControllerState {
        MemoryControllerState {
            policy: memory_state(baseline_mib, low_ticks),
            authority: TargetAuthority::Recovering,
            last_accepted_target_mib,
            retry: MemoryRetry::default(),
        }
    }

    /// Drive the production driver with answers supplied per request.
    async fn drive_scripted(
        bounds: MemoryBounds,
        from: MemoryControllerState,
        samples: Vec<anyhow::Result<Option<MemorySample>>>,
        log: SharedPolicyLog,
    ) -> MemoryControllerState {
        let answered = std::rc::Rc::clone(&log);
        drive_memory(
            bounds,
            from,
            futures::stream::iter(samples),
            move |request| {
                let log = std::rc::Rc::clone(&answered);
                async move {
                    let mut log = log.borrow_mut();
                    log.requests.push(request);
                    match log
                        .answers
                        .pop_front()
                        .expect("every policy request has a scripted answer")
                    {
                        ScriptedAnswer::Accept(target_mib) => Ok(target_mib),
                        ScriptedAnswer::Fail => Err(MemoryResizeError::Modify(anyhow::anyhow!(
                            "scripted apply failure with unknown live effect"
                        ))),
                    }
                }
            },
        )
        .await
    }

    fn samples_of(rows: &[(u64, u64)]) -> Vec<anyhow::Result<Option<MemorySample>>> {
        rows.iter()
            .map(|(limit, used)| Ok(Some(sample(*limit, *used))))
            .collect()
    }

    #[tokio::test]
    async fn memory_stream_emits_only_confirmed_target_changes() {
        let bounds = adjustable();
        let log = policy_log([
            ScriptedAnswer::Accept(768),
            ScriptedAnswer::Accept(512),
            ScriptedAnswer::Accept(896),
            ScriptedAnswer::Fail,
            ScriptedAnswer::Accept(1024),
        ]);
        let mut rows = vec![(512u64, 128u64), (512, 400)];
        rows.extend(std::iter::repeat_n((768, 128), 49));
        rows.push((1024, 128));
        rows.push((768, 128));
        rows.push((768, 600));
        let mut stream = samples_of(&rows);
        stream.push(Ok(Some(MemorySample {
            memory_limit_bytes: 768 * MIB,
            memory_available_bytes: None,
        })));
        stream.push(Err(anyhow::anyhow!("scripted metrics lookup failure")));
        stream.push(Ok(Some(sample(896, 800))));
        stream.push(Ok(Some(sample(896, 800))));
        let mut tail = samples_of(&vec![(1024u64, 768u64); 50]);
        stream.append(&mut tail);

        let final_state =
            drive_scripted(bounds, confirmed(512, 0), stream, std::rc::Rc::clone(&log)).await;

        let log = log.borrow();
        assert!(
            log.answers.is_empty(),
            "the stream consumed no unwritten acknowledgment"
        );
        assert_eq!(
            log.requests
                .iter()
                .map(|request| request.target_mib)
                .collect::<Vec<_>>(),
            vec![768, 512, 896, 1152, 1152]
        );
        // Row 9 requested 1152 and was answered with 1024: the receipt, not the request,
        // becomes the accepted target.
        assert_eq!(final_state.policy, memory_state(1024, 0));
        assert_eq!(final_state.authority, TargetAuthority::Confirmed);
        assert_eq!(final_state.last_accepted_target_mib, 1024);
    }

    #[tokio::test]
    async fn demand_above_the_ceiling_stops_at_the_top_without_asking_again() {
        // A 1 GiB ceiling, the smallest adjustable production launch: the guest climbs to the
        // top, then keeps using everything it has (availability zero at `limit == max`). The
        // controller must hold the ceiling rather than ask the runtime for more, and it must
        // still be able to leave the top afterwards.
        let ceiling = bounds(512, 1024);
        let log = policy_log([
            ScriptedAnswer::Accept(768),
            ScriptedAnswer::Accept(1024),
            ScriptedAnswer::Accept(512),
        ]);
        let mut rows = vec![(512u64, 480u64), (768, 700)];
        rows.extend(std::iter::repeat_n((1024, 1024), 30));
        rows.extend(lows(49, 1024, 128));
        let mut stream = samples_of(&rows);
        stream.push(Ok(Some(sample(1024, 128))));

        let final_state =
            drive_scripted(ceiling, confirmed(512, 0), stream, std::rc::Rc::clone(&log)).await;

        let log = log.borrow();
        assert!(log.answers.is_empty(), "every scripted answer was consumed");
        assert_eq!(
            log.requests
                .iter()
                .map(|request| request.target_mib)
                .collect::<Vec<_>>(),
            vec![768, 1024, 512],
            "one request to reach the ceiling, none while it is exhausted, one to leave"
        );
        // Nothing asked for more than the ceiling, so no request can be clamped or refused.
        assert!(
            log.requests
                .iter()
                .all(|request| request.target_mib <= 1024),
            "a request above the ceiling would be a plan the runtime cannot honour"
        );
        assert_eq!(final_state.policy, memory_state(512, 0));
        assert_eq!(final_state.authority, TargetAuthority::Confirmed);
        // The same two facts at the decision seam the driver calls: at the top with the guest
        // using all of it, the proposal is the current target and the low run is untouched.
        let at_top = memory_state(1024, 0);
        assert_eq!(
            memory_tick(ceiling, at_top, sample(1024, 1024)),
            memory_state(1024, 0),
            "demand above the ceiling proposes nothing above it"
        );
        assert_eq!(
            memory_desired_mib(ceiling, 1024 * MIB),
            1024,
            "the ceiling is the clamp, not a value above it"
        );
    }

    #[tokio::test]
    async fn metrics_error_and_missing_slot_reset_the_low_run() {
        // The run is interrupted *after* 49 real lows, so a missing reset would carry 49
        // into the post-gap sequence: the first post-gap low would reclaim instead of the
        // 50th, and the counter left by the gap itself would be 49 rather than 0. Both are
        // asserted directly, which is what makes this row discriminate the reset.
        for gap in ["metrics error", "missing slot"] {
            let bounds = adjustable();
            let log = policy_log([ScriptedAnswer::Accept(512), ScriptedAnswer::Accept(768)]);
            let gap_row = || match gap {
                "metrics error" => Err(anyhow::anyhow!("scripted metrics lookup failure")),
                _ => Ok(None),
            };
            let tick = |from: MemoryControllerState,
                        rows: Vec<anyhow::Result<Option<MemorySample>>>| {
                let log = std::rc::Rc::clone(&log);
                async move { drive_scripted(bounds, from, rows, log).await }
            };

            let after_lows = tick(confirmed(1024, 0), samples_of(&lows(49, 1024, 128))).await;
            assert_eq!(after_lows.policy, memory_state(1024, 49), "{gap}");
            assert!(log.borrow().requests.is_empty(), "{gap}");

            // The gap itself: the target holds, and the run is discarded.
            let after_gap = tick(after_lows, vec![gap_row()]).await;
            assert_eq!(
                after_gap.policy,
                memory_state(1024, 0),
                "{gap}: the interrupted run is discarded, not carried"
            );
            assert!(log.borrow().requests.is_empty(), "{gap}");

            // 49 more lows must not reclaim: the run restarts from the gap.
            let after_restart = tick(after_gap, samples_of(&lows(49, 1024, 128))).await;
            assert_eq!(after_restart.policy, memory_state(1024, 49), "{gap}");
            assert!(
                log.borrow().requests.is_empty(),
                "{gap}: a carried counter would have reclaimed during these 49 ticks"
            );

            // The 50th does, then a later growth still succeeds.
            let mut tail = samples_of(&lows(1, 1024, 128));
            tail.push(Ok(Some(sample(512, 400))));
            let final_state = tick(after_restart, tail).await;

            let log = log.borrow();
            assert!(log.answers.is_empty(), "{gap}");
            assert_eq!(
                log.requests
                    .iter()
                    .map(|request| request.target_mib)
                    .collect::<Vec<_>>(),
                vec![512, 768],
                "{gap}: one reclaim after the interrupted run, then a later growth"
            );
            assert_eq!(final_state.policy, memory_state(768, 0), "{gap}");
            assert_eq!(final_state.authority, TargetAuthority::Confirmed, "{gap}");
        }
    }

    #[tokio::test]
    async fn modify_errors_keep_the_session_alive_and_retry() {
        // A no-effect growth failure: the next observation rebases and retries the growth.
        let log = policy_log([ScriptedAnswer::Fail, ScriptedAnswer::Accept(768)]);
        let after_error = drive_scripted(
            adjustable(),
            confirmed(512, 0),
            samples_of(&[(512, 400)]),
            std::rc::Rc::clone(&log),
        )
        .await;
        assert_eq!(after_error.authority, TargetAuthority::Recovering);
        assert_eq!(after_error.policy, memory_state(512, 0));
        assert_eq!(after_error.last_accepted_target_mib, 512);
        let final_state = drive_scripted(
            adjustable(),
            after_error,
            samples_of(&[(512, 400)]),
            std::rc::Rc::clone(&log),
        )
        .await;
        assert_eq!(final_state.authority, TargetAuthority::Confirmed);
        assert_eq!(final_state.policy, memory_state(768, 0));
        assert_eq!(final_state.last_accepted_target_mib, 768);
        assert_eq!(log.borrow().requests.len(), 2);

        // A no-effect downsize failure against a stable observed baseline: the dwell starts
        // over and needs its own 50 ticks.
        let log = policy_log([ScriptedAnswer::Fail, ScriptedAnswer::Accept(512)]);
        let after_error = drive_scripted(
            adjustable(),
            confirmed(1024, 49),
            samples_of(&[(1024, 128)]),
            std::rc::Rc::clone(&log),
        )
        .await;
        assert_eq!(after_error.authority, TargetAuthority::Recovering);
        assert_eq!(after_error.policy, memory_state(1024, 0));
        let mid = drive_scripted(
            adjustable(),
            after_error,
            samples_of(&lows(49, 1024, 128)),
            std::rc::Rc::clone(&log),
        )
        .await;
        assert_eq!(mid.policy, memory_state(1024, 49));
        assert_eq!(mid.authority, TargetAuthority::Recovering);
        let rows = vec![Ok(Some(sample(1024, 128)))];
        let final_state = drive_scripted(adjustable(), mid, rows, std::rc::Rc::clone(&log)).await;
        assert_eq!(final_state.policy, memory_state(512, 0));
        assert_eq!(final_state.authority, TargetAuthority::Confirmed);
        assert_eq!(
            log.borrow()
                .requests
                .iter()
                .map(|request| request.target_mib)
                .collect::<Vec<_>>(),
            vec![512, 512]
        );
    }

    // A stateful model of one sandbox: the SDK's real saved-config equality rule, real
    // partial effects and a one-shot injected fault. Every returned plan is derived from
    // this state, never from a queue of successes.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum LiveFault {
        /// The call fails before any runtime control is sent: no effect at all.
        NoEffect,
        /// Like `NoEffect`, but it fires on every apply instead of once.
        PersistentNoEffect,
        /// Runtime control succeeded, active-config persistence then failed.
        AtPersistence,
        /// Both took effect, but the returned plan carried no memory status.
        StatuslessReceipt,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum PrepareFault {
        ErrorBeforePersist,
        ErrorAfterPersist,
        NotApplied,
        LiveStatusReported,
    }

    /// What the model says the builder resolved for one memory value: the SDK parses its
    /// own text back, so the fixture must speak the same two spellings.
    fn status_text(mib: u32) -> String {
        if mib >= 1024 && mib.is_multiple_of(1024) {
            format!("{} GiB", mib / 1024)
        } else {
            format!("{mib} MiB")
        }
    }

    #[derive(Default)]
    struct FakeState {
        actual_mib: u32,
        runtime_target_mib: u32,
        saved_desired_mib: u32,
        sdk_actions: Vec<(MemoryApplyMode, u32)>,
        control_requests: Vec<u32>,
        policy_requests: Vec<MemoryResizeRequest>,
        live_fault: Option<LiveFault>,
        prepare_fault: Option<PrepareFault>,
        prepare_persisted: Option<tokio::sync::oneshot::Sender<()>>,
        prepare_release: Option<tokio::sync::oneshot::Receiver<()>>,
    }

    struct FakeVm {
        state: std::sync::Mutex<FakeState>,
    }

    impl FakeVm {
        fn new(actual_mib: u32, saved_desired_mib: u32) -> std::sync::Arc<Self> {
            std::sync::Arc::new(Self {
                state: std::sync::Mutex::new(FakeState {
                    actual_mib,
                    runtime_target_mib: actual_mib,
                    saved_desired_mib,
                    ..FakeState::default()
                }),
            })
        }

        fn with_live_fault(&self, fault: LiveFault) {
            self.state.lock().unwrap().live_fault = Some(fault);
        }

        fn with_prepare_fault(&self, fault: PrepareFault) {
            self.state.lock().unwrap().prepare_fault = Some(fault);
        }

        fn advance_actual(&self, actual_mib: u32) {
            self.state.lock().unwrap().actual_mib = actual_mib;
        }

        fn snapshot(&self) -> (u32, u32, u32) {
            let state = self.state.lock().unwrap();
            (
                state.actual_mib,
                state.runtime_target_mib,
                state.saved_desired_mib,
            )
        }

        fn sdk_actions(&self) -> Vec<(MemoryApplyMode, u32)> {
            self.state.lock().unwrap().sdk_actions.clone()
        }

        fn control_requests(&self) -> Vec<u32> {
            self.state.lock().unwrap().control_requests.clone()
        }

        fn policy_requests(&self) -> Vec<u32> {
            self.state
                .lock()
                .unwrap()
                .policy_requests
                .iter()
                .map(|request| request.target_mib)
                .collect()
        }

        /// One SDK call against the model, without any await point.
        fn step(
            state: &mut FakeState,
            mode: MemoryApplyMode,
            mib: u32,
        ) -> anyhow::Result<microsandbox::sandbox::SandboxModificationPlan> {
            state.sdk_actions.push((mode, mib));
            match mode {
                MemoryApplyMode::NextStart => {
                    if state.prepare_fault == Some(PrepareFault::ErrorBeforePersist) {
                        state.prepare_fault = None;
                        return Err(anyhow::anyhow!(
                            "the next-start seed patch was rejected before persistence"
                        ));
                    }
                    state.saved_desired_mib = mib;
                    match state.prepare_fault.take() {
                        Some(PrepareFault::ErrorAfterPersist) => Err(anyhow::anyhow!(
                            "the next-start seed patch failed after persistence"
                        )),
                        Some(PrepareFault::NotApplied) => Ok(modification_plan(false, vec![])),
                        Some(PrepareFault::LiveStatusReported) => Ok(modification_plan(
                            true,
                            vec![memory_resize_status(
                                microsandbox::sandbox::ResourceConvergenceState::Accepted,
                                &status_text(mib),
                                &status_text(state.runtime_target_mib),
                                &status_text(mib),
                            )],
                        )),
                        Some(PrepareFault::ErrorBeforePersist) => unreachable!("handled above"),
                        None => Ok(modification_plan(true, vec![])),
                    }
                }
                MemoryApplyMode::Live => {
                    // The SDK's own rule: a patch equal to the saved desired memory plans
                    // no change, so it applies and reports no live status.
                    if state.saved_desired_mib == mib {
                        return Ok(modification_plan(true, vec![]));
                    }
                    // A persistent fault stays armed so a test can measure the re-ask rate.
                    if state.live_fault == Some(LiveFault::PersistentNoEffect) {
                        return Err(anyhow::anyhow!("the live memory control request failed"));
                    }
                    match state.live_fault.take() {
                        Some(LiveFault::NoEffect | LiveFault::PersistentNoEffect) => {
                            Err(anyhow::anyhow!("the live memory control request failed"))
                        }
                        fault => {
                            state.control_requests.push(mib);
                            state.runtime_target_mib = mib;
                            match fault {
                                Some(LiveFault::AtPersistence) => Err(anyhow::anyhow!(
                                    "the live target was accepted and active-config persistence failed"
                                )),
                                Some(LiveFault::StatuslessReceipt) => {
                                    state.saved_desired_mib = mib;
                                    Ok(modification_plan(true, vec![]))
                                }
                                _ => {
                                    state.saved_desired_mib = mib;
                                    Ok(modification_plan(
                                        true,
                                        vec![memory_resize_status(
                                            microsandbox::sandbox::ResourceConvergenceState::Applied,
                                            &status_text(mib),
                                            &status_text(state.actual_mib),
                                            &status_text(state.runtime_target_mib),
                                        )],
                                    ))
                                }
                            }
                        }
                    }
                }
            }
        }

        async fn apply(
            &self,
            mode: MemoryApplyMode,
            mib: u32,
        ) -> anyhow::Result<microsandbox::sandbox::SandboxModificationPlan> {
            let (outcome, persisted, release) = {
                let mut state = self.state.lock().unwrap();
                let outcome = Self::step(&mut state, mode, mib);
                let persisted = state.prepare_persisted.take();
                let release = state.prepare_release.take();
                (outcome, persisted, release)
            };
            // Outside the lock: a deterministic window between persisting the seed and
            // returning the prepare plan.
            if let Some(sender) = persisted {
                let _ = sender.send(());
            }
            if let Some(release) = release {
                let _ = release.await;
            }
            outcome
        }
    }

    /// Drive the production driver *and* the production SDK adapter against the model.
    async fn drive_fake(
        bounds: MemoryBounds,
        from: MemoryControllerState,
        samples: Vec<anyhow::Result<Option<MemorySample>>>,
        vm: std::sync::Arc<FakeVm>,
    ) -> MemoryControllerState {
        let modifier = std::sync::Arc::clone(&vm);
        drive_memory(
            bounds,
            from,
            futures::stream::iter(samples),
            move |request| {
                let vm = std::sync::Arc::clone(&modifier);
                async move {
                    vm.state.lock().unwrap().policy_requests.push(request);
                    resize_memory_with(bounds, request, move |mode, mib| {
                        let vm = std::sync::Arc::clone(&vm);
                        async move { vm.apply(mode, mib).await }
                    })
                    .await
                }
            },
        )
        .await
    }

    fn lows(count: usize, limit_mib: u64, used_mib: u64) -> Vec<(u64, u64)> {
        vec![(limit_mib, used_mib); count]
    }

    #[tokio::test]
    async fn repeated_identical_growth_failures_are_damped() {
        let bounds = adjustable();
        // A persistent growth failure: the runtime refuses the ask every time, and nothing
        // about the guest changes. Without damping this is two SDK applies per 200 ms tick
        // for the whole session.
        let vm = FakeVm::new(512, 512);
        vm.with_live_fault(LiveFault::PersistentNoEffect);
        let state = drive_fake(
            bounds,
            confirmed(512, 0),
            samples_of(&lows(100, 512, 400)),
            std::sync::Arc::clone(&vm),
        )
        .await;
        let attempts = vm.policy_requests().len();
        // The first repeat is immediate and only later ones back off, so 100 ticks are a
        // handful of attempts rather than 100. The exact count pins the backoff schedule: one
        // confirmed attempt, one immediate recovery retry (the authority change makes it a
        // different ask), then 1 s, 2 s, 3 s, … apart.
        assert_eq!(
            attempts, 8,
            "100 ticks of a persistent failure must be damped, got {attempts}"
        );
        assert_eq!(
            vm.sdk_actions().len(),
            1 + (attempts - 1) * 2,
            "a failed confirmed growth is one live apply; every later attempt is a recovery \
             prepare plus a failing live apply"
        );
        assert!(vm.control_requests().is_empty());
        assert_eq!(state.authority, TargetAuthority::Recovering);
        assert_eq!(state.policy, memory_state(512, 0));
        assert_eq!(state.last_accepted_target_mib, 512);

        // The damping must not delay recovery: one transient failure still resumes on the
        // next observation, with no change in what the guest reports.
        let vm = FakeVm::new(512, 512);
        vm.with_live_fault(LiveFault::NoEffect);
        let state = drive_fake(
            bounds,
            confirmed(512, 0),
            samples_of(&lows(8, 512, 400)),
            std::sync::Arc::clone(&vm),
        )
        .await;
        assert_eq!(
            state.authority,
            TargetAuthority::Confirmed,
            "a single failure still recovers on its own"
        );
        assert_eq!(state.policy, memory_state(768, 0));
        assert_eq!(vm.policy_requests().len(), 2);
        assert_eq!(vm.control_requests().len(), 1);

        // And a changed ask is never damped, even right after a failure: the recovery repair
        // of `partially_applied_shrink_recovers_growth_after_persistence_error` depends on it.
        let vm = FakeVm::new(1024, 1024);
        vm.with_live_fault(LiveFault::NoEffect);
        let state = drive_fake(
            bounds,
            confirmed(512, 0),
            samples_of(&[(512, 400), (512, 400)]),
            std::sync::Arc::clone(&vm),
        )
        .await;
        assert_eq!(vm.policy_requests(), vec![768, 768]);
        assert_eq!(state.authority, TargetAuthority::Confirmed);
    }

    #[tokio::test]
    async fn a_changed_target_never_inherits_the_previous_damping() {
        // Two failures of the *same* ask, then a different target. The counts have to start
        // over for the new ask, or its next retry would wait out the old one's backoff.
        let bounds = adjustable();
        let log = policy_log([
            ScriptedAnswer::Fail,
            ScriptedAnswer::Fail,
            ScriptedAnswer::Fail,
            ScriptedAnswer::Accept(896),
        ]);
        let tick = |from: MemoryControllerState, rows: Vec<(u64, u64)>| {
            let log = std::rc::Rc::clone(&log);
            async move { drive_scripted(bounds, from, samples_of(&rows), log).await }
        };

        let state = tick(recovering(512, 0, 1024), vec![(512, 400)]).await;
        let state = tick(state, vec![(512, 400)]).await;
        assert_eq!(
            log.borrow().requests.len(),
            2,
            "the first repeat is immediate"
        );
        assert_eq!(
            state.retry.attempts, 2,
            "two consecutive failures of one ask"
        );

        // A different target is a different ask: it goes out on this tick, and its own count
        // starts at one rather than inheriting the failed ask's two.
        let state = tick(state, vec![(768, 600)]).await;
        {
            let log = log.borrow();
            assert_eq!(log.requests.len(), 3, "a changed ask is never delayed");
            assert_eq!(log.requests[2].target_mib, 896);
        }
        assert_eq!(state.retry.attempts, 1, "the new ask starts its own count");

        // And its own first repeat is immediate, so the inherited count really is gone.
        let state = tick(state, vec![(768, 600)]).await;
        assert_eq!(log.borrow().requests.len(), 4);
        assert_eq!(state.policy, memory_state(896, 0));
        assert_eq!(state.authority, TargetAuthority::Confirmed);
        assert_eq!(
            state.retry,
            MemoryRetry::default(),
            "progress clears the damping"
        );
    }

    #[test]
    fn memory_ask_identity_maps_the_request() {
        // The bookkeeping rows below build `MemoryAsk` literals, so they verify the damping but
        // say nothing about the production mapping. This pins `MemoryAsk::of` itself: every
        // direction against the baseline, and the authority carried through unchanged.
        let of = |baseline_mib, target_mib, recovering| {
            MemoryAsk::of(MemoryResizeRequest {
                baseline_mib,
                target_mib,
                recovering,
            })
        };
        for recovering in [false, true] {
            // A growth, then an equal ask (which is Up: nothing is being reclaimed), then a
            // shrink.
            assert_eq!(
                of(512, 768, recovering),
                MemoryAsk {
                    target_mib: 768,
                    direction: MemoryDirection::Up,
                    recovering,
                },
                "a target above the baseline is up ({recovering})"
            );
            assert_eq!(
                of(768, 768, recovering),
                MemoryAsk {
                    target_mib: 768,
                    direction: MemoryDirection::Up,
                    recovering,
                },
                "an equal target is not a reclamation ({recovering})"
            );
            assert_eq!(
                of(1024, 512, recovering),
                MemoryAsk {
                    target_mib: 512,
                    direction: MemoryDirection::Down,
                    recovering,
                },
                "a target below the baseline is down ({recovering})"
            );
        }
        // The two authority values are distinct identities for the same number and direction.
        assert_ne!(of(512, 768, false), of(512, 768, true));
        assert_ne!(of(1024, 512, false), of(1024, 512, true));
        // And a reversal is a different identity even at the same target.
        assert_ne!(of(1024, 768, true), of(512, 768, true));
    }

    #[test]
    fn retry_damping_is_per_ask_identity() {
        // The bookkeeping on its own: same ask, changed target, reversed direction, changed
        // authority. Each of the last three must be admitted at once and start from zero.
        let down768 = MemoryAsk {
            target_mib: 768,
            direction: MemoryDirection::Down,
            recovering: true,
        };
        let mut retry = MemoryRetry::default();
        assert!(retry.admit(down768));
        retry.damp(down768);
        assert_eq!(retry.attempts, 1);
        assert!(retry.admit(down768), "the first repeat is immediate");
        retry.damp(down768);
        assert_eq!(retry.attempts, 2);
        assert!(!retry.admit(down768), "the second repeat waits");
        retry.waited = retry.delay();
        assert!(retry.admit(down768), "and then it is re-asked");

        let up896 = MemoryAsk {
            target_mib: 896,
            ..down768
        };
        assert!(retry.admit(up896), "a changed target is never delayed");
        assert_eq!(
            retry.attempts, 0,
            "a changed target does not inherit the count"
        );
        retry.damp(up896);
        assert_eq!(retry.attempts, 1, "the new ask starts its own count");

        retry.damp(up896);
        assert!(!retry.admit(up896));
        let up768 = MemoryAsk {
            target_mib: 768,
            direction: MemoryDirection::Up,
            recovering: true,
        };
        assert!(
            retry.admit(up768),
            "the same target in the opposite direction is a different ask"
        );
        assert_eq!(retry.attempts, 0);

        retry.damp(up768);
        retry.damp(up768);
        assert!(!retry.admit(up768));
        let confirmed768 = MemoryAsk {
            recovering: false,
            ..up768
        };
        assert!(
            retry.admit(confirmed768),
            "the same ask under a different authority is a different ask"
        );
        assert_eq!(retry.attempts, 0);

        retry.damp(confirmed768);
        retry.clear();
        assert_eq!(retry, MemoryRetry::default(), "progress clears everything");
        assert!(retry.admit(confirmed768));
        assert_eq!(retry.attempts, 0);
    }

    #[tokio::test]
    async fn a_reversed_ask_is_never_queued_behind_a_failed_one() {
        // The same target, the opposite direction: a shrink that failed twice must not delay
        // the growth that supersedes it.
        let bounds = adjustable();
        let log = policy_log([
            ScriptedAnswer::Fail,
            ScriptedAnswer::Fail,
            ScriptedAnswer::Accept(768),
        ]);
        let tick = |from: MemoryControllerState, rows: Vec<(u64, u64)>| {
            let log = std::rc::Rc::clone(&log);
            async move { drive_scripted(bounds, from, samples_of(&rows), log).await }
        };

        // Recovering at 1024 with the run complete: 400 MiB of use wants 768, which is down.
        let state = tick(recovering(1024, 49, 1024), vec![(1024, 400)]).await;
        assert_eq!(log.borrow().requests.len(), 1);
        assert_eq!(state.retry.attempts, 1);
        // A failed shrink restarts the dwell, so the same ask is only eligible again after
        // another 50 low ticks.
        let state = {
            let log = std::rc::Rc::clone(&log);
            drive_scripted(bounds, state, samples_of(&lows(50, 1024, 400)), log).await
        };
        {
            let log = log.borrow();
            assert_eq!(
                log.requests.len(),
                2,
                "the shrink is re-asked after its dwell"
            );
            assert_eq!(log.requests[1].target_mib, 768);
        }
        assert_eq!(state.retry.attempts, 2);

        // The live limit is now 512: the same 768 MiB target is an *up* ask, and it goes out
        // on this tick rather than waiting out the shrink's backoff.
        let state = tick(state, vec![(512, 400)]).await;
        {
            let log = log.borrow();
            assert_eq!(log.requests.len(), 3, "a reversal is never delayed");
            assert_eq!(log.requests[2].target_mib, 768);
        }
        assert_eq!(state.policy, memory_state(768, 0));
        assert_eq!(state.authority, TargetAuthority::Confirmed);
    }

    #[tokio::test]
    async fn an_accepted_target_below_the_request_is_not_re_asked_every_tick() {
        // `enforced` is the authority even when it is below the ask, but a target the runtime
        // reports as accepted and never reaches is not progress: re-asking it every tick
        // would be the same storm as a hard failure.
        let bounds = adjustable();
        // Four short receipts, then a full one: the standing ask is answered with 768 while
        // the guest asks for 896, and only the last attempt is granted what it asked for.
        let log = policy_log(
            std::iter::repeat_n(ScriptedAnswer::Accept(768), 4)
                .chain(std::iter::once(ScriptedAnswer::Accept(896))),
        );
        let requested = |log: &SharedPolicyLog| {
            log.borrow()
                .requests
                .iter()
                .map(|request| request.target_mib)
                .collect::<Vec<_>>()
        };

        let state = drive_scripted(
            bounds,
            confirmed(512, 0),
            samples_of(&lows(20, 768, 600)),
            std::rc::Rc::clone(&log),
        )
        .await;
        assert_eq!(
            requested(&log),
            vec![896, 896, 896, 896],
            "the same short-of-request ask is retried on a bounded schedule, not per tick"
        );
        assert_eq!(state.authority, TargetAuthority::Confirmed);
        assert_eq!(state.policy, memory_state(768, 0));
        assert_eq!(state.last_accepted_target_mib, 768);
        assert_eq!(
            state.retry.attempts, 4,
            "four no-progress results are recorded, so the next attempt waits"
        );

        // The eventual grant must land: the standing ask is still retried, and a full receipt
        // clears the damping so later ticks are not delayed by it.
        let state = drive_scripted(
            bounds,
            state,
            samples_of(&lows(20, 768, 600)),
            std::rc::Rc::clone(&log),
        )
        .await;
        assert_eq!(
            requested(&log),
            vec![896, 896, 896, 896, 896],
            "the bounded schedule still re-asks, and the last one is the grant"
        );
        assert!(
            log.borrow().answers.is_empty(),
            "every scripted answer was consumed: four short, then one full"
        );
        assert_eq!(state.policy, memory_state(896, 0), "the grant is adopted");
        assert_eq!(state.authority, TargetAuthority::Confirmed);
        assert_eq!(state.last_accepted_target_mib, 896);
        assert_eq!(
            state.retry,
            MemoryRetry::default(),
            "a full receipt clears the damping"
        );
    }

    #[tokio::test]
    async fn partially_applied_shrink_recovers_growth_after_persistence_error() {
        for (saved_desired_mib, fault) in [
            (1024u32, LiveFault::AtPersistence),
            (768, LiveFault::AtPersistence),
            (1024, LiveFault::StatuslessReceipt),
        ] {
            let label = format!("saved {saved_desired_mib} / {fault:?}");
            // A statusless receipt means both live control and active persistence
            // succeeded, so only the acknowledgment is missing.
            let persisted_mib = match fault {
                LiveFault::StatuslessReceipt => 512,
                _ => saved_desired_mib,
            };
            let bounds = adjustable();
            let vm = FakeVm::new(1024, saved_desired_mib);
            vm.with_live_fault(fault);
            // The 50th lower-demand tick requests the shrink; the call fails after the VM
            // already changed, so the request is not an acknowledgment.
            let state = drive_fake(
                bounds,
                confirmed(1024, 49),
                samples_of(&[(1024, 128)]),
                std::sync::Arc::clone(&vm),
            )
            .await;
            assert_eq!(vm.policy_requests(), vec![512], "{label}");
            assert_eq!(vm.snapshot(), (1024, 512, persisted_mib), "{label}");
            assert_eq!(state.authority, TargetAuthority::Recovering, "{label}");
            assert_eq!(state.policy, memory_state(1024, 0), "{label}");
            assert_eq!(state.last_accepted_target_mib, 1024, "{label}");

            // An old-limit sample must not clear recovery, and cannot reclaim yet.
            let state = drive_fake(
                bounds,
                state,
                samples_of(&[(1024, 128)]),
                std::sync::Arc::clone(&vm),
            )
            .await;
            assert_eq!(state.authority, TargetAuthority::Recovering, "{label}");
            assert_eq!(vm.policy_requests(), vec![512], "{label}");

            // The VM really is at 512 and genuinely needs more: the same tick that observes
            // it must repair saved configuration and restore growth.
            vm.advance_actual(512);
            let state = drive_fake(
                bounds,
                state,
                samples_of(&[(512, 400)]),
                std::sync::Arc::clone(&vm),
            )
            .await;
            assert_eq!(vm.policy_requests(), vec![512, 768], "{label}");
            assert_eq!(
                vm.sdk_actions(),
                vec![
                    (MemoryApplyMode::Live, 512),
                    (MemoryApplyMode::NextStart, 640),
                    (MemoryApplyMode::Live, 768),
                ],
                "{label}: the seed defeats saved-config equality"
            );
            assert_eq!(vm.control_requests(), vec![512, 768], "{label}");
            assert_eq!(vm.snapshot(), (512, 768, 768), "{label}");
            assert_eq!(state.policy, memory_state(768, 0), "{label}");
            assert_eq!(state.authority, TargetAuthority::Confirmed, "{label}");
            assert_eq!(state.last_accepted_target_mib, 768, "{label}");
        }
    }

    #[tokio::test]
    async fn unconfirmed_persisted_growth_does_not_spin_on_statusless_noops() {
        let bounds = adjustable();
        let vm = FakeVm::new(512, 512);
        vm.with_live_fault(LiveFault::StatuslessReceipt);
        let state = drive_fake(
            bounds,
            confirmed(512, 0),
            samples_of(&[(512, 400)]),
            std::sync::Arc::clone(&vm),
        )
        .await;
        assert_eq!(vm.policy_requests(), vec![768]);
        assert_eq!(vm.snapshot(), (512, 768, 768));
        assert_eq!(state.authority, TargetAuthority::Recovering);
        assert_eq!(state.last_accepted_target_mib, 512);

        // Still 512 as far as the guest reports, and still needing 768: a plain repeat of
        // the live patch would be a statusless no-op, so the seed must come first.
        let state = drive_fake(
            bounds,
            state,
            samples_of(&[(512, 400)]),
            std::sync::Arc::clone(&vm),
        )
        .await;
        assert_eq!(
            vm.sdk_actions(),
            vec![
                (MemoryApplyMode::Live, 768),
                (MemoryApplyMode::NextStart, 640),
                (MemoryApplyMode::Live, 768),
            ]
        );
        assert_eq!(vm.control_requests(), vec![768, 768]);
        assert_eq!(state.policy, memory_state(768, 0));
        assert_eq!(state.authority, TargetAuthority::Confirmed);
        assert_eq!(state.last_accepted_target_mib, 768);

        // Steady demand at the settled target sends nothing at all.
        vm.advance_actual(768);
        let state = drive_fake(
            bounds,
            state,
            samples_of(&lows(1000, 768, 400)),
            std::sync::Arc::clone(&vm),
        )
        .await;
        assert_eq!(vm.sdk_actions().len(), 3);
        assert_eq!(state.policy, memory_state(768, 0));

        // A later reclamation and a later growth both really control the VM.
        let state = drive_fake(
            bounds,
            state,
            samples_of(&lows(50, 768, 128)),
            std::sync::Arc::clone(&vm),
        )
        .await;
        assert_eq!(state.policy, memory_state(512, 0));
        assert_eq!(vm.control_requests(), vec![768, 768, 512]);
        vm.advance_actual(512);
        let state = drive_fake(
            bounds,
            state,
            samples_of(&[(512, 400)]),
            std::sync::Arc::clone(&vm),
        )
        .await;
        assert_eq!(state.policy, memory_state(768, 0));
        assert_eq!(vm.control_requests(), vec![768, 768, 512, 768]);

        // Companion branch: the published limit converges before the first recovery
        // decision, so there is nothing to repair and nothing to send.
        let vm = FakeVm::new(512, 512);
        vm.with_live_fault(LiveFault::StatuslessReceipt);
        let state = drive_fake(
            bounds,
            confirmed(512, 0),
            samples_of(&[(512, 400)]),
            std::sync::Arc::clone(&vm),
        )
        .await;
        assert_eq!(vm.sdk_actions(), vec![(MemoryApplyMode::Live, 768)]);
        vm.advance_actual(768);
        let state = drive_fake(
            bounds,
            state,
            samples_of(&[(768, 400)]),
            std::sync::Arc::clone(&vm),
        )
        .await;
        assert_eq!(state.authority, TargetAuthority::Recovering);
        assert_eq!(state.policy, memory_state(768, 0));
        assert_eq!(state.last_accepted_target_mib, 512);
        assert_eq!(vm.sdk_actions(), vec![(MemoryApplyMode::Live, 768)]);
        // A genuine change repairs and confirms on the tick that observes it.
        let state = drive_fake(
            bounds,
            state,
            samples_of(&lows(50, 768, 128)),
            std::sync::Arc::clone(&vm),
        )
        .await;
        assert_eq!(
            vm.sdk_actions(),
            vec![
                (MemoryApplyMode::Live, 768),
                (MemoryApplyMode::NextStart, 640),
                (MemoryApplyMode::Live, 512),
            ]
        );
        assert_eq!(state.policy, memory_state(512, 0));
        assert_eq!(state.authority, TargetAuthority::Confirmed);
        assert_eq!(state.last_accepted_target_mib, 512);
    }

    #[tokio::test]
    async fn recovery_reseeds_saved_config_without_changing_live_memory() {
        // The kernel's own literals, checked against an independent candidate sequence.
        let candidate_oracle = |baseline: u32, desired: u32| {
            (0..3u32)
                .map(|step| 512 + 128 * step)
                .find(|candidate| *candidate != baseline && *candidate != desired)
        };
        for (baseline, desired) in [(512u32, 768u32), (896, 1024), (768, 512), (1024, 768)] {
            assert_eq!(
                memory_recovery_seed(adjustable(), baseline, desired),
                candidate_oracle(baseline, desired),
                "{baseline} -> {desired}"
            );
        }
        for (baseline, desired) in [(0u32, 0u32), (512, 640), (8192, u32::MAX)] {
            assert_eq!(
                memory_recovery_seed(adjustable(), baseline, desired),
                candidate_oracle(baseline, desired),
                "{baseline} -> {desired}"
            );
        }
        // No eligible seed in a synthetic one-step interval: an advisory refusal, no I/O.
        assert_eq!(memory_recovery_seed(bounds(512, 640), 512, 640), None);
        let vm = FakeVm::new(512, 1024);
        let outcome = resize_memory_with(
            bounds(512, 640),
            MemoryResizeRequest {
                baseline_mib: 512,
                target_mib: 640,
                recovering: true,
            },
            |mode, mib| {
                let vm = std::sync::Arc::clone(&vm);
                async move { vm.apply(mode, mib).await }
            },
        )
        .await;
        assert!(matches!(outcome, Err(MemoryResizeError::Unconfirmed(_))));
        assert!(vm.sdk_actions().is_empty());

        // O896 -> D1024 seeds 512, and the configuration-only patch must not shrink the
        // running VM: observe the model between persisting and returning.
        let bounds = adjustable();
        let vm = FakeVm::new(896, 2048);
        let (persisted_tx, persisted_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        {
            let mut state = vm.state.lock().unwrap();
            state.prepare_persisted = Some(persisted_tx);
            state.prepare_release = Some(release_rx);
        }
        let driver = tokio::spawn(drive_fake(
            bounds,
            recovering(896, 0, 2048),
            samples_of(&[(896, 700)]),
            std::sync::Arc::clone(&vm),
        ));
        persisted_rx.await.expect("the seed was persisted");
        assert_eq!(
            vm.sdk_actions(),
            vec![(MemoryApplyMode::NextStart, 512)],
            "the seed is the only call so far"
        );
        assert!(
            vm.control_requests().is_empty(),
            "a configuration-only patch sends no runtime control"
        );
        assert_eq!(
            vm.snapshot(),
            (896, 896, 512),
            "usable memory is unchanged by the seed"
        );
        release_tx.send(()).expect("the prepare plan is awaited");
        let state = driver.await.expect("the driver task");
        assert_eq!(
            vm.sdk_actions(),
            vec![
                (MemoryApplyMode::NextStart, 512),
                (MemoryApplyMode::Live, 1024),
            ]
        );
        assert_eq!(vm.control_requests(), vec![1024]);
        assert_eq!(state.authority, TargetAuthority::Confirmed);
        assert_eq!(state.last_accepted_target_mib, 1024);

        // Every failing stage selects Recovering, and a later healthy attempt still works.
        for fault in [
            PrepareFault::ErrorBeforePersist,
            PrepareFault::ErrorAfterPersist,
            PrepareFault::NotApplied,
            PrepareFault::LiveStatusReported,
        ] {
            let vm = FakeVm::new(512, 1024);
            vm.with_prepare_fault(fault);
            let state = drive_fake(
                bounds,
                recovering(512, 0, 1024),
                samples_of(&[(512, 400)]),
                std::sync::Arc::clone(&vm),
            )
            .await;
            assert_eq!(state.authority, TargetAuthority::Recovering, "{fault:?}");
            assert_eq!(state.policy, memory_state(512, 0), "{fault:?}");
            assert_eq!(state.last_accepted_target_mib, 1024, "{fault:?}");
            assert!(
                vm.control_requests().is_empty(),
                "{fault:?}: a rejected prepare sends no runtime control"
            );
            let state = drive_fake(
                bounds,
                state,
                samples_of(&[(512, 400)]),
                std::sync::Arc::clone(&vm),
            )
            .await;
            assert_eq!(state.authority, TargetAuthority::Confirmed, "{fault:?}");
            assert_eq!(state.last_accepted_target_mib, 768, "{fault:?}");
        }
        // A live failure after a successful prepare leaves Recovering, not a fake receipt.
        let vm = FakeVm::new(512, 1024);
        vm.with_live_fault(LiveFault::NoEffect);
        let state = drive_fake(
            bounds,
            recovering(512, 0, 1024),
            samples_of(&[(512, 400)]),
            std::sync::Arc::clone(&vm),
        )
        .await;
        assert_eq!(state.authority, TargetAuthority::Recovering);
        assert_eq!(state.last_accepted_target_mib, 1024);
        assert_eq!(vm.snapshot(), (512, 512, 640));
    }

    #[tokio::test]
    async fn recovery_baseline_change_after_49_lows_restarts_dwell() {
        let bounds = adjustable();
        let vm = FakeVm::new(1024, 2048);
        let state = drive_fake(
            bounds,
            recovering(1024, 0, 2048),
            samples_of(&lows(49, 1024, 128)),
            std::sync::Arc::clone(&vm),
        )
        .await;
        assert_eq!(state.policy, memory_state(1024, 49));
        assert!(vm.policy_requests().is_empty());

        // The baseline moves: 49 ticks measured against another commitment are discarded.
        let state = drive_fake(
            bounds,
            state,
            samples_of(&[(896, 128)]),
            std::sync::Arc::clone(&vm),
        )
        .await;
        assert_eq!(state.policy, memory_state(896, 1));
        assert_eq!(state.authority, TargetAuthority::Recovering);
        assert_eq!(state.last_accepted_target_mib, 2048);
        assert!(vm.policy_requests().is_empty());

        let state = drive_fake(
            bounds,
            state,
            samples_of(&lows(48, 896, 128)),
            std::sync::Arc::clone(&vm),
        )
        .await;
        assert_eq!(state.policy, memory_state(896, 49));
        assert!(vm.sdk_actions().is_empty());

        let state = drive_fake(
            bounds,
            state,
            samples_of(&[(896, 128)]),
            std::sync::Arc::clone(&vm),
        )
        .await;
        assert_eq!(vm.policy_requests(), vec![512]);
        assert_eq!(
            vm.sdk_actions(),
            vec![
                (MemoryApplyMode::NextStart, 640),
                (MemoryApplyMode::Live, 512),
            ]
        );
        assert_eq!(vm.control_requests(), vec![512]);
        assert_eq!(state.policy, memory_state(512, 0));
        assert_eq!(state.authority, TargetAuthority::Confirmed);
        assert_eq!(state.last_accepted_target_mib, 512);
    }

    #[tokio::test]
    async fn alternating_recovery_baselines_never_accumulate_lows() {
        let bounds = adjustable();
        let vm = FakeVm::new(896, 2048);
        let mut state = recovering(896, 0, 2048);
        for observation in 0..1000usize {
            let limit_mib = if observation % 2 == 0 { 1024 } else { 896 };
            state = drive_fake(
                bounds,
                state,
                samples_of(&[(limit_mib, 128)]),
                std::sync::Arc::clone(&vm),
            )
            .await;
            assert_eq!(
                state.policy,
                memory_state(limit_mib as u32, 1),
                "observation {observation}"
            );
            assert_eq!(state.authority, TargetAuthority::Recovering);
            assert_eq!(state.last_accepted_target_mib, 2048);
        }
        assert!(vm.policy_requests().is_empty());
        assert!(vm.sdk_actions().is_empty());
        assert!(vm.control_requests().is_empty());
    }

    #[tokio::test]
    async fn stabilized_recovery_baseline_completes_exact_remaining_dwell() {
        let bounds = adjustable();
        let vm = FakeVm::new(896, 2048);
        // The shared prefix: the alternation above, ending on the 896 baseline with one
        // low tick counted.
        let mut state = recovering(896, 0, 2048);
        for observation in 0..1000usize {
            let limit_mib = if observation % 2 == 0 { 1024 } else { 896 };
            state = drive_fake(
                bounds,
                state,
                samples_of(&[(limit_mib, 128)]),
                std::sync::Arc::clone(&vm),
            )
            .await;
        }
        assert_eq!(state.policy, memory_state(896, 1));
        for tick in 2..=49u32 {
            state = drive_fake(
                bounds,
                state,
                samples_of(&[(896, 128)]),
                std::sync::Arc::clone(&vm),
            )
            .await;
            assert_eq!(state.policy, memory_state(896, tick), "stable tick {tick}");
            assert!(vm.sdk_actions().is_empty());
            assert_eq!(state.last_accepted_target_mib, 2048);
        }
        state = drive_fake(
            bounds,
            state,
            samples_of(&[(896, 128)]),
            std::sync::Arc::clone(&vm),
        )
        .await;
        assert_eq!(vm.policy_requests(), vec![512]);
        assert_eq!(
            vm.sdk_actions(),
            vec![
                (MemoryApplyMode::NextStart, 640),
                (MemoryApplyMode::Live, 512),
            ]
        );
        assert_eq!(vm.control_requests(), vec![512]);
        assert_eq!(state.policy, memory_state(512, 0));
        assert_eq!(state.authority, TargetAuthority::Confirmed);
        assert_eq!(state.last_accepted_target_mib, 512);
    }

    #[tokio::test]
    async fn failed_prepare_seed_persists_through_holds_then_genuine_growth() {
        let bounds = adjustable();
        for fault in [
            PrepareFault::ErrorAfterPersist,
            PrepareFault::NotApplied,
            PrepareFault::LiveStatusReported,
        ] {
            let vm = FakeVm::new(512, 1024);
            vm.with_prepare_fault(fault);
            let state = drive_fake(
                bounds,
                recovering(512, 0, 1024),
                samples_of(&[(512, 400)]),
                std::sync::Arc::clone(&vm),
            )
            .await;
            assert_eq!(state.authority, TargetAuthority::Recovering, "{fault:?}");
            assert_eq!(state.policy, memory_state(512, 0), "{fault:?}");
            assert_eq!(state.last_accepted_target_mib, 1024, "{fault:?}");
            assert_eq!(vm.snapshot(), (512, 512, 640), "{fault:?}");
            assert!(
                vm.control_requests().is_empty(),
                "{fault:?}: the failed prepare sends no runtime control"
            );

            // A thousand holds repair nothing, roll nothing back and send nothing.
            let state = drive_fake(
                bounds,
                state,
                samples_of(&lows(1000, 512, 128)),
                std::sync::Arc::clone(&vm),
            )
            .await;
            assert_eq!(state.authority, TargetAuthority::Recovering, "{fault:?}");
            assert_eq!(state.policy, memory_state(512, 0), "{fault:?}");
            assert_eq!(state.last_accepted_target_mib, 1024, "{fault:?}");
            assert_eq!(vm.snapshot(), (512, 512, 640), "{fault:?}");
            assert_eq!(vm.sdk_actions().len(), 1, "{fault:?}");

            // Genuine demand for the value already saved still reseeds, because a plain
            // live patch equal to the saved seed would be a statusless no-op.
            let state = drive_fake(
                bounds,
                state,
                samples_of(&[(512, 257)]),
                std::sync::Arc::clone(&vm),
            )
            .await;
            assert_eq!(vm.policy_requests(), vec![768, 640], "{fault:?}");
            assert_eq!(
                vm.sdk_actions(),
                vec![
                    (MemoryApplyMode::NextStart, 640),
                    (MemoryApplyMode::NextStart, 768),
                    (MemoryApplyMode::Live, 640),
                ],
                "{fault:?}"
            );
            assert_eq!(vm.control_requests(), vec![640], "{fault:?}");
            assert_eq!(state.policy, memory_state(640, 0), "{fault:?}");
            assert_eq!(state.authority, TargetAuthority::Confirmed, "{fault:?}");
            assert_eq!(state.last_accepted_target_mib, 640, "{fault:?}");
        }
        // Negative control: at saved 640 the plain live patch is applied and statusless.
        let vm = FakeVm::new(512, 640);
        let plan = vm
            .apply(MemoryApplyMode::Live, 640)
            .await
            .expect("an applied plan");
        assert!(plan.applied);
        assert!(plan.resize_status.is_empty());
        assert!(vm.control_requests().is_empty());
    }

    #[tokio::test]
    async fn observed_limit_recovery_validates_integral_bounded_limits() {
        let bounds = adjustable();
        for limit_mib in [512u32, 768, 8192] {
            assert_eq!(
                observed_memory_target(bounds, u64::from(limit_mib) * MIB)
                    .expect("an accepted observation"),
                limit_mib
            );
        }
        for limit_bytes in [
            512 * MIB + 1,
            0,
            511 * MIB,
            8193 * MIB,
            (u64::from(u32::MAX) + 1) * MIB,
        ] {
            observed_memory_target(bounds, limit_bytes)
                .expect_err(&format!("{limit_bytes} bytes must be rejected"));
        }

        // Every unusable observation keeps Recovering with no resize, and a later valid
        // limit restores a reachable growth request.
        let vm = FakeVm::new(1024, 2048);
        let mut state = recovering(1024, 0, 2048);
        for unusable in [
            Ok(Some(MemorySample {
                memory_limit_bytes: 1024 * MIB + 1,
                memory_available_bytes: Some(896 * MIB),
            })),
            Ok(None),
            Err(anyhow::anyhow!("scripted metrics lookup failure")),
        ] {
            state = drive_fake(bounds, state, vec![unusable], std::sync::Arc::clone(&vm)).await;
            assert_eq!(state.authority, TargetAuthority::Recovering);
            assert_eq!(state.policy, memory_state(1024, 0));
            assert_eq!(state.last_accepted_target_mib, 2048);
            assert!(vm.policy_requests().is_empty());
        }
        // A valid limit with no availability updates the baseline and nothing else.
        state = drive_fake(
            bounds,
            state,
            vec![Ok(Some(MemorySample {
                memory_limit_bytes: 512 * MIB,
                memory_available_bytes: None,
            }))],
            std::sync::Arc::clone(&vm),
        )
        .await;
        assert_eq!(state.policy, memory_state(512, 0));
        assert_eq!(state.authority, TargetAuthority::Recovering);
        assert_eq!(state.last_accepted_target_mib, 2048);
        assert!(vm.policy_requests().is_empty());
        // And then a reachable growth request.
        state = drive_fake(
            bounds,
            state,
            samples_of(&[(512, 400)]),
            std::sync::Arc::clone(&vm),
        )
        .await;
        assert_eq!(vm.policy_requests(), vec![768]);
        assert_eq!(state.policy, memory_state(768, 0));
        assert_eq!(state.authority, TargetAuthority::Confirmed);
        assert_eq!(state.last_accepted_target_mib, 768);
    }

    // ------------------------------------------------ monitor logging and lifetime

    #[derive(Clone, Debug)]
    struct CapturedEvent {
        level: tracing::Level,
        target: String,
        message: String,
        fields: std::collections::BTreeMap<String, String>,
    }

    #[derive(Clone, Default)]
    struct Capture(std::sync::Arc<std::sync::Mutex<Vec<CapturedEvent>>>);

    impl Capture {
        fn events(&self) -> Vec<CapturedEvent> {
            self.0.lock().expect("capture lock").clone()
        }
    }

    struct FieldVisitor<'a>(&'a mut std::collections::BTreeMap<String, String>);

    impl tracing::field::Visit for FieldVisitor<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0
                .insert(field.name().to_string(), format!("{value:?}"));
        }
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.insert(field.name().to_string(), value.to_string());
        }
        fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
            self.0.insert(field.name().to_string(), value.to_string());
        }
        fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
            self.0.insert(field.name().to_string(), value.to_string());
        }
        fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
            self.0.insert(field.name().to_string(), value.to_string());
        }
    }

    /// One thread's capture: what it records, how verbose it is, and which case it names.
    struct CaptureState {
        capture: Capture,
        max_level: tracing::Level,
        /// The sandbox and case this capture belongs to. Inserted before the span's fields,
        /// which override them.
        context: (String, String),
        spans: std::collections::HashMap<u64, std::collections::BTreeMap<String, String>>,
        stack: Vec<u64>,
        next_span: u64,
    }

    thread_local! {
        /// The capture this thread records into; a thread with none records nothing.
        static ACTIVE_CAPTURE: std::cell::RefCell<Option<CaptureState>> =
            const { std::cell::RefCell::new(None) };
    }

    /// The one subscriber this test module installs.
    ///
    /// Switching dispatchers per test (`set_default` plus `rebuild_interest_cache`) cannot be
    /// made safe here: `tracing` caches callsite interest **process-wide**, so two captures
    /// running at once rebuild over each other and can drop an event — an intermittent missing
    /// event that no amount of assertion strength would catch reliably. One immutable
    /// subscriber, with the capture chosen per thread through [`ACTIVE_CAPTURE`], has no such
    /// state to race over. Each test still sees only its own events, nothing is written to
    /// stderr, and the production tracing configuration is untouched.
    struct CaptureSubscriber;

    impl CaptureSubscriber {
        fn with<R>(&self, record: impl FnOnce(&mut CaptureState) -> R) -> Option<R> {
            ACTIVE_CAPTURE.with(|slot| slot.borrow_mut().as_mut().map(record))
        }

        fn span_fields(
            state: &CaptureState,
            id: u64,
        ) -> std::collections::BTreeMap<String, String> {
            state.spans.get(&id).cloned().unwrap_or_default()
        }
    }

    impl tracing::Subscriber for CaptureSubscriber {
        /// Always, never "sometimes".
        ///
        /// The default implementation asks [`Self::enabled`], which is false whenever *this
        /// thread* has no capture — and `tracing` caches that answer for the whole process. The
        /// first event emitted outside a capture would then pin the callsite to `never` for
        /// every later capture, which is exactly the intermittent missing event this
        /// subscriber replaces. Level and capture filtering therefore happen in
        /// [`Self::event`], where it is a per-call decision rather than a cached one.
        fn register_callsite(
            &self,
            _metadata: &'static tracing::Metadata<'static>,
        ) -> tracing::subscriber::Interest {
            tracing::subscriber::Interest::always()
        }

        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            ACTIVE_CAPTURE.with(|slot| {
                slot.borrow()
                    .as_ref()
                    .is_some_and(|state| *metadata.level() <= state.max_level)
            })
        }
        fn new_span(&self, attributes: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            let id = self
                .with(|state| {
                    let id = state.next_span;
                    state.next_span += 1;
                    let mut fields = std::collections::BTreeMap::new();
                    attributes.record(&mut FieldVisitor(&mut fields));
                    state.spans.insert(id, fields);
                    id
                })
                .unwrap_or(0);
            // A span created while no capture is active is never entered by a subscriber that
            // would record it, so a placeholder id is enough.
            tracing::span::Id::from_u64(id.max(1))
        }
        fn record(&self, span: &tracing::span::Id, values: &tracing::span::Record<'_>) {
            self.with(|state| {
                let mut fields = Self::span_fields(state, span.into_u64());
                values.record(&mut FieldVisitor(&mut fields));
                state.spans.insert(span.into_u64(), fields);
            });
        }
        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            self.with(|state| {
                if *event.metadata().level() > state.max_level {
                    return;
                }
                let mut fields = std::collections::BTreeMap::new();
                event.record(&mut FieldVisitor(&mut fields));
                // Span fields travel with the event, which is how `sandbox` and `case_id`
                // correlate it; the capture's own context is the fallback, and the message is
                // a field like any other.
                for id in state.stack.iter() {
                    for (name, value) in Self::span_fields(state, *id) {
                        fields.entry(name).or_insert(value);
                    }
                }
                fields
                    .entry("sandbox".to_string())
                    .or_insert_with(|| state.context.0.clone());
                fields
                    .entry("case_id".to_string())
                    .or_insert_with(|| state.context.1.clone());
                let message = fields.remove("message").unwrap_or_default();
                state
                    .capture
                    .0
                    .lock()
                    .expect("capture lock")
                    .push(CapturedEvent {
                        level: *event.metadata().level(),
                        target: event.metadata().target().to_string(),
                        message,
                        fields,
                    });
            });
        }
        fn enter(&self, span: &tracing::span::Id) {
            self.with(|state| state.stack.push(span.into_u64()));
        }
        fn exit(&self, _span: &tracing::span::Id) {
            self.with(|state| {
                state.stack.pop();
            });
        }
    }

    fn install_capture_subscriber() {
        static INSTALL: std::sync::Once = std::sync::Once::new();
        INSTALL.call_once(|| {
            if tracing::subscriber::set_global_default(CaptureSubscriber).is_ok() {
                // Callsites evaluated before this point cached `never`, and `tracing` only
                // recomputes that on an explicit rebuild. Doing it exactly once, with the one
                // subscriber that will ever be installed, is what makes the capture stable:
                // there is nothing left that could change interest afterwards.
                tracing::callsite::rebuild_interest_cache();
            }
        });
    }

    /// Drive the production driver under a capture and return what it logged.
    async fn capture_run<R, F>(
        bounds: MemoryBounds,
        case_id: &'static str,
        max_level: tracing::Level,
        from: MemoryControllerState,
        samples: Vec<anyhow::Result<Option<MemorySample>>>,
        resize: R,
    ) -> (Capture, MemoryControllerState)
    where
        R: FnMut(MemoryResizeRequest) -> F,
        F: std::future::Future<Output = Result<u32, MemoryResizeError>>,
    {
        install_capture_subscriber();
        let capture = Capture::default();
        ACTIVE_CAPTURE.with(|slot| {
            *slot.borrow_mut() = Some(CaptureState {
                capture: capture.clone(),
                max_level,
                context: ("unit-test-sandbox".to_string(), case_id.to_string()),
                spans: std::collections::HashMap::new(),
                stack: Vec::new(),
                next_span: 1,
            });
        });
        // Production keeps its real sandbox span; the test adds a `case_id` so one capture of
        // many scenarios can still be validated per case.
        let span = tracing::debug_span!(
            target: MONITOR_TARGET,
            "memory_commitment",
            sandbox = "unit-test-sandbox",
            case_id = case_id,
        );
        // A capture that admits DEBUG must have the span, or the correlation it asserts is not
        // actually being exercised.
        if max_level >= tracing::Level::DEBUG {
            assert!(
                !span.is_disabled(),
                "the capture span must be enabled for {case_id}"
            );
        }
        let final_state = drive_memory(bounds, from, futures::stream::iter(samples), resize)
            .instrument(span)
            .await;
        ACTIVE_CAPTURE.with(|slot| *slot.borrow_mut() = None);
        (capture, final_state)
    }

    const MONITOR_ERROR_EVENTS: [&str; 6] = [
        "metrics_error",
        "metrics_missing",
        "modify_error",
        "unconfirmed_resize_status",
        "invalid_recovery_limit",
        "monitor_join_error",
    ];

    fn is_error_event(event: &CapturedEvent) -> bool {
        event
            .fields
            .get("event")
            .map(|name| MONITOR_ERROR_EVENTS.contains(&name.as_str()))
            .unwrap_or(false)
    }

    /// One correlated DEBUG error event per expected case, whose diagnostic names that
    /// case's own underlying cause — not merely its stage.
    fn validate_error_events(
        events: &[CapturedEvent],
        sandbox: &str,
        expected: &[(&str, &str)],
    ) -> Result<(), String> {
        for (case, cause) in expected {
            let found = events.iter().any(|event| {
                if event.level != tracing::Level::DEBUG
                    || event.target != MONITOR_TARGET
                    || event.fields.get("case_id").map(String::as_str) != Some(*case)
                    || !is_error_event(event)
                    || event.fields.get("sandbox").map(String::as_str) != Some(sandbox)
                {
                    return false;
                }
                let diagnostic = event
                    .fields
                    .get("error")
                    .or_else(|| event.fields.get("reason"))
                    .cloned()
                    .unwrap_or_default();
                diagnostic.contains(cause)
            });
            if !found {
                return Err(format!(
                    "no correlated DEBUG error event for case {case} naming {cause:?}"
                ));
            }
        }
        Ok(())
    }

    /// Production resize through the model, for the logging scenarios.
    macro_rules! fake_resize {
        ($vm:expr, $bounds:expr) => {
            move |request| {
                let vm = std::sync::Arc::clone(&$vm);
                async move {
                    resize_memory_with($bounds, request, move |mode, mib| {
                        let vm = std::sync::Arc::clone(&vm);
                        async move { vm.apply(mode, mib).await }
                    })
                    .await
                }
            }
        };
    }

    #[tokio::test]
    async fn monitor_logs_are_debug_only() {
        let bounds = adjustable();
        // One scenario that reconciles (the observed limit differs from the recovery
        // baseline) and one that fails (a live apply with no effect), so each named event is
        // required by name rather than by a disjunction any other event could satisfy.
        let reconciling = FakeVm::new(512, 2048);
        let (capture, reconciled_state) = capture_run(
            bounds,
            "reconciling",
            tracing::Level::TRACE,
            recovering(1024, 0, 2048),
            samples_of(&[(512, 400)]),
            fake_resize!(reconciling, bounds),
        )
        .await;
        assert_eq!(reconciled_state.authority, TargetAuthority::Confirmed);
        let failing = FakeVm::new(512, 512);
        failing.with_live_fault(LiveFault::NoEffect);
        let (failure_capture, failure_state) = capture_run(
            bounds,
            "failing",
            tracing::Level::TRACE,
            confirmed(512, 0),
            samples_of(&[(512, 400)]),
            fake_resize!(failing, bounds),
        )
        .await;
        assert_eq!(failure_state.authority, TargetAuthority::Recovering);

        let events: Vec<CapturedEvent> = capture
            .events()
            .into_iter()
            .chain(failure_capture.events())
            .collect();
        let monitor: Vec<&CapturedEvent> = events
            .iter()
            .filter(|event| event.target == MONITOR_TARGET)
            .collect();
        let has = |name: &str| {
            monitor
                .iter()
                .any(|event| event.fields.get("event").map(String::as_str) == Some(name))
        };
        assert!(has("memory_transition"), "a confirmed transition is logged");
        assert!(has("memory_reconciled"), "a rebaseline is logged");
        assert!(has("modify_error"), "a failed apply is logged");
        for event in &monitor {
            assert_eq!(
                event.level,
                tracing::Level::DEBUG,
                "monitor event {:?} is not DEBUG",
                event.fields.get("event")
            );
        }
        // A WARN filter sees none of it: normal output stays silent.
        let vm = FakeVm::new(512, 512);
        vm.with_live_fault(LiveFault::NoEffect);
        let (warn_capture, _) = capture_run(
            bounds,
            "mixed",
            tracing::Level::WARN,
            confirmed(512, 0),
            samples_of(&[(512, 400)]),
            fake_resize!(vm, bounds),
        )
        .await;
        assert!(
            warn_capture
                .events()
                .iter()
                .all(|event| event.target != MONITOR_TARGET),
            "no monitor event survives a WARN filter"
        );
    }

    #[tokio::test]
    async fn each_transient_monitor_error_emits_a_debug_event() {
        let bounds = adjustable();
        let mut events = Vec::new();
        let unreachable_resize = || async {
            Err::<u32, MemoryResizeError>(MemoryResizeError::Modify(anyhow::anyhow!(
                "this scenario issues no resize"
            )))
        };

        let (capture, state) = capture_run(
            bounds,
            "metrics_error",
            tracing::Level::TRACE,
            confirmed(512, 0),
            vec![Err(anyhow::anyhow!("scripted metrics lookup failure"))],
            |_request| unreachable_resize(),
        )
        .await;
        events.extend(capture.events());
        assert_eq!(state.authority, TargetAuthority::Confirmed);
        let (capture, _) = capture_run(
            bounds,
            "metrics_missing",
            tracing::Level::TRACE,
            confirmed(512, 0),
            vec![Ok(None)],
            |_request| unreachable_resize(),
        )
        .await;
        events.extend(capture.events());
        let (capture, _) = capture_run(
            bounds,
            "invalid_recovery_limit",
            tracing::Level::TRACE,
            recovering(1024, 0, 2048),
            vec![Ok(Some(MemorySample {
                memory_limit_bytes: 1024 * MIB + 1,
                memory_available_bytes: Some(896 * MIB),
            }))],
            |_request| unreachable_resize(),
        )
        .await;
        events.extend(capture.events());

        // A live apply that fails before any effect.
        let vm = FakeVm::new(512, 512);
        vm.with_live_fault(LiveFault::NoEffect);
        let (capture, state) = capture_run(
            bounds,
            "modify_error_live_apply",
            tracing::Level::TRACE,
            confirmed(512, 0),
            samples_of(&[(512, 400)]),
            fake_resize!(vm, bounds),
        )
        .await;
        events.extend(capture.events());
        assert_eq!(state.authority, TargetAuthority::Recovering);

        // A recovery prepare that fails before and after persisting the seed.
        for (case_id, fault) in [
            (
                "modify_error_recovery_prepare_before",
                PrepareFault::ErrorBeforePersist,
            ),
            (
                "modify_error_recovery_prepare_after",
                PrepareFault::ErrorAfterPersist,
            ),
        ] {
            let vm = FakeVm::new(512, 1024);
            vm.with_prepare_fault(fault);
            let (capture, state) = capture_run(
                bounds,
                case_id,
                tracing::Level::TRACE,
                recovering(512, 0, 1024),
                samples_of(&[(512, 400)]),
                fake_resize!(vm, bounds),
            )
            .await;
            events.extend(capture.events());
            assert_eq!(state.authority, TargetAuthority::Recovering);
        }

        // Rejected prepare plans are unconfirmed receipts, not applies.
        for (case_id, fault) in [
            ("unconfirmed_prepare_not_applied", PrepareFault::NotApplied),
            (
                "unconfirmed_prepare_live_status",
                PrepareFault::LiveStatusReported,
            ),
        ] {
            let vm = FakeVm::new(512, 1024);
            vm.with_prepare_fault(fault);
            let (capture, state) = capture_run(
                bounds,
                case_id,
                tracing::Level::TRACE,
                recovering(512, 0, 1024),
                samples_of(&[(512, 400)]),
                fake_resize!(vm, bounds),
            )
            .await;
            events.extend(capture.events());
            assert_eq!(state.authority, TargetAuthority::Recovering);
        }

        // Each negative live-receipt fixture through the production decoder.
        let mut fixtures: Vec<(&'static str, microsandbox::sandbox::SandboxModificationPlan)> = vec![
            ("unconfirmed_not_applied", modification_plan(false, vec![])),
            ("unconfirmed_missing_row", modification_plan(true, vec![])),
            (
                "unconfirmed_duplicate_row",
                modification_plan(
                    true,
                    vec![
                        memory_resize_status(
                            microsandbox::sandbox::ResourceConvergenceState::Accepted,
                            "768 MiB",
                            "512 MiB",
                            "768 MiB",
                        );
                        2
                    ],
                ),
            ),
            (
                "unconfirmed_out_of_range",
                modification_plan(
                    true,
                    vec![memory_resize_status(
                        microsandbox::sandbox::ResourceConvergenceState::Accepted,
                        "768 MiB",
                        "512 MiB",
                        "8193 MiB",
                    )],
                ),
            ),
        ];
        for (case_id, plan) in fixtures.drain(..) {
            let decoder_plan = plan.clone();
            let (capture, state) = capture_run(
                bounds,
                case_id,
                tracing::Level::TRACE,
                confirmed(512, 0),
                samples_of(&[(512, 400)]),
                move |request| {
                    let plan = decoder_plan.clone();
                    async move {
                        let _ = request;
                        accepted_memory_target(&plan, bounds).map_err(|error| {
                            MemoryResizeError::Unconfirmed(
                                error.context("live_apply: decoding the status"),
                            )
                        })
                    }
                },
            )
            .await;
            events.extend(capture.events());
            assert_eq!(state.authority, TargetAuthority::Recovering);
        }

        let expected = [
            ("metrics_error", "scripted metrics lookup failure"),
            ("metrics_missing", "no live row"),
            ("invalid_recovery_limit", "not a whole number of MiB"),
            (
                "modify_error_live_apply",
                "the live memory control request failed",
            ),
            (
                "modify_error_recovery_prepare_before",
                "rejected before persistence",
            ),
            (
                "modify_error_recovery_prepare_after",
                "failed after persistence",
            ),
            ("unconfirmed_prepare_not_applied", "was not applied"),
            (
                "unconfirmed_prepare_live_status",
                "reported a live resize status",
            ),
            ("unconfirmed_not_applied", "was not applied"),
            ("unconfirmed_missing_row", "no memory resize status"),
            (
                "unconfirmed_duplicate_row",
                "more than one memory resize status",
            ),
            ("unconfirmed_out_of_range", "outside 512..=8192 MiB"),
        ];
        // The untouched capture passes. A suppressed category, a raised level or a lost
        // correlation fails the same validator: these are oracle controls, not production
        // switches.
        assert_eq!(
            validate_error_events(&events, "unit-test-sandbox", &expected),
            Ok(())
        );

        let mut suppressed = events.clone();
        suppressed.retain(|event| {
            !(event.fields.get("case_id").map(String::as_str) == Some("metrics_error")
                && is_error_event(event))
        });
        assert!(validate_error_events(&suppressed, "unit-test-sandbox", &expected).is_err());

        let mut raised = events.clone();
        for event in &mut raised {
            if event.fields.get("case_id").map(String::as_str) == Some("modify_error_live_apply")
                && is_error_event(event)
            {
                event.level = tracing::Level::INFO;
            }
        }
        assert!(validate_error_events(&raised, "unit-test-sandbox", &expected).is_err());

        for correlation in ["", "another-sandbox"] {
            let mut wrong = events.clone();
            for event in &mut wrong {
                if event.fields.get("case_id").map(String::as_str) == Some("metrics_missing")
                    && is_error_event(event)
                {
                    event
                        .fields
                        .insert("sandbox".to_string(), correlation.to_string());
                }
            }
            assert!(validate_error_events(&wrong, "unit-test-sandbox", &expected).is_err());
        }
        // Every diagnostic names its stage or reason, not merely "failed".
        for event in events.iter().filter(|event| is_error_event(event)) {
            let text = format!("{} {:?}", event.message, event.fields);
            assert!(
                [
                    "live_apply",
                    "recovery_prepare",
                    "metrics",
                    "observed",
                    "catalog",
                    "row"
                ]
                .iter()
                .any(|stage| text.contains(stage)),
                "diagnostic {text} names no stage"
            );
        }
    }

    #[tokio::test]
    async fn monitor_interval_waits_200ms_and_skips_missed_ticks() {
        tokio::time::pause();
        let reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = std::sync::Arc::clone(&reads);
        let mut stream = std::pin::pin!(memory_samples(move || {
            let counter = std::sync::Arc::clone(&counter);
            let index = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async move {
                if index == 1 {
                    // A slow read that overruns the next deadline.
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                Ok(None)
            }
        }));
        let count = |expected: usize| {
            assert_eq!(
                reads.load(std::sync::atomic::Ordering::SeqCst),
                expected,
                "read count"
            );
        };
        // No immediate first poll: the first read is one interval away.
        assert!(futures::poll!(futures::StreamExt::next(&mut stream)).is_pending());
        count(0);
        tokio::time::advance(Duration::from_millis(199)).await;
        assert!(futures::poll!(futures::StreamExt::next(&mut stream)).is_pending());
        count(0);
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(futures::StreamExt::next(&mut stream).await.is_some());
        count(1);
        // The next read is one interval away, not immediate.
        assert!(futures::poll!(futures::StreamExt::next(&mut stream)).is_pending());
        count(1);
        tokio::time::advance(Duration::from_millis(200)).await;
        // This read blocks for 500 ms, so the stream is pending until the clock moves.
        assert!(futures::poll!(futures::StreamExt::next(&mut stream)).is_pending());
        count(2);
        tokio::time::advance(Duration::from_millis(500)).await;
        assert!(futures::StreamExt::next(&mut stream).await.is_some());
        // Exactly one overdue tick is delivered immediately...
        assert!(futures::StreamExt::next(&mut stream).await.is_some());
        // ...and then the stream is pending until a future deadline instead of replaying
        // the missed intervals.
        assert!(futures::poll!(futures::StreamExt::next(&mut stream)).is_pending());
        let settled = reads.load(std::sync::atomic::Ordering::SeqCst);
        tokio::time::advance(Duration::from_millis(100)).await;
        assert!(futures::StreamExt::next(&mut stream).await.is_some());
        count(settled + 1);
        assert!(futures::poll!(futures::StreamExt::next(&mut stream)).is_pending());
        count(settled + 1);
    }

    #[test]
    fn monitor_spawn_predicate_covers_both_resource_axes() {
        let sizing = |boot_cpus, max_cpus, boot_memory_mib, max_memory_mib| {
            ResourceCeiling(Sizing {
                max_cpus,
                max_memory_mib,
                boot_cpus,
                boot_memory_mib,
            })
        };
        assert!(!sizing(1, 1, 512, 512).monitor_needed(), "nothing to scale");
        assert!(sizing(1, 2, 512, 512).monitor_needed(), "CPU-only spare");
        assert!(
            sizing(1, 1, 512, 8192).monitor_needed(),
            "memory-only spare"
        );
        assert!(sizing(1, 4, 512, 8192).monitor_needed(), "both spare");
        // Every production launch with a memory ceiling above the boot commitment starts
        // the task; `--memory 1` is not a no-resize axis.
        for gib in [1u32, 2, 8] {
            let ceiling = ResourceCeiling::from_launch_options(gib, 1).expect("accepted");
            assert!(ceiling.monitor_needed(), "{gib} GiB");
        }
    }

    struct DropReceipt(Option<tokio::sync::oneshot::Sender<()>>);

    impl DropReceipt {
        fn new(sender: tokio::sync::oneshot::Sender<()>) -> Self {
            Self(Some(sender))
        }
    }

    impl Drop for DropReceipt {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    #[tokio::test]
    async fn monitor_stop_joins_an_inflight_resize_and_is_idempotent() {
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (drop_tx, drop_rx) = tokio::sync::oneshot::channel();
        let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = std::sync::Arc::clone(&requests);
        let entered = std::sync::Mutex::new(Some(entered_tx));
        let task = tokio::spawn(async move {
            let _receipt = DropReceipt::new(drop_tx);
            drive_memory(
                adjustable(),
                confirmed(512, 0),
                futures::stream::iter(samples_of(&[(512, 400)])),
                move |_request| {
                    counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let signal = entered.lock().expect("entered lock").take();
                    async move {
                        if let Some(signal) = signal {
                            let _ = signal.send(());
                        }
                        std::future::pending::<()>().await;
                        unreachable!("the stalled resize never completes")
                    }
                },
            )
            .await;
        });
        entered_rx.await.expect("the resize was entered");
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 1);
        let monitor = ResourceMonitor::from_task_for_tests(task);
        tokio::time::timeout(Duration::from_secs(5), monitor.stop())
            .await
            .expect("stop returns after the stalled resize");
        drop_rx
            .await
            .expect("the task was destroyed before stop returned");
        assert!(!monitor.retains_task().await);
        monitor.stop().await;
        assert_eq!(
            requests.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "an abandoned monitor issues no further resize"
        );
    }

    #[tokio::test]
    async fn monitor_cancellation_after_prepare_preserves_saved_seed() {
        let bounds = adjustable();
        let vm = FakeVm::new(512, 1024);
        let (persisted_tx, persisted_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        {
            let mut state = vm.state.lock().unwrap();
            state.prepare_persisted = Some(persisted_tx);
            state.prepare_release = Some(release_rx);
        }
        let (drop_tx, drop_rx) = tokio::sync::oneshot::channel();
        let driven = std::sync::Arc::clone(&vm);
        let task = tokio::spawn(async move {
            let _receipt = DropReceipt::new(drop_tx);
            drive_fake(
                bounds,
                recovering(512, 0, 1024),
                samples_of(&[(512, 400)]),
                driven,
            )
            .await;
        });
        persisted_rx.await.expect("the seed was persisted");
        let monitor = ResourceMonitor::from_task_for_tests(task);
        monitor.stop().await;
        drop_rx.await.expect("the monitor's task is destroyed");
        // The deterministic window between persisting the seed and returning the prepare
        // plan: abort cannot roll the configuration write back, and no live seed was sent.
        assert_eq!(vm.sdk_actions(), vec![(MemoryApplyMode::NextStart, 640)]);
        assert!(vm.control_requests().is_empty());
        assert_eq!(vm.snapshot(), (512, 512, 640));
        drop(release_tx);
    }

    #[tokio::test]
    async fn cancelled_monitor_stop_retains_the_join_handle() {
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (drop_tx, drop_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _receipt = DropReceipt::new(drop_tx);
            let _ = entered_tx.send(());
            std::future::pending::<()>().await;
        });
        entered_rx.await.expect("the task started");
        let monitor = ResourceMonitor::from_task_for_tests(task);
        {
            let stopping = monitor.stop();
            let mut stopping = std::pin::pin!(stopping);
            // One poll requests the abort and reaches the join, which cannot complete
            // until the runtime schedules the task's destruction.
            assert!(futures::poll!(&mut stopping).is_pending());
        }
        assert!(
            monitor.retains_task().await,
            "a cancelled stop must leave the handle for a later hook"
        );
        monitor.stop().await;
        drop_rx.await.expect("the second stop joined the task");
        assert!(!monitor.retains_task().await);
    }

    #[tokio::test]
    async fn dropping_monitor_aborts_its_task() {
        let consumed = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (drop_tx, drop_rx) = tokio::sync::oneshot::channel();
        let (item_tx, mut item_rx) = tokio::sync::mpsc::channel::<()>(4);
        let counted = std::sync::Arc::clone(&consumed);
        let task = tokio::spawn(async move {
            let _receipt = DropReceipt::new(drop_tx);
            let mut entered = Some(entered_tx);
            while item_rx.recv().await.is_some() {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if let Some(signal) = entered.take() {
                    let _ = signal.send(());
                }
            }
        });
        item_tx.send(()).await.expect("an item");
        entered_rx.await.expect("the task started");
        assert_eq!(consumed.load(std::sync::atomic::Ordering::SeqCst), 1);
        let monitor = ResourceMonitor::from_task_for_tests(task);
        drop(monitor);
        drop_rx.await.expect("the aborted task was destroyed");
        // A late item cannot be consumed, and the channel says so: the task is gone
        // rather than merely unobserved.
        assert!(item_tx.send(()).await.is_err());
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert_eq!(consumed.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
