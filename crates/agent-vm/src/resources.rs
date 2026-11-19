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

// ADR-0070 D5 (#647): the CPU axis. `cpu_percent` counts one core per 100 (issue #647
// S-A/S-B, accepted evidence M2), so saturation of `C` committed vCPUs is measured at
// `C * 95%` and reclamation at `(C - 1) * 85%`. Both thresholds are compared on
// conservative integer tenths intervals, never on a rounded float.

/// Saturation of one committed vCPU, in tenths of a percent.
const CPU_UP_TENTHS_PER_CORE: u32 = 950;
/// The scale-down threshold of one *released* vCPU, in tenths of a percent.
const CPU_DOWN_TENTHS_PER_CORE: u32 = 850;
/// Distinct saturated observations behind one upward step (nominal 2 s at 200 ms).
const CPU_HIGH_TICKS: u32 = 10;
/// Distinct low observations behind one downward step (nominal 1 s at 200 ms).
const CPU_LOW_TICKS: u32 = 5;
/// `255 CPUs * 100% * 10`: the largest rate any comparison can reach.
const MAX_CPU_RATE_TENTHS: u32 = 255_000;
/// `25500.0f32` in IEEE-754 bits — 255 vCPUs under full load, in tenths.
const CPU_RATE_CAP_BITS: u32 = 0x46c7_3800;

/// The CPU interval a session may move within: `1 ..= max_cpus`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CpuBounds { boot_cpus: u8, max_cpus: u8 }

/// A CPU target and the counts of consecutive higher/lower-demand observations.
///
/// [`cpu_tick`] returns a **proposal**; only the driver that decoded a receipt may treat
/// a target as accepted, so this type never claims a resize happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CpuState { current_cpus: u8, high_ticks: u32, low_ticks: u32 }

/// A measured rate as the conservative tenths interval `[floor(10r), ceil(10r)]`.
///
/// Scaling up uses the lower endpoint and scaling down the upper one, so a reported
/// `94.999%` cannot round into saturation and `85.001%` cannot round into low load.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CpuRate { lower_tenths: u32, upper_tenths: u32 }

spec fn spec_cpu_rate_lo(numerator: int, denominator: int) -> int {
    if numerator / denominator > MAX_CPU_RATE_TENTHS as int {
        MAX_CPU_RATE_TENTHS as int
    } else {
        numerator / denominator
    }
}

spec fn spec_cpu_rate_hi(numerator: int, denominator: int) -> int {
    let quotient = numerator / denominator;
    let rounded = if numerator % denominator != 0 { quotient + 1 } else { quotient };
    if rounded > MAX_CPU_RATE_TENTHS as int { MAX_CPU_RATE_TENTHS as int } else { rounded }
}

/// Floor and ceiling of an already-scaled ratio, clamped to the largest meaningful rate.
///
/// A zero numerator or denominator has no defined rate and is `None` by specification,
/// not by a division precondition. Every intermediate is widened to `u64`, so the
/// statements hold for all `u32` inputs.
fn cpu_rate_tenths(numerator: u32, denominator: u32) -> (r: Option<CpuRate>)
    ensures
        match r {
            Some(rate) => {
                &&& numerator != 0 && denominator != 0
                &&& rate.lower_tenths as int == spec_cpu_rate_lo(numerator as int, denominator as int)
                &&& rate.upper_tenths as int == spec_cpu_rate_hi(numerator as int, denominator as int)
                &&& 0 <= rate.lower_tenths as int
                &&& (rate.lower_tenths as int) <= (rate.upper_tenths as int)
                &&& (rate.upper_tenths as int) <= MAX_CPU_RATE_TENTHS as int
                &&& (rate.upper_tenths as int) - (rate.lower_tenths as int) <= 1
                &&& rate.upper_tenths > 0
            },
        None => numerator == 0 || denominator == 0,
    },
{
    if numerator == 0 || denominator == 0 {
        return None;
    }
    let quotient = u64::from(numerator) / u64::from(denominator);
    let remainder = u64::from(numerator) % u64::from(denominator);
    let rounded = if remainder != 0 { quotient + 1 } else { quotient };
    let cap = u64::from(MAX_CPU_RATE_TENTHS);
    proof {
        assert(quotient as int == (numerator as int) / (denominator as int));
        assert(remainder as int == (numerator as int) % (denominator as int));
    }
    let lower = if quotient > cap { MAX_CPU_RATE_TENTHS } else { quotient as u32 };
    let upper = if rounded > cap { MAX_CPU_RATE_TENTHS } else { rounded as u32 };
    proof {
        assert(0 < numerator as int && 0 < denominator as int);
        assert(numerator as int / denominator as int >= 0);
        assert(numerator as int % denominator as int >= 0);
        if quotient == 0 {
            // A positive numerator below the denominator leaves its own remainder, so the
            // ceiling of a sub-unit ratio is one tenth, never zero.
            vstd::arithmetic::div_mod::lemma_small_div_converse(
                numerator as int,
                denominator as int,
            );
            assert((numerator as int) < (denominator as int));
            vstd::arithmetic::div_mod::lemma_small_mod(
                numerator as nat,
                denominator as nat,
            );
            assert((numerator as int) % (denominator as int) == numerator as int);
            assert(remainder != 0);
        }
    }
    proof {
        assert(lower as int == spec_cpu_rate_lo(numerator as int, denominator as int));
        assert(upper as int == spec_cpu_rate_hi(numerator as int, denominator as int));
        assert(upper > 0);
    }
    Some(CpuRate { lower_tenths: lower, upper_tenths: upper })
}

spec fn cpu_bits_exp(bits: u32) -> u32 { (bits >> 23) & 0xff }

spec fn cpu_bits_frac(bits: u32) -> u32 { bits & 0x7f_ffff }

/// `150 - exponent`, the right shift that scales the significand to an integer
/// significand of the value in tenths of a percent. Zero for exponents at or above 150,
/// which the rational branch never reaches.
///
/// `1.0f32` is `0x3f800000`; its value is `significand / 2^23`, and the tenths numerator is
/// `significand * 10`, so the denominator is `2^(127 + 23 - exponent)`.
spec fn cpu_bits_shift(bits: u32) -> u32 {
    if cpu_bits_exp(bits) >= 150 { 0 } else { (150 - cpu_bits_exp(bits) as int) as u32 }
}

spec fn cpu_bits_significand(bits: u32) -> int {
    0x800000int + cpu_bits_frac(bits) as int
}

spec fn cpu_bits_numerator(bits: u32) -> int { cpu_bits_significand(bits) * 10 }

spec fn cpu_bits_denominator(bits: u32) -> int { (1u32 << cpu_bits_shift(bits)) as int }

/// Positive values at or below about 0.1%: subnormals and every normal whose shift is at
/// least 32. They are a real observation of a small positive rate, not an absence.
spec fn cpu_bits_tiny(bits: u32) -> bool {
    cpu_bits_exp(bits) == 0 || cpu_bits_shift(bits) >= 32
}

/// Sign set (including `-0`), `NaN`/infinity, or `+0`: no rate was measured.
spec fn cpu_bits_rejected(bits: u32) -> bool {
    bits >> 31 != 0 || cpu_bits_exp(bits) == 255 || bits == 0
}

spec fn cpu_rate_from_bits_lo_spec(bits: u32) -> int {
    if bits >= CPU_RATE_CAP_BITS {
        MAX_CPU_RATE_TENTHS as int
    } else if cpu_bits_tiny(bits) {
        0
    } else {
        spec_cpu_rate_lo(cpu_bits_numerator(bits), cpu_bits_denominator(bits))
    }
}

spec fn cpu_rate_from_bits_hi_spec(bits: u32) -> int {
    if bits >= CPU_RATE_CAP_BITS {
        MAX_CPU_RATE_TENTHS as int
    } else if cpu_bits_tiny(bits) {
        1
    } else {
        spec_cpu_rate_hi(cpu_bits_numerator(bits), cpu_bits_denominator(bits))
    }
}

/// ADR-0070 D5: the proved IEEE-754 bit classification behind [`cpu_rate_of`].
///
/// The mapping is the one *specified* in the plan, not merely output bounds: reject the
/// sign bit, an all-ones exponent and `+0`; saturate at `25500%`; report positive tiny
/// values as `[0,1]`; otherwise divide the exact significand by the exact power of two.
/// The meaning of `f32::to_bits` and of the SDK's percentage field stay trusted.
fn cpu_rate_from_bits(bits: u32) -> (r: Option<CpuRate>)
    ensures
        match r {
            Some(rate) => {
                &&& !cpu_bits_rejected(bits)
                &&& rate.lower_tenths as int == cpu_rate_from_bits_lo_spec(bits)
                &&& rate.upper_tenths as int == cpu_rate_from_bits_hi_spec(bits)
                &&& 0 <= rate.lower_tenths as int
                &&& (rate.lower_tenths as int) <= (rate.upper_tenths as int)
                &&& (rate.upper_tenths as int) <= MAX_CPU_RATE_TENTHS as int
                &&& (rate.upper_tenths as int) - (rate.lower_tenths as int) <= 1
                &&& rate.upper_tenths > 0
            },
            None => cpu_bits_rejected(bits),
        },
        cpu_bits_rejected(bits) ==> match r { None => true, Some(_) => false },
        (bits >= CPU_RATE_CAP_BITS && !cpu_bits_rejected(bits)) ==> match r {
            Some(rate) => rate.lower_tenths == MAX_CPU_RATE_TENTHS
                && rate.upper_tenths == MAX_CPU_RATE_TENTHS,
            None => false,
        },
        (bits < CPU_RATE_CAP_BITS && !cpu_bits_rejected(bits) && cpu_bits_tiny(bits)) ==> match r {
            Some(rate) => rate.lower_tenths == 0 && rate.upper_tenths == 1,
            None => false,
        },
{
    let sign = bits >> 31;
    let exponent = (bits >> 23) & 0xff;
    if sign != 0 || exponent == 255 || bits == 0 {
        return None;
    }
    proof {
        assert(exponent == cpu_bits_exp(bits));
    }
    if bits >= CPU_RATE_CAP_BITS {
        return Some(CpuRate {
            lower_tenths: MAX_CPU_RATE_TENTHS,
            upper_tenths: MAX_CPU_RATE_TENTHS,
        });
    }
    proof {
        // A rate below `25500%` has an exponent of at most 141.
        assert((bits < CPU_RATE_CAP_BITS ==> ((bits >> 23) & 0xff) <= 141u32)) by (bit_vector);
    }
    let shift = 150u32.saturating_sub(exponent);
    proof {
        assert(shift == cpu_bits_shift(bits));
    }
    if shift >= 32 {
        return Some(CpuRate { lower_tenths: 0, upper_tenths: 1 });
    }
    proof {
        // The early return above is the only reason the shift fits a `u32` shift operand.
        assert(shift < 32);
        assert((0x0080_0000u64 + ((bits & 0x7f_ffff) as u64)) <= 0x00ff_ffffu64) by (bit_vector);
    }
    let significand: u64 = 0x0080_0000u64 + (bits & 0x7f_ffff) as u64;
    proof {
        assert(significand as int == cpu_bits_significand(bits));
    }
    proof {
        assert(((0x0080_0000u64 + ((bits & 0x7f_ffff) as u64)) * 10u64) <= 167772150u64)
            by (bit_vector);
    }
    let numerator: u64 = significand * 10;
    proof {
        assert(numerator as int == cpu_bits_numerator(bits));
    }
    let numerator = numerator as u32;
    proof {
        assert(numerator as int == cpu_bits_numerator(bits));
        assert(numerator != 0);
    }
    proof {
        assert((shift < 32u32 ==> (1u32 << shift) != 0u32)) by (bit_vector);
    }
    let denominator = 1u32 << shift;
    proof {
        assert(denominator as int == cpu_bits_denominator(bits));
        assert(denominator != 0);
    }
    cpu_rate_tenths(numerator, denominator)
}

/// The CPU interval test every accepted, seeded and proposed target goes through.
spec fn cpu_target_in_bounds_spec(bounds: CpuBounds, target: u8) -> bool {
    &&& 1 <= bounds.boot_cpus as int
    &&& (bounds.boot_cpus as int) <= (target as int)
    &&& (target as int) <= (bounds.max_cpus as int)
}

fn cpu_target_in_bounds(bounds: CpuBounds, target: u8) -> (accepted: bool)
    ensures accepted == cpu_target_in_bounds_spec(bounds, target),
{
    bounds.boot_cpus >= 1 && bounds.boot_cpus <= target && target <= bounds.max_cpus
}

spec fn cpu_bounds_valid(bounds: CpuBounds) -> bool {
    1 <= bounds.boot_cpus as int && (bounds.boot_cpus as int) <= (bounds.max_cpus as int)
}

/// The baseline the next decision is measured from: the current value clamped into valid
/// bounds, or the boot commitment when the bounds themselves are malformed.
spec fn cpu_base(bounds: CpuBounds, state: CpuState) -> int {
    if !cpu_bounds_valid(bounds) {
        bounds.boot_cpus as int
    } else if (state.current_cpus as int) < (bounds.boot_cpus as int) {
        bounds.boot_cpus as int
    } else if (state.current_cpus as int) > (bounds.max_cpus as int) {
        bounds.max_cpus as int
    } else {
        state.current_cpus as int
    }
}

spec fn cpu_high_run(state: CpuState) -> int {
    if (state.high_ticks as int) > CPU_HIGH_TICKS as int - 1 {
        CPU_HIGH_TICKS as int - 1
    } else {
        state.high_ticks as int
    }
}

spec fn cpu_low_run(state: CpuState) -> int {
    if (state.low_ticks as int) > CPU_LOW_TICKS as int - 1 {
        CPU_LOW_TICKS as int - 1
    } else {
        state.low_ticks as int
    }
}

/// `[lo, hi]` is a real observation only in this shape. An interval that is reversed,
/// out of range, wider than one tenth, or entirely zero is no observation at all.
spec fn cpu_rate_usable(rate: CpuRate) -> bool {
    &&& (rate.lower_tenths as int) >= 0
    &&& (rate.lower_tenths as int) <= (rate.upper_tenths as int)
    &&& (rate.upper_tenths as int) <= MAX_CPU_RATE_TENTHS as int
    &&& (rate.upper_tenths as int) - (rate.lower_tenths as int) <= 1
    &&& rate.upper_tenths > 0
}

spec fn cpu_current_outside(bounds: CpuBounds, state: CpuState) -> bool {
    (state.current_cpus as int) < (bounds.boot_cpus as int)
        || (state.current_cpus as int) > (bounds.max_cpus as int)
}

spec fn cpu_high_condition(bounds: CpuBounds, state: CpuState, rate: CpuRate) -> bool {
    &&& cpu_base(bounds, state) < (bounds.max_cpus as int)
    &&& (rate.lower_tenths as int) >= (CPU_UP_TENTHS_PER_CORE as int) * cpu_base(bounds, state)
}

spec fn cpu_low_condition(bounds: CpuBounds, state: CpuState, rate: CpuRate) -> bool {
    &&& cpu_base(bounds, state) > (bounds.boot_cpus as int)
    &&& (rate.upper_tenths as int) <= (CPU_DOWN_TENTHS_PER_CORE as int) * (cpu_base(bounds, state) - 1)
}

spec fn cpu_tick_current_spec(bounds: CpuBounds, state: CpuState, rate: Option<CpuRate>) -> int {
    if !cpu_bounds_valid(bounds) {
        bounds.boot_cpus as int
    } else if cpu_current_outside(bounds, state) {
        cpu_base(bounds, state)
    } else {
        match rate {
            None => cpu_base(bounds, state),
            Some(measured) => {
                if !cpu_rate_usable(measured) {
                    cpu_base(bounds, state)
                } else if cpu_high_condition(bounds, state, measured) {
                    if cpu_high_run(state) < CPU_HIGH_TICKS as int - 1 {
                        cpu_base(bounds, state)
                    } else {
                        cpu_base(bounds, state) + 1
                    }
                } else if cpu_low_condition(bounds, state, measured) {
                    if cpu_low_run(state) < CPU_LOW_TICKS as int - 1 {
                        cpu_base(bounds, state)
                    } else {
                        cpu_base(bounds, state) - 1
                    }
                } else {
                    cpu_base(bounds, state)
                }
            },
        }
    }
}

spec fn cpu_tick_high_spec(bounds: CpuBounds, state: CpuState, rate: Option<CpuRate>) -> int {
    if !cpu_bounds_valid(bounds) {
        0
    } else if cpu_current_outside(bounds, state) {
        0
    } else {
        match rate {
            None => 0,
            Some(measured) => {
                if cpu_rate_usable(measured)
                    && cpu_high_condition(bounds, state, measured)
                    && cpu_high_run(state) < CPU_HIGH_TICKS as int - 1
                {
                    cpu_high_run(state) + 1
                } else {
                    0
                }
            },
        }
    }
}

spec fn cpu_tick_low_spec(bounds: CpuBounds, state: CpuState, rate: Option<CpuRate>) -> int {
    if !cpu_bounds_valid(bounds) {
        0
    } else if cpu_current_outside(bounds, state) {
        0
    } else {
        match rate {
            None => 0,
            Some(measured) => {
                if cpu_rate_usable(measured)
                    && !cpu_high_condition(bounds, state, measured)
                    && cpu_low_condition(bounds, state, measured)
                    && cpu_low_run(state) < CPU_LOW_TICKS as int - 1
                {
                    cpu_low_run(state) + 1
                } else {
                    0
                }
            },
        }
    }
}

/// ADR-0070 D5: one distinct demand-eligible observation of the CPU hysteresis.
///
/// One invocation is one *distinct* observation (S-F): a duplicate poll never calls this
/// kernel, and an absent or unusable rate calls its reset path. Recovery deliberately does
/// not call it at all. The ordered rows are the plan's transition table: invalid bounds,
/// a current value outside the interval, an unusable rate, then the high run, the low run
/// and finally every floor- or ceiling-inhibited hold.
fn cpu_tick(bounds: CpuBounds, state: CpuState, rate: Option<CpuRate>) -> (next: CpuState)
    ensures
        next.current_cpus as int == cpu_tick_current_spec(bounds, state, rate),
        next.high_ticks as int == cpu_tick_high_spec(bounds, state, rate),
        next.low_ticks as int == cpu_tick_low_spec(bounds, state, rate),
        next.high_ticks <= CPU_HIGH_TICKS - 1,
        next.low_ticks <= CPU_LOW_TICKS - 1,
        cpu_bounds_valid(bounds) ==> {
            &&& (bounds.boot_cpus as int) <= (next.current_cpus as int)
            &&& (next.current_cpus as int) <= (bounds.max_cpus as int)
        },
        cpu_bounds_valid(bounds) ==> (next.high_ticks == 0 || next.low_ticks == 0),
        (cpu_bounds_valid(bounds) && !cpu_current_outside(bounds, state)) ==> {
            &&& -1 <= (next.current_cpus as int) - (state.current_cpus as int)
            &&& (next.current_cpus as int) - (state.current_cpus as int) <= 1
        },
{
    if !(1 <= bounds.boot_cpus && bounds.boot_cpus <= bounds.max_cpus) {
        return CpuState { current_cpus: bounds.boot_cpus, high_ticks: 0, low_ticks: 0 };
    }
    let base = if state.current_cpus < bounds.boot_cpus {
        bounds.boot_cpus
    } else if state.current_cpus > bounds.max_cpus {
        bounds.max_cpus
    } else {
        state.current_cpus
    };
    proof {
        assert(base as int == cpu_base(bounds, state));
        assert(cpu_bounds_valid(bounds));
    }
    let hold = CpuState { current_cpus: base, high_ticks: 0, low_ticks: 0 };
    if state.current_cpus < bounds.boot_cpus || state.current_cpus > bounds.max_cpus {
        return hold;
    }
    let Some(measured) = rate else {
        return hold;
    };
    if !(measured.lower_tenths <= measured.upper_tenths
        && measured.upper_tenths <= MAX_CPU_RATE_TENTHS
        && measured.upper_tenths - measured.lower_tenths <= 1
        && measured.upper_tenths > 0)
    {
        return hold;
    }
    proof {
        assert(cpu_rate_usable(measured));
    }
    let high = if state.high_ticks > CPU_HIGH_TICKS - 1 { CPU_HIGH_TICKS - 1 } else { state.high_ticks };
    let low = if state.low_ticks > CPU_LOW_TICKS - 1 { CPU_LOW_TICKS - 1 } else { state.low_ticks };
    proof {
        assert(high as int == cpu_high_run(state));
        assert(low as int == cpu_low_run(state));
    }
    let base_cpus = u32::from(base);
    if base < bounds.max_cpus && measured.lower_tenths >= CPU_UP_TENTHS_PER_CORE * base_cpus {
        proof {
            assert(cpu_high_condition(bounds, state, measured));
            assert(CPU_UP_TENTHS_PER_CORE * base_cpus <= 950 * 255);
        }
        if high < CPU_HIGH_TICKS - 1 {
            return CpuState { current_cpus: base, high_ticks: high + 1, low_ticks: 0 };
        }
        return CpuState { current_cpus: base + 1, high_ticks: 0, low_ticks: 0 };
    }
    let released_cpus = base_cpus - 1;
    if base > bounds.boot_cpus && measured.upper_tenths <= CPU_DOWN_TENTHS_PER_CORE * released_cpus {
        proof {
            assert(cpu_low_condition(bounds, state, measured));
            assert(CPU_DOWN_TENTHS_PER_CORE * released_cpus <= 850 * 254);
        }
        if low < CPU_LOW_TICKS - 1 {
            return CpuState { current_cpus: base, high_ticks: 0, low_ticks: low + 1 };
        }
        return CpuState { current_cpus: base - 1, high_ticks: 0, low_ticks: 0 };
    }
    hold
}

spec fn cpu_seed_in_range(bounds: CpuBounds, target: u8) -> bool {
    cpu_target_in_bounds_spec(bounds, target)
}

spec fn cpu_recovery_seed_spec(bounds: CpuBounds, target_cpus: u8) -> Option<int> {
    if !cpu_seed_in_range(bounds, target_cpus) {
        None
    } else if bounds.boot_cpus != target_cpus {
        Some(bounds.boot_cpus as int)
    } else if (bounds.boot_cpus as int) + 1 <= (bounds.max_cpus as int) {
        Some(bounds.boot_cpus as int + 1)
    } else {
        None
    }
}

/// The configuration-repair value a Recovering CPU request saves before it live-applies.
///
/// `NextStart` cannot change live CPUs, so a seed that differs from the re-confirm target
/// is enough to make the following live apply a real planned change instead of an
/// applied-but-statusless equality no-op. The boot value is preferred; at the boot value
/// the next one up is the only other in-range choice, which is why the two-value interval
/// `1..=2` works for either target. It is a repair value, never a policy target.
fn cpu_recovery_seed(bounds: CpuBounds, target_cpus: u8) -> (seed: Option<u8>)
    ensures
        match seed {
            Some(chosen) => {
                &&& cpu_recovery_seed_spec(bounds, target_cpus) == Some::<int>(chosen as int)
                &&& cpu_target_in_bounds_spec(bounds, chosen)
                &&& chosen != target_cpus
            },
            None => cpu_recovery_seed_spec(bounds, target_cpus) == None,
        },
{
    if !cpu_target_in_bounds(bounds, target_cpus) {
        return None;
    }
    if bounds.boot_cpus != target_cpus {
        return Some(bounds.boot_cpus);
    }
    if bounds.boot_cpus < bounds.max_cpus {
        return Some(bounds.boot_cpus + 1);
    }
    None
}

} // verus!

/// Trusted adapter from the SDK's percentage to the proved integer interval.
///
/// The SDK field is a non-optional `f32` (`sandbox/metrics.rs:41-45`), so the only
/// "absence" this seam can express is a value that encodes none — `0.0` with either sign,
/// a `NaN`, or an infinity. The meaning of the float, its provenance and the delivery of a
/// genuine observation stay trusted; the bit classification and the arithmetic after it
/// are proved. `None` therefore means "no usable measurement", never "the guest is idle".
fn cpu_rate_of(percent: f32) -> Option<CpuRate> {
    cpu_rate_from_bits(percent.to_bits())
}

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

    fn cpu_bounds(&self) -> CpuBounds {
        let sizing = self.0;
        CpuBounds {
            boot_cpus: sizing.boot_cpus,
            max_cpus: sizing.max_cpus,
        }
    }

    fn resource_bounds(&self) -> ResourceBounds {
        ResourceBounds {
            cpu: self.cpu_bounds(),
            memory: self.memory_bounds(),
        }
    }

    /// Start the in-process resource monitor and hand back the only handle that stops it.
    ///
    /// One task owns both axes: one metrics read per tick, one serial apply owner. A session
    /// with no room on either axis never starts it.
    pub(crate) fn monitor(&self, sandbox: &microsandbox::Sandbox) -> ResourceMonitor {
        let span = tracing::debug_span!(
            target: "agent_vm::resources",
            "resource_commitment",
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
                    "resource monitor not started"
                )
            });
            return ResourceMonitor::idle(span);
        }
        let bounds = self.resource_bounds();
        let initial = ResourceControllerState {
            cpu: CpuControllerState {
                policy: CpuState {
                    current_cpus: bounds.cpu.boot_cpus,
                    high_ticks: 0,
                    low_ticks: 0,
                },
                authority: TargetAuthority::Confirmed,
                last_accepted_cpus: bounds.cpu.boot_cpus,
                outstanding: None,
                correction_retry: ResizeRetry::default(),
            },
            memory: MemoryControllerState {
                policy: MemoryState {
                    current_target_mib: bounds.memory.boot_memory_mib,
                    low_ticks: 0,
                },
                authority: TargetAuthority::Confirmed,
                last_accepted_target_mib: bounds.memory.boot_memory_mib,
                retry: MemoryRetry::default(),
            },
            cpu_clock: CpuObservationClock::default(),
            cpu_lifecycle: CpuLifecycleCache::default(),
        };
        let reader = sandbox.clone();
        let samples = resource_samples(move || {
            let sandbox = reader.clone();
            async move { read_resource_sample(&sandbox).await }
        });
        let modifier = sandbox.clone();
        let resize = move |request| {
            let sandbox = modifier.clone();
            async move { resize_resources(&sandbox, bounds, request).await }
        };
        let prober = sandbox.clone();
        let probe_lifecycle = move || {
            let sandbox = prober.clone();
            async move { read_cpu_lifecycle(&sandbox).await }
        };
        let driving = drive_resources(bounds, initial, samples, resize, probe_lifecycle);
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

/// Damping for an ask that is being repeated without effect, per axis.
///
/// Growth is immediate, so nothing else throttles a repeat: a persistent failure (host out of
/// memory, a runtime without live resize, a paused sandbox) or an `enforced` target below the
/// ask would be re-requested every 200 ms, at two SDK applies each. What is damped is the
/// **nth repeat of one identical ask**:
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
///
/// The storage is generic so both axes share one implementation. The *identity* each axis
/// supplies is not shared: memory compares [`MemoryAsk`] (authority-sensitive), while CPU
/// correction retries compare the stable target only, and CPU demand keeps its own record
/// ([`CpuOutstandingDemand`]) precisely so a correction can never clear it.
#[derive(Clone, Copy, PartialEq, Eq)]
struct ResizeRetry<A: Copy + Eq> {
    /// The ask that last made no progress. Taken, not merely compared, on the next admit, so a
    /// changed ask cannot inherit this count.
    failed: Option<A>,
    /// How many consecutive attempts at `failed` have made no progress.
    attempts: u32,
    /// Ticks observed since the last attempt at `failed`.
    waited: u32,
}

impl<A: Copy + Eq> Default for ResizeRetry<A> {
    fn default() -> Self {
        Self {
            failed: None,
            attempts: 0,
            waited: 0,
        }
    }
}

impl<A: Copy + Eq> std::fmt::Debug for ResizeRetry<A> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResizeRetry")
            .field("attempts", &self.attempts)
            .field("waited", &self.waited)
            .finish_non_exhaustive()
    }
}

impl<A: Copy + Eq> ResizeRetry<A> {
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
    fn admit(&mut self, ask: A) -> bool {
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
    fn damp(&mut self, ask: A) {
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

/// Memory's damping record: compared by the authority-sensitive [`MemoryAsk`] identity.
type MemoryRetry = ResizeRetry<MemoryAsk>;

/// One change the driver asks the SDK adapter for, on either axis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MemoryResizeRequest {
    baseline_mib: u32,
    target_mib: u32,
    recovering: bool,
}

/// `Live` sends runtime control; `NextStart` only persists desired configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResourceApplyMode {
    Live,
    NextStart,
}

/// A resize that did not produce an accepted target, split by what is known about the VM.
#[derive(Debug)]
enum ResourceResizeError {
    /// The apply call returned an error: the live effect is unknown, not absent.
    Modify(anyhow::Error),
    /// The call returned but its receipt was missing or unusable: also unknown.
    Unconfirmed(anyhow::Error),
}

impl ResourceResizeError {
    fn event(&self) -> &'static str {
        match self {
            ResourceResizeError::Modify(_) => "modify_error",
            ResourceResizeError::Unconfirmed(_) => "unconfirmed_resize_status",
        }
    }

    /// The whole anyhow chain, so the stage context and the underlying cause both appear.
    fn detail(&self) -> String {
        match self {
            ResourceResizeError::Modify(error) | ResourceResizeError::Unconfirmed(error) => {
                format!("{error:#}")
            }
        }
    }
}

/// Test-only spelling kept so the S2 memory tests read as they did.
#[cfg(test)]
type MemoryResizeError = ResourceResizeError;

/// The two-axis interval a session may move within.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ResourceBounds {
    cpu: CpuBounds,
    memory: MemoryBounds,
}

/// One change the CPU driver asks the adapter for.
///
/// `recovering` means authority is unknown, so the adapter repairs saved configuration before
/// it live-applies; `baseline_cpus` is what the driver believes is current, used only to report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CpuResizeRequest {
    baseline_cpus: u8,
    target_cpus: u8,
    recovering: bool,
}

/// Both axes' requests, so one live apply can carry whichever were admitted this tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ResourceResizeRequest {
    cpu: Option<CpuResizeRequest>,
    memory: Option<MemoryResizeRequest>,
}

/// The fields one SDK apply carries. `None` is "this axis is not in this call".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ResourceTargets {
    cpus: Option<u8>,
    memory_mib: Option<u32>,
}

/// Both axes' outcomes. `None` means **not requested**, never success.
#[derive(Debug)]
struct ResourceResizeOutcome {
    cpu: Option<Result<u8, ResourceResizeError>>,
    memory: Option<Result<u32, ResourceResizeError>>,
}

/// Which way an ask moves the commitment, independent of its target number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CpuDirection {
    Up,
    Down,
}

/// What the policy is asking for, as the durable part of an unmet demand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CpuDemand {
    target_cpus: u8,
    direction: CpuDirection,
}

/// A directional demand that has been asked for and not yet observed as progress.
///
/// This is deliberately **not** a [`ResizeRetry`]: its identity must survive a corrective
/// re-confirmation that returns enforcement to the baseline, because the guest still needs the
/// change. Only a usable receipt that moves enforcement toward the demand from `anchor_cpus`,
/// or genuinely new demand evidence, may clear it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CpuOutstandingDemand {
    demand: CpuDemand,
    /// The accepted commitment when this unmet demand began.
    anchor_cpus: u8,
    /// Normal demand attempts that produced no usable progress.
    no_progress_attempts: u32,
    /// Original monitor polls observed since the last normal demand attempt.
    waited_polls: u32,
}

/// The stable identity of a corrective re-confirmation: its target only.
///
/// Deliberately excludes the authority and the observed baseline, so repeated recovery failures
/// damp one identity instead of restarting the delay whenever a catalog or observation drifts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CpuCorrectionAsk {
    target_cpus: u8,
}

/// What the driver knows about the CPU axis between ticks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CpuControllerState {
    /// The accepted commitment under `Confirmed`; the last accepted value under `Recovering`
    /// (never a proposed target).
    policy: CpuState,
    authority: TargetAuthority,
    /// Receipt history only: never overwritten by an observation or by `actual`.
    last_accepted_cpus: u8,
    outstanding: Option<CpuOutstandingDemand>,
    correction_retry: ResizeRetry<CpuCorrectionAsk>,
}

/// Lifecycle eligibility for CPU work, separate from demand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CpuLifecycle {
    Running,
    NotRunning,
    Unavailable,
}

/// One metrics row as both policies see it: memory fields unchanged, plus the decoded rate and
/// the row's own timestamp. The reader never awaits a lifecycle query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ResourceSample {
    memory: MemorySample,
    /// The internal decoded interval, never the SDK's non-optional `f32` field type.
    cpu_rate: Option<CpuRate>,
    timestamp: std::time::SystemTime,
}

/// The nondecreasing-within-epoch high-water mark of row timestamps.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct CpuObservationClock {
    high_water: Option<std::time::SystemTime>,
    consecutive_regressed_polls: u32,
}

/// What one original poll's timestamp is relative to the epoch high-water mark.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CpuObservation {
    Distinct,
    Duplicate,
    Regressed,
    ClockCorrection,
    Gap,
}

/// The cached lifecycle answer and when its probe attempt started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CpuLifecycleCache {
    value: CpuLifecycle,
    /// Whether a reply has been cached at all. Invalidation clears this but keeps the probe
    /// start, so it can never become a probe storm.
    valid: bool,
    last_probe_started: Option<tokio::time::Instant>,
}

impl Default for CpuLifecycleCache {
    fn default() -> Self {
        Self {
            value: CpuLifecycle::Unavailable,
            valid: false,
            last_probe_started: None,
        }
    }
}

/// Everything the two-axis driver owns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ResourceControllerState {
    cpu: CpuControllerState,
    memory: MemoryControllerState,
    cpu_clock: CpuObservationClock,
    cpu_lifecycle: CpuLifecycleCache,
}

/// Nominal five ticks at [`METRICS_SAMPLE_INTERVAL`]: how long one lifecycle reply is reused.
const CPU_LIFECYCLE_TTL: Duration = Duration::from_secs(1);
/// The bound on one lifecycle query's await, not on metrics or apply I/O.
const CPU_LIFECYCLE_TIMEOUT: Duration = Duration::from_millis(50);
/// Consecutive timestamp-below-high-water polls that re-anchor the epoch (20 s nominal).
const CPU_REGRESSION_STREAK: u32 = 100;

/// The CPU delay before re-asking the same failing identity, in monitor polls.
///
/// Same 0/5..50 schedule as memory ([`MEMORY_RETRY_FIRST_TICKS`],
/// [`MEMORY_RETRY_MAX_TICKS`]); named here so the two axes can diverge only deliberately.
const CPU_RETRY_FIRST_TICKS: u32 = MEMORY_RETRY_FIRST_TICKS;
const CPU_RETRY_MAX_TICKS: u32 = MEMORY_RETRY_MAX_TICKS;

/// Classify one original poll's timestamp against the epoch high-water mark (plan §3.2).
///
/// The high-water never decreases inside an epoch. The sole exception is the operator-approved
/// clock correction after [`CPU_REGRESSION_STREAK`] consecutive regressed polls, which re-anchors
/// to this poll's timestamp and discards the row. An equal timestamp neither advances nor
/// lowers anything and interrupts the regression streak.
fn observe_cpu_clock(
    clock: &mut CpuObservationClock,
    timestamp: std::time::SystemTime,
) -> CpuObservation {
    match clock.high_water {
        None => {
            clock.high_water = Some(timestamp);
            clock.consecutive_regressed_polls = 0;
            CpuObservation::Distinct
        }
        Some(high_water) if timestamp > high_water => {
            clock.high_water = Some(timestamp);
            clock.consecutive_regressed_polls = 0;
            CpuObservation::Distinct
        }
        Some(high_water) if timestamp == high_water => {
            clock.consecutive_regressed_polls = 0;
            CpuObservation::Duplicate
        }
        Some(_) => {
            clock.consecutive_regressed_polls = clock.consecutive_regressed_polls.saturating_add(1);
            if clock.consecutive_regressed_polls >= CPU_REGRESSION_STREAK {
                clock.high_water = Some(timestamp);
                clock.consecutive_regressed_polls = 0;
                CpuObservation::ClockCorrection
            } else {
                CpuObservation::Regressed
            }
        }
    }
}

/// A usable measured rate is a real observation of demand: ordered, at most one tenth wide and
/// strictly positive. Zero/absent encodes no decision (S-B). This is the shell's restatement of
/// the proved `cpu_rate_usable` predicate over the decoded interval.
fn measured_rate_is_usable(rate: CpuRate) -> bool {
    rate.lower_tenths <= rate.upper_tenths
        && rate.upper_tenths <= MAX_CPU_RATE_TENTHS
        && rate.upper_tenths - rate.lower_tenths <= 1
        && rate.upper_tenths > 0
}

fn cpu_bounds_adjustable(bounds: CpuBounds) -> bool {
    bounds.boot_cpus < bounds.max_cpus
}

/// The delay before repeating one CPU identity, from its consecutive no-progress attempts.
fn cpu_retry_delay(attempts: u32) -> u32 {
    if attempts <= 1 {
        return 0;
    }
    (attempts - 1)
        .saturating_mul(CPU_RETRY_FIRST_TICKS)
        .min(CPU_RETRY_MAX_TICKS)
}

/// Whether a usable receipt moved enforcement toward (or past) the recorded demand.
fn cpu_demand_met(demand: CpuOutstandingDemand, enforced_cpus: u8) -> bool {
    match demand.demand.direction {
        CpuDirection::Up => enforced_cpus > demand.anchor_cpus,
        CpuDirection::Down => enforced_cpus < demand.anchor_cpus,
    }
}

/// Whether one positive distinct eligible observation still supports a recorded direction.
///
/// The kernel holds in four ways: below the growth threshold, at the ceiling, above the shrink
/// threshold and at the floor. Plan §3.4(b) ends an outstanding demand when the evidence becomes
/// a deadband or a boundary hold, and keeps it while the same direction continues — including
/// the retry-gated case, where the kernel proposes the step but the deadline refuses to ask.
fn cpu_hold_supports(
    direction: CpuDirection,
    bounds: CpuBounds,
    current_cpus: u8,
    rate: CpuRate,
) -> bool {
    match direction {
        // Growth continues while the conservative lower endpoint still reaches the threshold
        // and the session still has room above the current commitment.
        CpuDirection::Up => {
            current_cpus < bounds.max_cpus
                && rate.lower_tenths >= CPU_UP_TENTHS_PER_CORE * u32::from(current_cpus)
        }
        // Reclamation continues while the upper endpoint still reaches the threshold of the
        // vCPU about to be released and something above the floor remains to reclaim.
        CpuDirection::Down => {
            current_cpus > bounds.boot_cpus
                && rate.upper_tenths <= CPU_DOWN_TENTHS_PER_CORE * u32::from(current_cpus - 1)
        }
    }
}

/// ADR-0070 D2/D3/D5: one sample stream through both policies, holding the authority, the
/// observation clock and the lifecycle cache that the pure kernels cannot see.
///
/// One task, one read per tick and at most one live apply: the launcher's whole interface stays
/// [`ResourceCeiling::monitor`]. Errors are handled here and never returned, so a finite test
/// stream asserts the exact final state.
///
/// The tick order is load-bearing:
/// 1. advance the memory retry, CPU demand and CPU correction clocks once per original poll;
/// 2. handle a shared absence or lookup error without touching either axis's history;
/// 3. evaluate memory from the row immediately — it never awaits a lifecycle query;
/// 4. classify the CPU clock before any lifecycle or demand work;
/// 5. give an admitted memory request priority over a lifecycle await, and defer CPU;
/// 6. evaluate CPU demand, or rate-independent corrective confirmation;
/// 7. await one shared resize, then settle each axis and, separately, outstanding demand.
async fn drive_resources<S, R, F, L, LF>(
    bounds: ResourceBounds,
    state: ResourceControllerState,
    samples: S,
    mut resize: R,
    mut probe_lifecycle: L,
) -> ResourceControllerState
where
    S: futures::Stream<Item = anyhow::Result<Option<ResourceSample>>>,
    R: FnMut(ResourceResizeRequest) -> F,
    F: std::future::Future<Output = ResourceResizeOutcome>,
    L: FnMut() -> LF,
    LF: std::future::Future<Output = anyhow::Result<CpuLifecycle>>,
{
    let mut state = state;
    let mut samples = std::pin::pin!(samples);
    while let Some(item) = futures::StreamExt::next(&mut samples).await {
        // (1) Every item is one monitor poll, whatever it carries: both retry delays and the
        // demand deadline are measured in opportunities to observe, not wall-clock time.
        if state.memory.retry.failed.is_some() {
            state.memory.retry.waited = state.memory.retry.waited.saturating_add(1);
        }
        if let Some(outstanding) = state.cpu.outstanding.as_mut() {
            outstanding.waited_polls = outstanding.waited_polls.saturating_add(1);
        }
        if state.cpu.correction_retry.failed.is_some() {
            state.cpu.correction_retry.waited = state.cpu.correction_retry.waited.saturating_add(1);
        }

        // (2) One shared read: an absent row or a lookup error is a CPU gap and a memory hold.
        let sample = match item {
            Ok(Some(sample)) => sample,
            Ok(None) => {
                let observation = CpuObservation::Gap;
                log_cpu_poll(
                    observation,
                    None,
                    state.cpu_lifecycle,
                    state.cpu.policy,
                    state.cpu.outstanding,
                    false,
                    None,
                    false,
                );
                tracing::debug!(
                    target: MONITOR_TARGET,
                    event = "metrics_missing",
                    observation = ?observation,
                    reason = "the metrics catalog has no live row for this sandbox yet",
                    "resource sample missing"
                );
                reset_cpu_evidence(&mut state.cpu);
                state.cpu_clock.consecutive_regressed_polls = 0;
                state.memory.policy.low_ticks = 0;
                continue;
            }
            Err(error) => {
                let observation = CpuObservation::Gap;
                log_cpu_poll(
                    observation,
                    None,
                    state.cpu_lifecycle,
                    state.cpu.policy,
                    state.cpu.outstanding,
                    false,
                    None,
                    false,
                );
                tracing::debug!(
                    target: MONITOR_TARGET,
                    event = "metrics_error",
                    observation = ?observation,
                    error = %format!("{error:#}"),
                    "resource metrics lookup failed"
                );
                reset_cpu_evidence(&mut state.cpu);
                state.cpu_clock.consecutive_regressed_polls = 0;
                state.memory.policy.low_ticks = 0;
                continue;
            }
        };

        // (3) Memory first, from this row only. A CPU eligibility wait never delays it.
        let mut memory_request: Option<MemoryResizeRequest> = None;
        let mut memory_ask: Option<MemoryAsk> = None;
        let recovering_memory = state.memory.authority == TargetAuthority::Recovering;
        let mut memory_rebasable = true;
        let observed = if recovering_memory {
            match observed_memory_target(bounds.memory, sample.memory.memory_limit_bytes) {
                Ok(observed) => Some(observed),
                Err(error) => {
                    tracing::debug!(
                        target: MONITOR_TARGET,
                        event = "invalid_recovery_limit",
                        error = %format!("{error:#}"),
                        last_accepted_target_mib = state.memory.last_accepted_target_mib,
                        "memory recovery baseline unusable; holding"
                    );
                    state.memory.policy =
                        memory_rebase(bounds.memory, state.memory.policy, true, None);
                    memory_rebasable = false;
                    None
                }
            }
        } else {
            None
        };
        if memory_rebasable {
            let previous_mib = state.memory.policy.current_target_mib;
            state.memory.policy = memory_rebase(
                bounds.memory,
                state.memory.policy,
                recovering_memory,
                observed,
            );
            if let Some(observed_mib) = observed
                && observed_mib != previous_mib
            {
                tracing::debug!(
                    target: MONITOR_TARGET,
                    event = "memory_reconciled",
                    observed_limit_mib = observed_mib,
                    last_accepted_target_mib = state.memory.last_accepted_target_mib,
                    "recovery baseline moved to the observed live limit"
                );
            }
            let baseline_mib = state.memory.policy.current_target_mib;
            let proposal = memory_tick(bounds.memory, state.memory.policy, sample.memory);
            if proposal.current_target_mib == baseline_mib {
                state.memory.policy.low_ticks = proposal.low_ticks;
            } else {
                let request = MemoryResizeRequest {
                    baseline_mib,
                    target_mib: proposal.current_target_mib,
                    recovering: recovering_memory,
                };
                let ask = MemoryAsk::of(request);
                if state.memory.retry.admit(ask) {
                    memory_request = Some(request);
                    memory_ask = Some(ask);
                } else {
                    // A repeat of an ask that made no progress: hold its dwell unchanged.
                    state.memory.policy.low_ticks = proposal.low_ticks;
                }
            }
        }

        // (4) The CPU clock is classified before any lifecycle or demand work.
        let observation = observe_cpu_clock(&mut state.cpu_clock, sample.timestamp);
        let usable_rate = sample
            .cpu_rate
            .filter(|rate| measured_rate_is_usable(*rate));
        let mut cpu_request: Option<CpuResizeRequest> = None;
        let mut deferred = false;
        match observation {
            CpuObservation::Duplicate => {
                // Neutral: no count, no dispatch, no probe. Merely expiring the cache changes
                // nothing; only an unusable rate resets the preserved runs.
                if usable_rate.is_none() {
                    reset_cpu_evidence(&mut state.cpu);
                }
                tracing::debug!(
                    target: MONITOR_TARGET,
                    event = "cpu_duplicate_observation",
                    high_ticks = state.cpu.policy.high_ticks,
                    low_ticks = state.cpu.policy.low_ticks,
                    "duplicate CPU row: no evidence, no call"
                );
            }
            CpuObservation::Regressed => {
                reset_cpu_evidence(&mut state.cpu);
                tracing::debug!(
                    target: MONITOR_TARGET,
                    event = "cpu_regressed_observation",
                    consecutive_regressed_polls = state.cpu_clock.consecutive_regressed_polls,
                    "timestamp below the high-water mark: no evidence, no call"
                );
            }
            CpuObservation::ClockCorrection => {
                reset_cpu_evidence(&mut state.cpu);
                state.cpu_lifecycle.valid = false;
                tracing::debug!(
                    target: MONITOR_TARGET,
                    event = "cpu_clock_correction",
                    "sustained regression re-anchored the epoch and discarded the row"
                );
            }
            CpuObservation::Gap => {}
            CpuObservation::Distinct => {
                // (5) Only a distinct row can produce CPU evidence.
                let adjustable = cpu_bounds_adjustable(bounds.cpu);
                let needs_lifecycle = adjustable
                    && match state.cpu.authority {
                        TargetAuthority::Confirmed => usable_rate.is_some(),
                        TargetAuthority::Recovering => true,
                    };
                if needs_lifecycle && !cpu_lifecycle_fresh(&state.cpu_lifecycle, now_instant()) {
                    if memory_request.is_some() {
                        // Memory priority: an urgent growth or reversal is dispatched now, and
                        // CPU waits for a later poll. Eligibility was unavailable, so its runs
                        // reset; recovery, demand and deadlines are retained.
                        deferred = true;
                        reset_cpu_evidence(&mut state.cpu);
                        tracing::debug!(
                            target: MONITOR_TARGET,
                            event = "cpu_lifecycle_deferred",
                            reason = "an admitted memory request has dispatch priority",
                            "CPU deferred instead of probing lifecycle"
                        );
                    } else if cpu_probe_allowed(&state.cpu_lifecycle, now_instant()) {
                        refresh_cpu_lifecycle(
                            &mut state.cpu_lifecycle,
                            &mut probe_lifecycle,
                            now_instant(),
                        )
                        .await;
                    }
                }
                let eligible = !deferred
                    && cpu_lifecycle_fresh(&state.cpu_lifecycle, now_instant())
                    && state.cpu_lifecycle.value == CpuLifecycle::Running;
                if !eligible {
                    // NotRunning, Unavailable, or no decision needed this poll.
                    reset_cpu_evidence(&mut state.cpu);
                } else if state.cpu.authority == TargetAuthority::Confirmed {
                    if let Some(rate) = usable_rate {
                        let base_cpus = state.cpu.policy.current_cpus;
                        let proposal = cpu_tick(bounds.cpu, state.cpu.policy, Some(rate));
                        if proposal.current_cpus == base_cpus {
                            state.cpu.policy.high_ticks = proposal.high_ticks;
                            state.cpu.policy.low_ticks = proposal.low_ticks;
                            // Plan §3.4(b): a deadband or boundary hold on positive distinct
                            // eligible evidence ends the outstanding demand, while a continuing
                            // same-direction observation keeps it and its deadline.
                            if state.cpu.outstanding.is_some_and(|outstanding| {
                                !cpu_hold_supports(
                                    outstanding.demand.direction,
                                    bounds.cpu,
                                    base_cpus,
                                    rate,
                                )
                            }) {
                                state.cpu.outstanding = None;
                            }
                        } else {
                            let target_cpus = proposal.current_cpus;
                            let direction = if target_cpus > base_cpus {
                                CpuDirection::Up
                            } else {
                                CpuDirection::Down
                            };
                            let demand = CpuDemand {
                                target_cpus,
                                direction,
                            };
                            let record = match state.cpu.outstanding {
                                Some(existing) if existing.demand == demand => existing,
                                _ => CpuOutstandingDemand {
                                    demand,
                                    anchor_cpus: base_cpus,
                                    no_progress_attempts: 0,
                                    waited_polls: 0,
                                },
                            };
                            state.cpu.outstanding = Some(record);
                            if record.waited_polls >= cpu_retry_delay(record.no_progress_attempts) {
                                state.cpu.policy.high_ticks = 0;
                                state.cpu.policy.low_ticks = 0;
                                cpu_request = Some(CpuResizeRequest {
                                    baseline_cpus: base_cpus,
                                    target_cpus,
                                    recovering: false,
                                });
                            } else {
                                // Retain the ready counter so the next distinct observation
                                // re-proposes after the deadline instead of restarting the run.
                                state.cpu.policy.high_ticks = if direction == CpuDirection::Up {
                                    CPU_HIGH_TICKS - 1
                                } else {
                                    0
                                };
                                state.cpu.policy.low_ticks = if direction == CpuDirection::Down {
                                    CPU_LOW_TICKS - 1
                                } else {
                                    0
                                };
                            }
                        }
                    } else {
                        // S-B: a published zero, and any absent or unusable rate, proves no
                        // demand decision whatever the lifecycle cache's age, so it resets both
                        // runs instead of leaving a run to survive behind a fresh cache.
                        reset_cpu_evidence(&mut state.cpu);
                    }
                } else {
                    // (6) Recovering: re-confirm the last accepted commitment at any rate,
                    // independent of demand and of the demand deadline.
                    let ask = CpuCorrectionAsk {
                        target_cpus: state.cpu.last_accepted_cpus,
                    };
                    if state.cpu.correction_retry.admit(ask) {
                        cpu_request = Some(CpuResizeRequest {
                            baseline_cpus: state.cpu.policy.current_cpus,
                            target_cpus: ask.target_cpus,
                            recovering: true,
                        });
                    }
                }
            }
        }

        // One record per original poll. Silent at the default filter, and the reason integrated
        // evidence can attribute a live run to a clock, a lifecycle or a memory deferral.
        log_cpu_poll(
            observation,
            usable_rate,
            state.cpu_lifecycle,
            state.cpu.policy,
            state.cpu.outstanding,
            memory_request.is_some(),
            cpu_request,
            deferred,
        );

        // (7) One shared operation, or none.
        if cpu_request.is_none() && memory_request.is_none() {
            continue;
        }
        let request = ResourceResizeRequest {
            cpu: cpu_request,
            memory: memory_request,
        };
        let outcome = resize(request).await;
        let any_error =
            matches!(&outcome.cpu, Some(Err(_))) || matches!(&outcome.memory, Some(Err(_)));

        if let Some(result) = outcome.memory {
            let memory = request
                .memory
                .expect("a memory outcome was only requested with a memory request");
            let ask = memory_ask.expect("an admitted memory ask was recorded");
            match result {
                Ok(accepted) => {
                    state.memory.policy = MemoryState {
                        current_target_mib: accepted,
                        low_ticks: 0,
                    };
                    state.memory.authority = TargetAuthority::Confirmed;
                    state.memory.last_accepted_target_mib = accepted;
                    if accepted < memory.target_mib {
                        state.memory.retry.damp(ask);
                    } else {
                        state.memory.retry.clear();
                    }
                    tracing::debug!(
                        target: MONITOR_TARGET,
                        event = "memory_transition",
                        previous_target_mib = memory.baseline_mib,
                        requested_target_mib = memory.target_mib,
                        accepted_target_mib = accepted,
                        "memory commitment changed"
                    );
                }
                Err(error) => {
                    state.memory.authority = TargetAuthority::Recovering;
                    state.memory.policy = MemoryState {
                        current_target_mib: memory.baseline_mib,
                        low_ticks: 0,
                    };
                    state.memory.retry.damp(ask);
                    tracing::debug!(
                        target: MONITOR_TARGET,
                        event = error.event(),
                        axis = "memory",
                        error = %error.detail(),
                        requested_target_mib = memory.target_mib,
                        last_accepted_target_mib = state.memory.last_accepted_target_mib,
                        "memory resize did not report an accepted target"
                    );
                }
            }
        }

        if let Some(result) = outcome.cpu {
            let cpu = request
                .cpu
                .expect("a CPU outcome was only requested with a CPU request");
            match result {
                Ok(accepted) => {
                    // Progress is measured against the unmet demand's anchor, never against
                    // the ask or the corrective target.
                    let progress = state
                        .cpu
                        .outstanding
                        .is_some_and(|demand| cpu_demand_met(demand, accepted));
                    state.cpu.authority = TargetAuthority::Confirmed;
                    state.cpu.last_accepted_cpus = accepted;
                    state.cpu.policy = CpuState {
                        current_cpus: accepted,
                        high_ticks: 0,
                        low_ticks: 0,
                    };
                    state.cpu.correction_retry.clear();
                    if progress {
                        state.cpu.outstanding = None;
                    } else if !cpu.recovering
                        && let Some(outstanding) = state.cpu.outstanding.as_mut()
                    {
                        outstanding.no_progress_attempts =
                            outstanding.no_progress_attempts.saturating_add(1);
                        outstanding.waited_polls = 0;
                    }
                    tracing::debug!(
                        target: MONITOR_TARGET,
                        event = "cpu_transition",
                        axis = "cpu",
                        previous_cpus = cpu.baseline_cpus,
                        requested_cpus = cpu.target_cpus,
                        enforced_cpus = accepted,
                        recovering = cpu.recovering,
                        outstanding = state.cpu.outstanding.is_some(),
                        "CPU commitment confirmed"
                    );
                }
                Err(error) => {
                    state.cpu.authority = TargetAuthority::Recovering;
                    state.cpu.policy = CpuState {
                        current_cpus: cpu.baseline_cpus,
                        high_ticks: 0,
                        low_ticks: 0,
                    };
                    if cpu.recovering {
                        state.cpu.correction_retry.damp(CpuCorrectionAsk {
                            target_cpus: cpu.target_cpus,
                        });
                    } else if let Some(outstanding) = state.cpu.outstanding.as_mut() {
                        outstanding.no_progress_attempts =
                            outstanding.no_progress_attempts.saturating_add(1);
                        outstanding.waited_polls = 0;
                    }
                    tracing::debug!(
                        target: MONITOR_TARGET,
                        event = error.event(),
                        axis = "cpu",
                        error = %error.detail(),
                        requested_cpus = cpu.target_cpus,
                        last_accepted_cpus = state.cpu.last_accepted_cpus,
                        "CPU resize did not report an accepted target"
                    );
                }
            }
        }

        if any_error {
            // No failure is evidence of "no effect", and a failure may have involved a paused
            // or recovering runtime. Invalidate the eligibility cache (keeping the probe start,
            // so this cannot become a probe storm) and require fresh evidence.
            state.cpu_lifecycle.valid = false;
            reset_cpu_evidence(&mut state.cpu);
        }
    }
    state
}

/// One debug record per original poll.
///
/// It carries exactly what a live run needs to be attributed after the fact: the clock class,
/// the decoded rate interval, the cached lifecycle and its age, both runs, the unmet demand's
/// counters, whether memory was admitted, whether CPU was deferred, and the dispatch decision.
/// Nothing is emitted at `info` or above, so normal output is unchanged.
#[allow(clippy::too_many_arguments)]
fn log_cpu_poll(
    observation: CpuObservation,
    rate: Option<CpuRate>,
    lifecycle: CpuLifecycleCache,
    counters: CpuState,
    outstanding: Option<CpuOutstandingDemand>,
    memory_admitted: bool,
    cpu_request: Option<CpuResizeRequest>,
    deferred: bool,
) {
    let (lower_tenths, upper_tenths) = match rate {
        Some(rate) => (rate.lower_tenths, rate.upper_tenths),
        None => (0, 0),
    };
    let cache_age_ms = lifecycle
        .last_probe_started
        .map(|started| now_instant().duration_since(started).as_millis() as u64);
    let (attempts, waited_polls, anchor_cpus, target_cpus) = match outstanding {
        Some(demand) => (
            demand.no_progress_attempts,
            demand.waited_polls,
            demand.anchor_cpus,
            demand.demand.target_cpus,
        ),
        None => (0, 0, 0, 0),
    };
    tracing::debug!(
        target: MONITOR_TARGET,
        event = "cpu_poll",
        clock = ?observation,
        rate_lower_tenths = lower_tenths,
        rate_upper_tenths = upper_tenths,
        lifecycle = ?lifecycle.value,
        lifecycle_valid = lifecycle.valid,
        cache_age_ms = cache_age_ms,
        high_ticks = counters.high_ticks,
        low_ticks = counters.low_ticks,
        current_cpus = counters.current_cpus,
        demand_target_cpus = target_cpus,
        demand_anchor_cpus = anchor_cpus,
        demand_attempts = attempts,
        demand_waited_polls = waited_polls,
        memory_admitted = memory_admitted,
        cpu_deferred = deferred,
        requested_cpus = cpu_request.map(|request| request.target_cpus).unwrap_or(0),
        recovering_request = cpu_request.map(|request| request.recovering).unwrap_or(false),
        "cpu poll"
    );
}

/// Zero the CPU evidence runs without touching authority, history, demand or deadlines.
fn reset_cpu_evidence(state: &mut CpuControllerState) {
    state.policy.high_ticks = 0;
    state.policy.low_ticks = 0;
}

fn now_instant() -> tokio::time::Instant {
    tokio::time::Instant::now()
}

/// A cached reply is usable only inside its TTL, measured from the **attempt start**.
fn cpu_lifecycle_fresh(cache: &CpuLifecycleCache, now: tokio::time::Instant) -> bool {
    cache.valid
        && cache
            .last_probe_started
            .is_some_and(|started| now.duration_since(started) < CPU_LIFECYCLE_TTL)
}

/// At most one probe attempt per TTL, whatever the cache says.
fn cpu_probe_allowed(cache: &CpuLifecycleCache, now: tokio::time::Instant) -> bool {
    cache
        .last_probe_started
        .is_none_or(|started| now.duration_since(started) >= CPU_LIFECYCLE_TTL)
}

/// One bounded lifecycle query, cached from its attempt start — including failures.
async fn refresh_cpu_lifecycle<L, LF>(
    cache: &mut CpuLifecycleCache,
    probe_lifecycle: &mut L,
    now: tokio::time::Instant,
) -> CpuLifecycle
where
    L: FnMut() -> LF,
    LF: std::future::Future<Output = anyhow::Result<CpuLifecycle>>,
{
    cache.last_probe_started = Some(now);
    let outcome = tokio::time::timeout(CPU_LIFECYCLE_TIMEOUT, probe_lifecycle()).await;
    let (value, detail) = match outcome {
        Ok(Ok(CpuLifecycle::Running)) => (CpuLifecycle::Running, "running"),
        Ok(Ok(CpuLifecycle::NotRunning)) => (CpuLifecycle::NotRunning, "not_running"),
        Ok(Ok(CpuLifecycle::Unavailable)) => (CpuLifecycle::Unavailable, "unavailable"),
        Ok(Err(error)) => {
            tracing::debug!(
                target: MONITOR_TARGET,
                event = "cpu_lifecycle_probe_error",
                error = %format!("{error:#}"),
                "the lifecycle probe failed"
            );
            (CpuLifecycle::Unavailable, "error")
        }
        Err(_) => {
            tracing::debug!(
                target: MONITOR_TARGET,
                event = "cpu_lifecycle_probe_timeout",
                timeout_ms = CPU_LIFECYCLE_TIMEOUT.as_millis() as u64,
                "the lifecycle probe exceeded its bound"
            );
            (CpuLifecycle::Unavailable, "timeout")
        }
    };
    cache.value = value;
    cache.valid = true;
    tracing::debug!(
        target: MONITOR_TARGET,
        event = "cpu_lifecycle_probe",
        result = detail,
        cache_age_ms = now.elapsed().as_millis() as u64,
        "lifecycle eligibility refreshed"
    );
    value
}

/// Test-only compatibility adapter: the S2 memory tests drive one axis through the shared
/// driver with fixed CPU bounds, so no CPU work and no probe is possible.
#[cfg(test)]
async fn drive_memory<S, R, F>(
    bounds: MemoryBounds,
    state: MemoryControllerState,
    samples: S,
    mut resize: R,
) -> MemoryControllerState
where
    S: futures::Stream<Item = anyhow::Result<Option<MemorySample>>>,
    R: FnMut(MemoryResizeRequest) -> F,
    F: std::future::Future<Output = Result<u32, ResourceResizeError>>,
{
    let resource_bounds = ResourceBounds {
        cpu: CpuBounds {
            boot_cpus: 1,
            max_cpus: 1,
        },
        memory: bounds,
    };
    let initial = ResourceControllerState {
        cpu: fixed_cpu_controller(),
        memory: state,
        cpu_clock: CpuObservationClock::default(),
        cpu_lifecycle: CpuLifecycleCache::default(),
    };
    let mut poll = 0u64;
    let samples = futures::StreamExt::map(samples, move |item| {
        poll += 1;
        item.map(|sample| {
            sample.map(|memory| ResourceSample {
                memory,
                cpu_rate: None,
                timestamp: std::time::UNIX_EPOCH + Duration::from_secs(poll),
            })
        })
    });
    let resize = move |request: ResourceResizeRequest| {
        let memory = request
            .memory
            .expect("the memory compatibility adapter only requests memory");
        let pending = resize(memory);
        async move {
            ResourceResizeOutcome {
                cpu: None,
                memory: Some(pending.await),
            }
        }
    };
    let probe = || async { anyhow::bail!("fixed CPU bounds never require a lifecycle probe") };
    let final_state = drive_resources(resource_bounds, initial, samples, resize, probe).await;
    final_state.memory
}

/// The disabled CPU axis the memory compatibility adapter uses: boot equals ceiling.
#[cfg(test)]
fn fixed_cpu_controller() -> CpuControllerState {
    CpuControllerState {
        policy: CpuState {
            current_cpus: 1,
            high_ticks: 0,
            low_ticks: 0,
        },
        authority: TargetAuthority::Confirmed,
        last_accepted_cpus: 1,
        outstanding: None,
        correction_retry: ResizeRetry::default(),
    }
}

/// The production cadence: one read per 200 ms tick, first tick after one interval.
///
/// `MissedTickBehavior::Skip` is load-bearing. `Burst` would manufacture a rapid catch-up
/// after slow I/O, and 50 such ticks would look like 10 s of lower demand.
///
/// The reader returns the row immediately: it never calls or awaits `pause_state()`. Lifecycle
/// is the driver's lazy concern, and memory dispatch must not wait behind it (N1).
fn resource_samples<R, F>(
    read: R,
) -> impl futures::Stream<Item = anyhow::Result<Option<ResourceSample>>> + Send
where
    R: FnMut() -> F + Send,
    F: std::future::Future<Output = anyhow::Result<Option<ResourceSample>>> + Send,
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
async fn read_resource_sample(
    sandbox: &microsandbox::Sandbox,
) -> anyhow::Result<Option<ResourceSample>> {
    let Some(local) = sandbox.backend().as_local() else {
        anyhow::bail!("the sandbox has no local backend, so live metrics cannot be read");
    };
    let mut metrics = microsandbox::sandbox::all_sandbox_metrics_local(local).await?;
    let Some(metrics) = metrics.remove(sandbox.name()) else {
        return Ok(None);
    };
    Ok(Some(resource_sample_of(&metrics)?))
}

/// Copy the fields both policies use, and nothing that could stand in for them.
///
/// Memory keeps exactly its two S2 fields. The CPU rate goes through the proved decoder, so the
/// SDK's non-optional `f32` becomes an internal `Option` interval; a published zero is `None`
/// because it proves neither absence nor idleness (S-B).
fn resource_sample_of(
    metrics: &microsandbox::sandbox::SandboxMetrics,
) -> anyhow::Result<ResourceSample> {
    let seconds = u64::try_from(metrics.timestamp.timestamp())
        .map_err(|_| anyhow::anyhow!("the metrics timestamp precedes the Unix epoch"))?;
    let timestamp = std::time::UNIX_EPOCH
        + Duration::from_secs(seconds)
        + Duration::from_nanos(u64::from(metrics.timestamp.timestamp_subsec_nanos()));
    Ok(ResourceSample {
        memory: MemorySample {
            memory_limit_bytes: metrics.memory_limit_bytes,
            memory_available_bytes: metrics.memory_available_bytes,
        },
        cpu_rate: cpu_rate_of(metrics.cpu_percent),
        timestamp,
    })
}

/// Trusted adapter: one lifecycle query, mapped to eligibility only.
///
/// `paused` and `recovery_required` both mean no CPU work; anything the SDK reports as an error
/// is `Unavailable`. This call takes a lifecycle transition guard and a run-matched control
/// session (`sandbox/pause.rs:175-223`), so it is not a cheap flag — the driver's cache exists
/// for that reason.
async fn read_cpu_lifecycle(sandbox: &microsandbox::Sandbox) -> anyhow::Result<CpuLifecycle> {
    let state = sandbox.pause_state().await?;
    Ok(if state.paused || state.recovery_required {
        CpuLifecycle::NotRunning
    } else {
        CpuLifecycle::Running
    })
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

/// A `std::error::Error` over one shared `Arc`, so a live failure that affects both axes can be
/// reported twice without requiring the error itself to be cloneable.
#[derive(Debug)]
struct SharedResizeError(std::sync::Arc<anyhow::Error>);

impl std::fmt::Display for SharedResizeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{:#}", self.0)
    }
}

impl std::error::Error for SharedResizeError {}

/// ADR-0070 D2 with the unknown-outcome amendment: one request through the SDK.
async fn resize_resources(
    sandbox: &microsandbox::Sandbox,
    bounds: ResourceBounds,
    request: ResourceResizeRequest,
) -> ResourceResizeOutcome {
    resize_resources_with(bounds, request, |mode, targets| {
        let sandbox = sandbox.clone();
        async move {
            let mut builder = sandbox.modify();
            if let Some(cpus) = targets.cpus {
                builder = builder.cpus(cpus);
            }
            if let Some(memory_mib) = targets.memory_mib {
                builder = builder.memory(memory_mib);
            }
            let builder = match mode {
                ResourceApplyMode::Live => builder,
                ResourceApplyMode::NextStart => builder.next_start(),
            };
            builder.apply().await.map_err(anyhow::Error::new)
        }
    })
    .await
}

/// The apply seam: one combined prepare for recovering axes, then one combined live apply.
///
/// A live patch whose desired field equals the persisted desired field is classified as an
/// applied plan with no status for that axis, so repeating it after a failed persistence can be
/// a statusless no-op forever. Persisting distinct `NextStart` seeds first makes each following
/// live field a real planned change, and `NextStart` sends no runtime control, so a seed never
/// bounces live state. Both axes share at most one prepare and one live apply, never per-axis
/// pairs (S-E).
///
/// Preparation is isolated: an axis with no seed, or one whose prepare did not apply cleanly, is
/// excluded from the live call with its own error and never blocks a healthy neighbour.
async fn resize_resources_with<A, F>(
    bounds: ResourceBounds,
    request: ResourceResizeRequest,
    mut apply: A,
) -> ResourceResizeOutcome
where
    A: FnMut(ResourceApplyMode, ResourceTargets) -> F,
    F: std::future::Future<Output = anyhow::Result<microsandbox::sandbox::SandboxModificationPlan>>,
{
    let mut outcome = ResourceResizeOutcome {
        cpu: None,
        memory: None,
    };

    // (1) Seeds for the requested recovering axes only.
    let mut seeds = ResourceTargets::default();
    let mut cpu_no_seed = None;
    let mut memory_no_seed = None;
    if let Some(cpu) = request.cpu
        && cpu.recovering
    {
        match cpu_recovery_seed(bounds.cpu, cpu.target_cpus) {
            Some(seed) => seeds.cpus = Some(seed),
            None => {
                cpu_no_seed = Some(ResourceResizeError::Unconfirmed(anyhow::anyhow!(
                    "recovery_prepare: no boot-derived seed in {}..={} differs from {}",
                    bounds.cpu.boot_cpus,
                    bounds.cpu.max_cpus,
                    cpu.target_cpus
                )))
            }
        }
    }
    if let Some(memory) = request.memory
        && memory.recovering
    {
        match memory_recovery_seed(bounds.memory, memory.baseline_mib, memory.target_mib) {
            Some(seed) => seeds.memory_mib = Some(seed),
            None => {
                memory_no_seed = Some(ResourceResizeError::Unconfirmed(anyhow::anyhow!(
                    "recovery_prepare: no configuration seed in {}..={} MiB differs from both {} and {}",
                    bounds.memory.boot_memory_mib,
                    bounds.memory.max_memory_mib,
                    memory.baseline_mib,
                    memory.target_mib
                )))
            }
        }
    }

    // (2) One combined NextStart apply containing only seed fields.
    let mut cpu_prepared = false;
    let mut memory_prepared = false;
    if seeds.cpus.is_some() || seeds.memory_mib.is_some() {
        let participants = ResourceTargets {
            cpus: if seeds.cpus.is_some() {
                request.cpu.map(|cpu| cpu.target_cpus)
            } else {
                None
            },
            memory_mib: if seeds.memory_mib.is_some() {
                request.memory.map(|memory| memory.target_mib)
            } else {
                None
            },
        };
        let prepared = apply(ResourceApplyMode::NextStart, seeds).await;
        let failure = match prepared {
            Err(error) => {
                let shared = std::sync::Arc::new(error);
                Some(ResourceResizeError::Modify(anyhow::Error::new(
                    SharedResizeError(shared),
                )))
            }
            Ok(plan) if !plan.applied => Some(ResourceResizeError::Unconfirmed(anyhow::anyhow!(
                "recovery_prepare: the combined seed patch was not applied"
            ))),
            Ok(plan) if !plan.resize_status.is_empty() => {
                Some(ResourceResizeError::Unconfirmed(anyhow::anyhow!(
                    "recovery_prepare: the combined seed patch reported a live resize status"
                )))
            }
            Ok(_) => None,
        };
        match failure {
            None => {
                cpu_prepared = participants.cpus.is_some();
                memory_prepared = participants.memory_mib.is_some();
            }
            Some(error) => {
                // No live seed mutation was intended, but saved values are unknown: stay
                // Recovering on every participating axis and report the failure once per axis.
                if let Some(target) = participants.cpus {
                    outcome.cpu = Some(Err(contextual_prepare_error(&error, target)));
                }
                if let Some(_target) = participants.memory_mib {
                    outcome.memory = Some(Err(contextual_memory_prepare_error(&error)));
                }
            }
        }
    }

    // (3) One live apply carrying every remaining field.
    let mut targets = ResourceTargets::default();
    let mut cpu_participates = false;
    let mut memory_participates = false;
    if let Some(cpu) = request.cpu {
        if !cpu.recovering || cpu_prepared {
            targets.cpus = Some(cpu.target_cpus);
            cpu_participates = true;
        } else if outcome.cpu.is_none() {
            outcome.cpu = Some(Err(cpu_no_seed.unwrap_or_else(|| {
                ResourceResizeError::Unconfirmed(anyhow::anyhow!(
                    "recovery_prepare: the CPU seed was not prepared"
                ))
            })));
        }
    }
    if let Some(memory) = request.memory {
        if !memory.recovering || memory_prepared {
            targets.memory_mib = Some(memory.target_mib);
            memory_participates = true;
        } else if outcome.memory.is_none() {
            outcome.memory = Some(Err(memory_no_seed.unwrap_or_else(|| {
                ResourceResizeError::Unconfirmed(anyhow::anyhow!(
                    "recovery_prepare: the memory seed was not prepared"
                ))
            })));
        }
    }
    if !cpu_participates && !memory_participates {
        return outcome;
    }

    let plan = apply(ResourceApplyMode::Live, targets).await;
    let plan = match plan {
        Ok(plan) => plan,
        Err(error) => {
            // One shared error, no partial receipt: every live participant has an unknown
            // outcome, and none may be inferred to be unchanged.
            let shared = std::sync::Arc::new(error);
            if cpu_participates {
                outcome.cpu = Some(Err(ResourceResizeError::Modify(
                    anyhow::Error::new(SharedResizeError(std::sync::Arc::clone(&shared))).context(
                        format!(
                            "live_apply: requesting {} vCPU",
                            targets.cpus.unwrap_or(bounds.cpu.boot_cpus)
                        ),
                    ),
                )));
            }
            if memory_participates {
                outcome.memory = Some(Err(ResourceResizeError::Modify(
                    anyhow::Error::new(SharedResizeError(shared)).context(format!(
                        "live_apply: requesting {} MiB",
                        targets.memory_mib.unwrap_or(bounds.memory.boot_memory_mib)
                    )),
                )));
            }
            return outcome;
        }
    };

    // (4) Decode each axis independently: one bad receipt must not discard a good one, and
    // `applied=false` makes every requested receipt unusable.
    if cpu_participates {
        let requested_cpus = targets.cpus.unwrap_or(bounds.cpu.boot_cpus);
        outcome.cpu = Some(
            accepted_cpu_target(&plan, bounds.cpu, requested_cpus).map_err(|error| {
                ResourceResizeError::Unconfirmed(error.context(format!(
                    "live_apply: decoding the status for {requested_cpus} vCPU"
                )))
            }),
        );
    }
    if memory_participates {
        let requested_mib = targets.memory_mib.unwrap_or(bounds.memory.boot_memory_mib);
        outcome.memory = Some(
            accepted_memory_target(&plan, bounds.memory).map_err(|error| {
                ResourceResizeError::Unconfirmed(error.context(format!(
                    "live_apply: decoding the status for {requested_mib} MiB"
                )))
            }),
        );
    }
    outcome
}

fn contextual_prepare_error(error: &ResourceResizeError, target_cpus: u8) -> ResourceResizeError {
    ResourceResizeError::Unconfirmed(anyhow::anyhow!(
        "recovery_prepare: seeding configuration before {target_cpus} vCPU: {}",
        error.detail()
    ))
}

fn contextual_memory_prepare_error(error: &ResourceResizeError) -> ResourceResizeError {
    ResourceResizeError::Unconfirmed(anyhow::anyhow!(
        "recovery_prepare: seeding configuration before the memory target: {}",
        error.detail()
    ))
}

/// Trusted decoder for the SDK's enforced CPU target, the only CPU authority there is.
///
/// `actual` is diagnostic: a converging guest may lag, and `requested` proves this receipt
/// belongs to this request, but neither establishes enforcement. No catalog `cpus`, saved
/// desired value, `cpu_percent` or `nproc` is accepted here.
fn accepted_cpu_target(
    plan: &microsandbox::sandbox::SandboxModificationPlan,
    bounds: CpuBounds,
    requested_cpus: u8,
) -> anyhow::Result<u8> {
    if !plan.applied {
        anyhow::bail!("the modification plan was not applied");
    }
    let mut statuses = plan
        .resize_status
        .iter()
        .filter(|status| status.resource == microsandbox::sandbox::ResourceKind::Cpus);
    let status = statuses
        .next()
        .ok_or_else(|| anyhow::anyhow!("the plan reported no CPU resize status"))?;
    if statuses.next().is_some() {
        anyhow::bail!("the plan reported more than one CPU resize status");
    }
    match status.state {
        microsandbox::sandbox::ResourceConvergenceState::Accepted
        | microsandbox::sandbox::ResourceConvergenceState::Converging
        | microsandbox::sandbox::ResourceConvergenceState::Applied => {}
        microsandbox::sandbox::ResourceConvergenceState::GuestRefused => {
            anyhow::bail!("the guest refused the CPU resize")
        }
        microsandbox::sandbox::ResourceConvergenceState::Failed => {
            anyhow::bail!("the CPU resize failed")
        }
    }
    let requested = cpu_status_count(&status.requested)?;
    if requested != requested_cpus {
        anyhow::bail!(
            "the receipt's requested value {requested} vCPU is not this request's {requested_cpus}"
        );
    }
    let actual = cpu_status_count(&status.actual)?;
    let enforced = cpu_status_count(&status.enforced)?;
    if !cpu_target_in_bounds(bounds, actual) {
        anyhow::bail!(
            "the actual target {actual} vCPU is outside {}..={}",
            bounds.boot_cpus,
            bounds.max_cpus
        );
    }
    if !cpu_target_in_bounds(bounds, enforced) {
        anyhow::bail!(
            "the enforced target {enforced} vCPU is outside {}..={}",
            bounds.boot_cpus,
            bounds.max_cpus
        );
    }
    tracing::debug!(
        target: MONITOR_TARGET,
        event = "cpu_resize_status",
        requested_cpus = requested,
        actual_cpus = actual,
        enforced_cpus = enforced,
        state = ?status.state,
        "decoded a CPU resize receipt"
    );
    Ok(enforced)
}

/// Nonempty ASCII decimal digits, checked into `u32` then `u8`. No units, sign or whitespace.
fn cpu_status_count(text: &str) -> anyhow::Result<u8> {
    let unsupported = || anyhow::anyhow!("the CPU target {text:?} is not a plain decimal count");
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(unsupported());
    }
    let value: u32 = text.parse().map_err(|_| unsupported())?;
    u8::try_from(value).map_err(|_| anyhow::anyhow!("the CPU target {text:?} exceeds u8"))
}

/// Test-only compatibility adapter: the S2 memory tests keep their single-axis seam.
#[cfg(test)]
async fn resize_memory_with<A, F>(
    bounds: MemoryBounds,
    request: MemoryResizeRequest,
    mut apply: A,
) -> Result<u32, ResourceResizeError>
where
    A: FnMut(ResourceApplyMode, u32) -> F,
    F: std::future::Future<Output = anyhow::Result<microsandbox::sandbox::SandboxModificationPlan>>,
{
    let resource_bounds = ResourceBounds {
        cpu: CpuBounds {
            boot_cpus: 1,
            max_cpus: 1,
        },
        memory: bounds,
    };
    let outcome = resize_resources_with(
        resource_bounds,
        ResourceResizeRequest {
            cpu: None,
            memory: Some(request),
        },
        move |mode, targets| {
            apply(
                mode,
                targets
                    .memory_mib
                    .expect("the memory compatibility adapter only sends memory"),
            )
        },
    )
    .await;
    outcome
        .memory
        .expect("a requested memory axis always has an outcome")
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

    /// `count` identical low-usage rows, the shape the memory damping tests need.
    impl FakeVm {
        async fn apply(
            &self,
            mode: ResourceApplyMode,
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
        sdk_actions: Vec<(ResourceApplyMode, u32)>,
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

        fn sdk_actions(&self) -> Vec<(ResourceApplyMode, u32)> {
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
            mode: ResourceApplyMode,
            mib: u32,
        ) -> anyhow::Result<microsandbox::sandbox::SandboxModificationPlan> {
            state.sdk_actions.push((mode, mib));
            match mode {
                ResourceApplyMode::NextStart => {
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
                ResourceApplyMode::Live => {
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
    }

    fn cpu_status(
        state: microsandbox::sandbox::ResourceConvergenceState,
        requested: &str,
        actual: &str,
        enforced: &str,
    ) -> microsandbox::sandbox::ResourceResizeStatus {
        microsandbox::sandbox::ResourceResizeStatus {
            resource: microsandbox::sandbox::ResourceKind::Cpus,
            requested: requested.to_string(),
            actual: actual.to_string(),
            enforced: enforced.to_string(),
            state,
        }
    }

    /// Where a live apply fails, in the pinned SDK's own stage order.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum StageFault {
        /// No runtime control was sent and nothing persisted.
        BeforeAny,
        /// CPU control took effect; its active-config persist failed.
        AfterCpuControl,
        /// CPU took effect and persisted; memory was not attempted.
        AfterCpuPersist,
        /// Memory control took effect after the CPU stages; its persist failed.
        AfterMemoryControl,
        /// Both active writes persisted; the desired write failed.
        AfterMemoryPersist,
        /// Everything persisted, and the call still failed.
        AfterDesiredPersist,
    }

    /// Corrupt only the *returned* receipt, after every modelled effect has run.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Corrupt {
        CpuReceipt,
        MemoryReceipt,
    }

    #[derive(Clone, Debug, Default)]
    struct FakeResourcesState {
        desired_cpus: u8,
        desired_mib: u32,
        enforced_cpus: u8,
        runtime_mib: u32,
        applies: Vec<(ResourceApplyMode, ResourceTargets)>,
        live_failures: u32,
        prepare_failure: bool,
        stage_fault: Option<StageFault>,
        corrupt: Option<Corrupt>,
        /// A diagnostic cap: the runtime enforces at most this many CPUs while still
        /// reporting the requested value as accepted (the under-enforcement the plan models).
        enforce_cap: u8,
    }

    /// One stateful SDK model: saved desired per field, runtime enforcement, and the real
    /// equality rule that a patch equal to saved desired emits no status.
    struct FakeResources {
        state: std::sync::Mutex<FakeResourcesState>,
    }

    impl FakeResources {
        fn new(cpus: u8, mib: u32) -> std::sync::Arc<Self> {
            std::sync::Arc::new(Self {
                state: std::sync::Mutex::new(FakeResourcesState {
                    desired_cpus: cpus,
                    desired_mib: mib,
                    enforced_cpus: cpus,
                    runtime_mib: mib,
                    ..FakeResourcesState::default()
                }),
            })
        }

        fn fail_live(&self, times: u32) {
            self.state.lock().unwrap().live_failures = times;
        }

        fn cap_enforcement(&self, cpus: u8) {
            self.state.lock().unwrap().enforce_cap = cpus;
        }

        fn fail_prepare(&self) {
            self.state.lock().unwrap().prepare_failure = true;
        }

        fn fail_at(&self, stage: StageFault) {
            self.state.lock().unwrap().stage_fault = Some(stage);
        }

        fn corrupt_receipt(&self, which: Corrupt) {
            self.state.lock().unwrap().corrupt = Some(which);
        }

        fn applies(&self) -> Vec<(ResourceApplyMode, ResourceTargets)> {
            self.state.lock().unwrap().applies.clone()
        }

        fn enforced(&self) -> (u8, u32) {
            let state = self.state.lock().unwrap();
            (state.enforced_cpus, state.runtime_mib)
        }

        fn desired(&self) -> (u8, u32) {
            let state = self.state.lock().unwrap();
            (state.desired_cpus, state.desired_mib)
        }

        fn apply(
            &self,
            mode: ResourceApplyMode,
            targets: ResourceTargets,
        ) -> anyhow::Result<microsandbox::sandbox::SandboxModificationPlan> {
            let mut state = self.state.lock().unwrap();
            state.applies.push((mode, targets));
            match mode {
                ResourceApplyMode::NextStart => {
                    if state.prepare_failure {
                        return Err(anyhow::anyhow!("the seed patch was rejected"));
                    }
                    if let Some(cpus) = targets.cpus {
                        state.desired_cpus = cpus;
                    }
                    if let Some(mib) = targets.memory_mib {
                        state.desired_mib = mib;
                    }
                    Ok(modification_plan(true, Vec::new()))
                }
                ResourceApplyMode::Live => {
                    if state.live_failures > 0 {
                        state.live_failures -= 1;
                        return Err(anyhow::anyhow!(
                            "the live patch failed before any runtime control request"
                        ));
                    }
                    let stage = state.stage_fault.take();
                    if stage == Some(StageFault::BeforeAny) {
                        return Err(anyhow::anyhow!(
                            "the live patch failed before any runtime control request"
                        ));
                    }
                    let cpu_planned = targets.cpus.is_some_and(|cpus| cpus != state.desired_cpus);
                    let memory_planned = targets
                        .memory_mib
                        .is_some_and(|mib| mib != state.desired_mib);
                    let mut statuses = Vec::new();
                    if let Some(cpus) = targets.cpus
                        && cpu_planned
                    {
                        // The requested CPU is written to active/desired config even when the
                        // enforced value differs, which is the pinned SDK's own behaviour.
                        let cap = state.enforce_cap;
                        let enforced = if cap == 0 { cpus } else { cpus.min(cap) };
                        state.enforced_cpus = enforced;
                        if stage == Some(StageFault::AfterCpuControl) {
                            return Err(anyhow::anyhow!(
                                "the CPU target was accepted and active-config persistence failed"
                            ));
                        }
                        state.desired_cpus = cpus;
                        statuses.push(cpu_status(
                            microsandbox::sandbox::ResourceConvergenceState::Accepted,
                            &cpus.to_string(),
                            &enforced.to_string(),
                            &enforced.to_string(),
                        ));
                        if stage == Some(StageFault::AfterCpuPersist) {
                            return Err(anyhow::anyhow!(
                                "the CPU target persisted and the memory request was not attempted"
                            ));
                        }
                    }
                    if let Some(mib) = targets.memory_mib
                        && memory_planned
                    {
                        state.runtime_mib = mib;
                        if stage == Some(StageFault::AfterMemoryControl) {
                            return Err(anyhow::anyhow!(
                                "the memory target was accepted and active-config persistence failed"
                            ));
                        }
                        state.desired_mib = mib;
                        statuses.push(memory_resize_status(
                            microsandbox::sandbox::ResourceConvergenceState::Applied,
                            &status_text(mib),
                            &status_text(mib),
                            &status_text(mib),
                        ));
                        if stage == Some(StageFault::AfterMemoryPersist) {
                            return Err(anyhow::anyhow!(
                                "both targets persisted and the desired write failed"
                            ));
                        }
                    }
                    if stage == Some(StageFault::AfterDesiredPersist) {
                        return Err(anyhow::anyhow!(
                            "everything persisted and the call still failed"
                        ));
                    }
                    match state.corrupt.take() {
                        // A malformed receipt changes only what the controller accepts; the
                        // modelled effects above stand, exactly as the SDK leaves them.
                        Some(Corrupt::CpuReceipt) => {
                            if let Some(status) = statuses.iter_mut().find(|status| {
                                status.resource == microsandbox::sandbox::ResourceKind::Cpus
                            }) {
                                status.enforced = "two".to_string();
                            }
                        }
                        Some(Corrupt::MemoryReceipt) => {
                            if let Some(status) = statuses.iter_mut().find(|status| {
                                status.resource == microsandbox::sandbox::ResourceKind::Memory
                            }) {
                                status.enforced = "loads".to_string();
                            }
                        }
                        None => {}
                    }
                    Ok(modification_plan(true, statuses))
                }
            }
        }
    }

    fn running_cache() -> CpuLifecycleCache {
        CpuLifecycleCache {
            value: CpuLifecycle::Running,
            valid: true,
            last_probe_started: Some(tokio::time::Instant::now()),
        }
    }

    fn resource_state(cpu_current: u8, memory_current_mib: u32) -> ResourceControllerState {
        ResourceControllerState {
            cpu: CpuControllerState {
                policy: cpu_state(cpu_current, 0, 0),
                authority: TargetAuthority::Confirmed,
                last_accepted_cpus: cpu_current,
                outstanding: None,
                correction_retry: ResizeRetry::default(),
            },
            memory: MemoryControllerState {
                policy: MemoryState {
                    current_target_mib: memory_current_mib,
                    low_ticks: 0,
                },
                authority: TargetAuthority::Confirmed,
                last_accepted_target_mib: memory_current_mib,
                retry: MemoryRetry::default(),
            },
            cpu_clock: CpuObservationClock::default(),
            cpu_lifecycle: running_cache(),
        }
    }

    fn resource_sample(second: u64, percent: f32, limit_mib: u64, used_mib: u64) -> ResourceSample {
        ResourceSample {
            memory: sample(limit_mib, used_mib),
            cpu_rate: cpu_rate_of(percent),
            timestamp: std::time::UNIX_EPOCH + Duration::from_secs(second),
        }
    }

    /// One row per nominal 200 ms poll, so paused time exercises the TTL honestly.
    fn advancing_samples(
        samples: Vec<anyhow::Result<Option<ResourceSample>>>,
    ) -> impl futures::Stream<Item = anyhow::Result<Option<ResourceSample>>> {
        futures::stream::unfold(samples.into_iter(), |mut items| async move {
            let item = items.next()?;
            tokio::time::advance(METRICS_SAMPLE_INTERVAL).await;
            Some((item, items))
        })
    }

    async fn drive_resources_fake<S>(
        bounds: ResourceBounds,
        from: ResourceControllerState,
        samples: S,
        vm: std::sync::Arc<FakeResources>,
        lifecycle: CpuLifecycle,
        probes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) -> ResourceControllerState
    where
        S: futures::Stream<Item = anyhow::Result<Option<ResourceSample>>>,
    {
        drive_resources_with_probe(bounds, from, samples, vm, move || {
            probes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async move { Ok(lifecycle) }
        })
        .await
    }

    /// The same driver with a scripted lifecycle probe, so a test can count calls, fail them,
    /// stall them past the 50 ms bound, or answer differently per call.
    async fn drive_resources_with_probe<S, L, LF>(
        bounds: ResourceBounds,
        from: ResourceControllerState,
        samples: S,
        vm: std::sync::Arc<FakeResources>,
        probe: L,
    ) -> ResourceControllerState
    where
        S: futures::Stream<Item = anyhow::Result<Option<ResourceSample>>>,
        L: FnMut() -> LF,
        LF: std::future::Future<Output = anyhow::Result<CpuLifecycle>>,
    {
        drive_resources(
            bounds,
            from,
            samples,
            move |request: ResourceResizeRequest| {
                let vm = std::sync::Arc::clone(&vm);
                async move {
                    resize_resources_with(bounds, request, move |mode, targets| {
                        let vm = std::sync::Arc::clone(&vm);
                        async move { vm.apply(mode, targets) }
                    })
                    .await
                }
            },
            probe,
        )
        .await
    }

    fn fresh_probes() -> std::sync::Arc<std::sync::atomic::AtomicUsize> {
        std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0))
    }

    fn probe_count(probes: &std::sync::atomic::AtomicUsize) -> usize {
        probes.load(std::sync::atomic::Ordering::SeqCst)
    }

    #[tokio::test]
    async fn simultaneous_admitted_targets_take_exactly_one_combined_apply() {
        tokio::time::pause();
        let bounds = ResourceBounds {
            cpu: cpu_bounds(1, 4),
            memory: bounds(512, 1024),
        };
        // CPU is one observation from a step and memory needs growth on the same row.
        let mut from = resource_state(1, 512);
        from.cpu.policy.high_ticks = CPU_HIGH_TICKS - 1;
        let vm = FakeResources::new(1, 512);
        let probes = fresh_probes();
        let final_state = drive_resources_fake(
            bounds,
            from,
            futures::stream::iter(vec![Ok(Some(resource_sample(10, 95.0, 512, 512)))]),
            std::sync::Arc::clone(&vm),
            CpuLifecycle::Running,
            std::sync::Arc::clone(&probes),
        )
        .await;
        assert_eq!(
            vm.applies(),
            vec![(
                ResourceApplyMode::Live,
                ResourceTargets {
                    cpus: Some(2),
                    memory_mib: Some(768),
                },
            )],
            "one builder, one live apply, both fields"
        );
        assert_eq!(vm.enforced(), (2, 768));
        assert_eq!(vm.desired(), (2, 768));
        assert_eq!(final_state.cpu.policy.current_cpus, 2);
        assert_eq!(final_state.cpu.authority, TargetAuthority::Confirmed);
        assert_eq!(final_state.memory.policy.current_target_mib, 768);
        assert_eq!(probe_count(&probes), 0, "a fresh cache needs no probe");
    }

    #[tokio::test]
    async fn one_axis_or_neither_dispatches_exactly_once() {
        tokio::time::pause();
        let bounds = ResourceBounds {
            cpu: cpu_bounds(1, 4),
            memory: bounds(512, 1024),
        };
        // CPU only: a completed high run, memory already converged.
        let vm = FakeResources::new(1, 512);
        let probes = fresh_probes();
        let mut from = resource_state(1, 512);
        from.cpu.policy.high_ticks = CPU_HIGH_TICKS - 1;
        let final_state = drive_resources_fake(
            bounds,
            from,
            futures::stream::iter(vec![Ok(Some(resource_sample(10, 95.0, 512, 256)))]),
            std::sync::Arc::clone(&vm),
            CpuLifecycle::Running,
            std::sync::Arc::clone(&probes),
        )
        .await;
        assert_eq!(vm.applies().len(), 1);
        assert_eq!(vm.applies()[0].1.cpus, Some(2));
        assert_eq!(vm.applies()[0].1.memory_mib, None);
        assert_eq!(final_state.cpu.policy.current_cpus, 2);

        // Memory only: a growing memory need with CPU in deadband at 2.
        let vm = FakeResources::new(2, 512);
        let probes = fresh_probes();
        let final_state = drive_resources_fake(
            bounds,
            resource_state(2, 512),
            futures::stream::iter(vec![Ok(Some(resource_sample(10, 100.0, 512, 512)))]),
            std::sync::Arc::clone(&vm),
            CpuLifecycle::Running,
            std::sync::Arc::clone(&probes),
        )
        .await;
        assert_eq!(vm.applies().len(), 1);
        assert_eq!(vm.applies()[0].1.cpus, None);
        assert_eq!(vm.applies()[0].1.memory_mib, Some(768));
        assert_eq!(final_state.memory.policy.current_target_mib, 768);

        // Neither: a deadband row with converged memory emits no call at all.
        let vm = FakeResources::new(2, 512);
        let probes = fresh_probes();
        let _final_state = drive_resources_fake(
            bounds,
            resource_state(2, 512),
            futures::stream::iter(vec![Ok(Some(resource_sample(10, 100.0, 512, 256)))]),
            std::sync::Arc::clone(&vm),
            CpuLifecycle::Running,
            std::sync::Arc::clone(&probes),
        )
        .await;
        assert!(vm.applies().is_empty());
    }

    #[tokio::test]
    async fn corrective_cpu_recovery_is_rate_independent_and_keeps_outstanding_demand() {
        tokio::time::pause();
        let bounds = ResourceBounds {
            cpu: cpu_bounds(1, 4),
            memory: bounds(512, 512),
        };
        let vm = FakeResources::new(1, 512);
        vm.fail_live(1);
        let probes = fresh_probes();
        let mut from = resource_state(1, 512);
        from.cpu.policy.high_ticks = CPU_HIGH_TICKS - 1;
        // The tenth high proposes 2; the live apply fails with an unknown outcome.
        let final_state = drive_resources_fake(
            bounds,
            from,
            futures::stream::iter(vec![Ok(Some(resource_sample(10, 95.0, 512, 256)))]),
            std::sync::Arc::clone(&vm),
            CpuLifecycle::Running,
            std::sync::Arc::clone(&probes),
        )
        .await;
        assert_eq!(final_state.cpu.authority, TargetAuthority::Recovering);
        let outstanding = final_state
            .cpu
            .outstanding
            .expect("the unmet upward demand survives the failure");
        assert_eq!(outstanding.demand.target_cpus, 2);
        assert_eq!(outstanding.demand.direction, CpuDirection::Up);
        assert_eq!(outstanding.no_progress_attempts, 1);
        let after_failure = vm.applies().len();

        // A long run of published zeros: no demand decision, but correction must still land.
        let zeros: Vec<_> = (11..=310)
            .map(|second| Ok(Some(resource_sample(second, 0.0, 512, 256))))
            .collect();
        let final_state = drive_resources_fake(
            bounds,
            final_state,
            advancing_samples(zeros),
            std::sync::Arc::clone(&vm),
            CpuLifecycle::Running,
            std::sync::Arc::clone(&probes),
        )
        .await;
        let calls = vm.applies();
        assert!(calls.len() > after_failure, "the correction was attempted");
        // The first correction attempt is the immediate repeat: a distinct seed, then live 1.
        assert_eq!(
            calls[after_failure],
            (
                ResourceApplyMode::NextStart,
                ResourceTargets {
                    cpus: Some(2),
                    memory_mib: None,
                }
            ),
            "the boot-derived seed is distinct from the re-confirm target of 1"
        );
        assert_eq!(
            calls[after_failure + 1],
            (
                ResourceApplyMode::Live,
                ResourceTargets {
                    cpus: Some(1),
                    memory_mib: None,
                }
            )
        );
        assert_eq!(vm.enforced(), (1, 512));
        assert_eq!(final_state.cpu.authority, TargetAuthority::Confirmed);
        assert_eq!(final_state.cpu.last_accepted_cpus, 1);
        // The corrective re-confirmation proves no progress toward the unmet Up2 demand.
        let outstanding = final_state
            .cpu
            .outstanding
            .expect("correction must not clear outstanding demand");
        assert_eq!(outstanding.demand.target_cpus, 2);
        assert_eq!(
            outstanding.no_progress_attempts, 1,
            "a correction is not a normal no-progress attempt"
        );
        // After the successful correction, zero rows are silent: no demand, no more calls.
        let settled_calls = vm.applies().len();
        let final_state = drive_resources_fake(
            bounds,
            final_state,
            advancing_samples(
                (311..=400)
                    .map(|second| Ok(Some(resource_sample(second, 0.0, 512, 256))))
                    .collect(),
            ),
            std::sync::Arc::clone(&vm),
            CpuLifecycle::Running,
            std::sync::Arc::clone(&probes),
        )
        .await;
        assert_eq!(
            vm.applies().len(),
            settled_calls,
            "zero never authorises a decision"
        );
        assert_eq!(final_state.cpu.policy.high_ticks, 0);
        assert_eq!(final_state.cpu.policy.low_ticks, 0);
    }

    #[test]
    fn the_epoch_high_water_never_lowers_and_correction_is_explicit() {
        let second = |value: u64| std::time::UNIX_EPOCH + Duration::from_secs(value);
        let mut clock = CpuObservationClock::default();
        assert_eq!(
            observe_cpu_clock(&mut clock, second(100)),
            CpuObservation::Distinct
        );
        assert_eq!(
            observe_cpu_clock(&mut clock, second(100)),
            CpuObservation::Duplicate
        );
        assert_eq!(clock.high_water, Some(second(100)));
        // A100 -> B90 -> identical A100: B resets the streak, replay A is a duplicate.
        assert_eq!(
            observe_cpu_clock(&mut clock, second(90)),
            CpuObservation::Regressed
        );
        assert_eq!(
            observe_cpu_clock(&mut clock, second(100)),
            CpuObservation::Duplicate
        );
        assert_eq!(clock.high_water, Some(second(100)));
        // 99 regressed polls keep the high-water; the 100th re-anchors and is discarded.
        for _ in 0..99 {
            assert_eq!(
                observe_cpu_clock(&mut clock, second(90)),
                CpuObservation::Regressed
            );
            assert_eq!(clock.high_water, Some(second(100)));
        }
        assert_eq!(
            observe_cpu_clock(&mut clock, second(90)),
            CpuObservation::ClockCorrection
        );
        assert_eq!(clock.high_water, Some(second(90)));
        assert_eq!(clock.consecutive_regressed_polls, 0);
        // A genuinely advancing row below the *old* maximum starts the corrected epoch.
        assert_eq!(
            observe_cpu_clock(&mut clock, second(95)),
            CpuObservation::Distinct
        );
        assert_eq!(clock.high_water, Some(second(95)));
        // Equal timestamps interrupt the streak, so alternation cannot force a correction.
        let mut clock = CpuObservationClock::default();
        assert_eq!(
            observe_cpu_clock(&mut clock, second(200)),
            CpuObservation::Distinct
        );
        for _ in 0..1000 {
            assert_eq!(
                observe_cpu_clock(&mut clock, second(150)),
                CpuObservation::Regressed
            );
            assert_eq!(
                observe_cpu_clock(&mut clock, second(200)),
                CpuObservation::Duplicate
            );
        }
        assert_eq!(clock.high_water, Some(second(200)));
        // Below the current high-water is still a regression; advancing above it is evidence.
        assert_eq!(
            observe_cpu_clock(&mut clock, second(160)),
            CpuObservation::Regressed
        );
        assert_eq!(clock.high_water, Some(second(200)));
        assert_eq!(
            observe_cpu_clock(&mut clock, second(210)),
            CpuObservation::Distinct
        );
        assert_eq!(clock.high_water, Some(second(210)));
    }

    #[tokio::test]
    async fn a_replayed_row_is_a_duplicate_and_never_dispatches() {
        tokio::time::pause();
        let bounds = ResourceBounds {
            cpu: cpu_bounds(1, 4),
            memory: bounds(512, 512),
        };
        let vm = FakeResources::new(1, 512);
        let probes = fresh_probes();
        let samples = futures::stream::iter(vec![
            Ok(Some(resource_sample(100, 95.0, 512, 256))),
            Ok(Some(resource_sample(90, 90.0, 512, 256))),
            Ok(Some(resource_sample(100, 95.0, 512, 256))),
        ]);
        let final_state = drive_resources_fake(
            bounds,
            resource_state(1, 512),
            samples,
            std::sync::Arc::clone(&vm),
            CpuLifecycle::Running,
            std::sync::Arc::clone(&probes),
        )
        .await;
        assert!(vm.applies().is_empty(), "one high is not a run");
        assert_eq!(final_state.cpu.policy.current_cpus, 1);
        assert_eq!(final_state.cpu.policy.high_ticks, 0);
        assert_eq!(
            final_state.cpu_clock.high_water,
            Some(std::time::UNIX_EPOCH + Duration::from_secs(100))
        );
    }

    #[tokio::test]
    async fn slow_producers_advance_the_dwell_on_distinct_rows_not_polls() {
        // Plan T16: a 400 ms producer behind the 200 ms reader hands every sampled row to
        // two polls. Ten *distinct* highs must still take ten distinct rows (20 polls), not
        // ten polls, and the duplicate must neither count nor reset.
        tokio::time::pause();
        let vm = FakeResources::new(1, 512);
        let mut state = resource_state(1, 512);
        let mut stamp = 10_000u64;
        for distinct in 1..=10u64 {
            state = drive_one_poll(&vm, state, stamp, 95.0).await;
            state = drive_one_poll(&vm, state, stamp, 95.0).await;
            if distinct < 10 {
                assert!(
                    vm.applies().is_empty(),
                    "grew after {distinct} distinct highs at a 400 ms producer"
                );
                assert_eq!(state.cpu.policy.high_ticks, distinct as u32);
            }
            stamp += 400;
        }
        assert_eq!(vm.applies().len(), 1, "one grow apply, not two");
        assert_eq!(vm.enforced().0, 2);
        assert_eq!(state.cpu.policy.current_cpus, 2);
        assert_eq!(state.cpu.policy.high_ticks, 0);

        // A 600 ms producer hands each row to three polls: five distinct lows at C=2 shrink
        // once, on the fifth distinct row, and not before.
        let vm = FakeResources::new(2, 512);
        let mut state = resource_state(2, 512);
        let mut stamp = 10_000u64;
        for distinct in 1..=5u64 {
            for _ in 0..3 {
                state = drive_one_poll(&vm, state, stamp, 85.0).await;
            }
            if distinct < 5 {
                assert!(
                    vm.applies().is_empty(),
                    "shrank after {distinct} distinct lows at a 600 ms producer"
                );
                assert_eq!(state.cpu.policy.low_ticks, distinct as u32);
            }
            stamp += 600;
        }
        assert_eq!(vm.applies().len(), 1, "one shrink apply, not two");
        assert_eq!(vm.enforced().0, 1);
        assert_eq!(state.cpu.policy.current_cpus, 1);
        assert_eq!(state.cpu.policy.low_ticks, 0);
    }

    #[tokio::test]
    async fn an_admitted_memory_request_never_waits_for_a_lifecycle_probe() {
        tokio::time::pause();
        let bounds = ResourceBounds {
            cpu: cpu_bounds(1, 4),
            memory: bounds(512, 1024),
        };
        let vm = FakeResources::new(1, 512);
        let probes = fresh_probes();
        let mut from = resource_state(1, 512);
        // No cached eligibility: a probe would be needed for CPU.
        from.cpu_lifecycle = CpuLifecycleCache::default();
        let final_state = drive_resources_fake(
            bounds,
            from,
            futures::stream::iter(vec![Ok(Some(resource_sample(10, 95.0, 512, 512)))]),
            std::sync::Arc::clone(&vm),
            CpuLifecycle::Running,
            std::sync::Arc::clone(&probes),
        )
        .await;
        // Memory was dispatched alone, and CPU was deferred without a probe.
        assert_eq!(
            vm.applies(),
            vec![(
                ResourceApplyMode::Live,
                ResourceTargets {
                    cpus: None,
                    memory_mib: Some(768),
                },
            )]
        );
        assert_eq!(probe_count(&probes), 0, "never on the memory dispatch path");
        assert_eq!(
            final_state.cpu.policy.high_ticks, 0,
            "eligibility was unavailable"
        );

        // With no admitted memory request, the next distinct row may probe.
        let final_state = drive_resources_fake(
            bounds,
            final_state,
            futures::stream::iter(vec![Ok(Some(resource_sample(11, 95.0, 768, 256)))]),
            std::sync::Arc::clone(&vm),
            CpuLifecycle::Running,
            std::sync::Arc::clone(&probes),
        )
        .await;
        assert_eq!(probe_count(&probes), 1);
        assert_eq!(final_state.cpu.policy.high_ticks, 1);
        assert_eq!(final_state.cpu_lifecycle.value, CpuLifecycle::Running);
        // The cache is reused inside its TTL: a third row probes nothing.
        let _final_state = drive_resources_fake(
            bounds,
            final_state,
            futures::stream::iter(vec![Ok(Some(resource_sample(12, 95.0, 768, 256)))]),
            std::sync::Arc::clone(&vm),
            CpuLifecycle::Running,
            std::sync::Arc::clone(&probes),
        )
        .await;
        assert_eq!(probe_count(&probes), 1, "one probe per TTL");
    }

    #[tokio::test]
    async fn a_settled_paused_lifecycle_blocks_cpu_without_a_call() {
        tokio::time::pause();
        let bounds = ResourceBounds {
            cpu: cpu_bounds(1, 4),
            memory: bounds(512, 512),
        };
        let vm = FakeResources::new(1, 512);
        let probes = fresh_probes();
        let mut from = resource_state(1, 512);
        from.cpu_lifecycle = CpuLifecycleCache::default();
        let final_state = drive_resources_fake(
            bounds,
            from,
            advancing_samples(
                (10..=12)
                    .map(|second| Ok(Some(resource_sample(second, 95.0, 512, 256))))
                    .collect(),
            ),
            std::sync::Arc::clone(&vm),
            CpuLifecycle::NotRunning,
            std::sync::Arc::clone(&probes),
        )
        .await;
        assert!(vm.applies().is_empty(), "no CPU work while not running");
        assert_eq!(probe_count(&probes), 1, "one probe inside one TTL");
        assert_eq!(final_state.cpu.policy.high_ticks, 0);
        assert_eq!(final_state.cpu.policy.current_cpus, 1);
    }

    // ---- T10/T11: stage faults and malformed-return follow-through ----

    fn combined_request() -> ResourceResizeRequest {
        ResourceResizeRequest {
            cpu: Some(CpuResizeRequest {
                baseline_cpus: 1,
                target_cpus: 2,
                recovering: false,
            }),
            memory: Some(MemoryResizeRequest {
                baseline_mib: 512,
                target_mib: 768,
                recovering: false,
            }),
        }
    }

    async fn apply_to_fake(
        bounds: ResourceBounds,
        request: ResourceResizeRequest,
        vm: std::sync::Arc<FakeResources>,
    ) -> ResourceResizeOutcome {
        resize_resources_with(bounds, request, {
            let vm = std::sync::Arc::clone(&vm);
            move |mode, targets| {
                let vm = std::sync::Arc::clone(&vm);
                async move { vm.apply(mode, targets) }
            }
        })
        .await
    }

    #[tokio::test]
    async fn every_live_stage_failure_leaves_the_outcome_unknown_for_both_axes() {
        tokio::time::pause();
        let bounds = ResourceBounds {
            cpu: cpu_bounds(1, 4),
            memory: bounds(512, 1024),
        };
        // Stage order is the pinned SDK's: CPU control, CPU persist, memory control, memory
        // persist, desired persist. Each row is (fault, enforced, desired) after the call.
        let cases = [
            (StageFault::BeforeAny, (1, 512), (1, 512)),
            (StageFault::AfterCpuControl, (2, 512), (1, 512)),
            (StageFault::AfterCpuPersist, (2, 512), (2, 512)),
            (StageFault::AfterMemoryControl, (2, 768), (2, 512)),
            (StageFault::AfterMemoryPersist, (2, 768), (2, 768)),
            (StageFault::AfterDesiredPersist, (2, 768), (2, 768)),
        ];
        for (stage, enforced, desired) in cases {
            let vm = FakeResources::new(1, 512);
            vm.fail_at(stage);
            let outcome =
                apply_to_fake(bounds, combined_request(), std::sync::Arc::clone(&vm)).await;
            assert!(
                outcome.cpu.is_some_and(|result| result.is_err()),
                "{stage:?}: the CPU outcome must be unknown, never 'no effect'"
            );
            assert!(
                outcome.memory.is_some_and(|result| result.is_err()),
                "{stage:?}: the memory outcome must be unknown"
            );
            assert_eq!(
                vm.enforced(),
                enforced,
                "{stage:?} enforcement after the failure"
            );
            assert_eq!(
                vm.desired(),
                desired,
                "{stage:?} saved desired after the failure"
            );
            assert_eq!(
                vm.applies().len(),
                1,
                "{stage:?}: one live apply and no prepare for a fresh combined request"
            );
        }
    }

    #[tokio::test]
    async fn a_malformed_receipt_never_discards_the_other_axis() {
        tokio::time::pause();
        let bounds = ResourceBounds {
            cpu: cpu_bounds(1, 4),
            memory: bounds(512, 1024),
        };
        // CPU valid, memory malformed: both effects persist, only CPU is accepted.
        let vm = FakeResources::new(1, 512);
        vm.corrupt_receipt(Corrupt::MemoryReceipt);
        let outcome = apply_to_fake(bounds, combined_request(), std::sync::Arc::clone(&vm)).await;
        assert_eq!(
            outcome.cpu.and_then(Result::ok),
            Some(2),
            "the valid axis is confirmed"
        );
        assert!(
            outcome.memory.is_some_and(|result| result.is_err()),
            "the malformed axis is not"
        );
        assert_eq!(vm.enforced(), (2, 768), "both modelled effects stand");
        assert_eq!(vm.desired(), (2, 768));

        // Memory valid, CPU malformed: the inverse, with the same persisted state.
        let vm = FakeResources::new(1, 512);
        vm.corrupt_receipt(Corrupt::CpuReceipt);
        let outcome = apply_to_fake(bounds, combined_request(), std::sync::Arc::clone(&vm)).await;
        assert!(
            outcome.cpu.is_some_and(|result| result.is_err()),
            "the malformed CPU receipt is not authority"
        );
        assert_eq!(outcome.memory.and_then(Result::ok), Some(768));
        assert_eq!(vm.enforced(), (2, 768));
        assert_eq!(vm.desired(), (2, 768));
    }

    #[tokio::test]
    async fn a_malformed_cpu_receipt_recovers_through_policy_and_a_fresh_receipt() {
        tokio::time::pause();
        let bounds = ResourceBounds {
            cpu: cpu_bounds(1, 4),
            memory: bounds(512, 512),
        };
        let vm = FakeResources::new(1, 512);
        vm.corrupt_receipt(Corrupt::CpuReceipt);
        let mut from = resource_state(1, 512);
        from.cpu.policy.high_ticks = CPU_HIGH_TICKS - 1;
        let state = drive_resources_fake(
            bounds,
            from,
            futures::stream::iter(vec![Ok(Some(resource_sample(10, 95.0, 512, 256)))]),
            std::sync::Arc::clone(&vm),
            CpuLifecycle::Running,
            fresh_probes(),
        )
        .await;
        // The receipt was unusable: Recovering with history only, and the effect persisted.
        assert_eq!(state.cpu.authority, TargetAuthority::Recovering);
        assert_eq!(
            state.cpu.last_accepted_cpus, 1,
            "observations never become history"
        );
        assert_eq!(
            vm.enforced().0,
            2,
            "the malformed receipt did not undo the effect"
        );
        // Advance past the invalidation cooldown on a distinct zero row: the correction may
        // run, and it needs a real receipt of its own.
        let state = drive_resources_fake(
            bounds,
            state,
            advancing_samples(
                (11..=16)
                    .map(|second| Ok(Some(resource_sample(second, 0.0, 512, 256))))
                    .collect(),
            ),
            std::sync::Arc::clone(&vm),
            CpuLifecycle::Running,
            fresh_probes(),
        )
        .await;
        assert_eq!(state.cpu.authority, TargetAuthority::Confirmed);
        assert_eq!(state.cpu.last_accepted_cpus, 1);
        assert_eq!(
            vm.enforced().0,
            1,
            "the correction re-confirmed the accepted value"
        );
        let calls = vm.applies();
        let tail: Vec<_> = calls[calls.len() - 2..].to_vec();
        assert_eq!(
            tail,
            vec![
                (
                    ResourceApplyMode::NextStart,
                    ResourceTargets {
                        cpus: Some(2),
                        memory_mib: None
                    }
                ),
                (
                    ResourceApplyMode::Live,
                    ResourceTargets {
                        cpus: Some(1),
                        memory_mib: None
                    }
                ),
            ],
            "a durable seed distinct from the re-confirm target, then the live repair"
        );
        assert_eq!(
            state.cpu.policy.high_ticks, 0,
            "a fresh dwell is required after recovery"
        );
        // The malformed receipt was a normal no-progress attempt, and the corrective
        // re-confirmation must not erase the unmet demand or its count.
        let demand = state
            .cpu
            .outstanding
            .expect("the unmet Up2 demand survives recovery");
        assert_eq!(demand.demand.target_cpus, 2);
        assert_eq!(demand.no_progress_attempts, 1);
    }

    #[tokio::test]
    async fn a_failed_prepare_suppresses_only_its_own_axis() {
        tokio::time::pause();
        let bounds = ResourceBounds {
            cpu: cpu_bounds(1, 4),
            memory: bounds(512, 1024),
        };
        let vm = FakeResources::new(1, 512);
        vm.fail_prepare();
        let outcome = apply_to_fake(
            bounds,
            ResourceResizeRequest {
                cpu: Some(CpuResizeRequest {
                    baseline_cpus: 1,
                    target_cpus: 2,
                    recovering: false,
                }),
                memory: Some(MemoryResizeRequest {
                    baseline_mib: 512,
                    target_mib: 768,
                    recovering: true,
                }),
            },
            std::sync::Arc::clone(&vm),
        )
        .await;
        assert!(
            outcome.cpu.is_some_and(|result| result.is_ok()),
            "the healthy neighbour still applies"
        );
        assert!(
            outcome.memory.is_some_and(|result| result.is_err()),
            "the failed prepare suppresses only its own axis"
        );
        let applies = vm.applies();
        assert_eq!(applies.len(), 2, "one prepare, then one live apply");
        assert_eq!(
            applies[0],
            (
                ResourceApplyMode::NextStart,
                ResourceTargets {
                    cpus: None,
                    memory_mib: Some(640),
                }
            ),
            "the seed carries only the preparing axis"
        );
        assert_eq!(
            applies[1],
            (
                ResourceApplyMode::Live,
                ResourceTargets {
                    cpus: Some(2),
                    memory_mib: None,
                }
            )
        );
        assert_eq!(
            vm.enforced(),
            (2, 512),
            "the memory axis never reached control"
        );
    }

    // ---- T7: the CPU receipt decoder's own table ----

    #[test]
    fn accepted_cpu_target_decodes_only_a_usable_enforced_receipt() {
        let bounds = cpu_bounds(1, 4);
        let accepting = |requested: &str, actual: &str, enforced: &str| {
            modification_plan(
                true,
                vec![cpu_status(
                    microsandbox::sandbox::ResourceConvergenceState::Accepted,
                    requested,
                    actual,
                    enforced,
                )],
            )
        };
        // M3 as reported: requested 3, guest still converging at 2, enforcement 3.
        assert_eq!(
            accepted_cpu_target(&accepting("3", "2", "3"), bounds, 3).ok(),
            Some(3)
        );
        // Enforced is the authority even when it differs from the ask or from actual.
        assert_eq!(
            accepted_cpu_target(&accepting("3", "3", "2"), bounds, 3).ok(),
            Some(2)
        );
        for state in [
            microsandbox::sandbox::ResourceConvergenceState::Accepted,
            microsandbox::sandbox::ResourceConvergenceState::Converging,
            microsandbox::sandbox::ResourceConvergenceState::Applied,
        ] {
            let plan = modification_plan(true, vec![cpu_status(state, "2", "2", "2")]);
            assert_eq!(
                accepted_cpu_target(&plan, bounds, 2).ok(),
                Some(2),
                "{state:?}"
            );
        }
        // applied=false makes even a well-formed receipt unusable.
        assert!(
            accepted_cpu_target(
                &modification_plan(
                    false,
                    vec![cpu_status(
                        microsandbox::sandbox::ResourceConvergenceState::Accepted,
                        "2",
                        "2",
                        "2"
                    )]
                ),
                bounds,
                2
            )
            .is_err()
        );
        // Missing and duplicated statuses.
        assert!(accepted_cpu_target(&modification_plan(true, Vec::new()), bounds, 2).is_err());
        assert!(
            accepted_cpu_target(
                &modification_plan(
                    true,
                    vec![
                        cpu_status(
                            microsandbox::sandbox::ResourceConvergenceState::Accepted,
                            "2",
                            "2",
                            "2"
                        );
                        2
                    ]
                ),
                bounds,
                2
            )
            .is_err()
        );
        for state in [
            microsandbox::sandbox::ResourceConvergenceState::GuestRefused,
            microsandbox::sandbox::ResourceConvergenceState::Failed,
        ] {
            let plan = modification_plan(true, vec![cpu_status(state, "2", "2", "2")]);
            assert!(accepted_cpu_target(&plan, bounds, 2).is_err(), "{state:?}");
        }
        // Malformed, mismatched and out-of-range fields. Units, signs, whitespace, fractions,
        // overflow and an out-of-bounds enforced value are all rejected.
        for (requested, actual, enforced) in [
            ("", "2", "2"),
            ("-2", "2", "2"),
            ("2.0", "2", "2"),
            ("2 vCPU", "2", "2"),
            (" 2", "2", "2"),
            ("+2", "2", "2"),
            ("256", "2", "2"),
            ("99999999999999999999", "2", "2"),
            ("3", "2", "2"),
            ("2", "0", "2"),
            ("2", "5", "2"),
            ("2", "2", "0"),
            ("2", "2", "5"),
        ] {
            assert!(
                accepted_cpu_target(&accepting(requested, actual, enforced), bounds, 2).is_err(),
                "{requested:?}/{actual:?}/{enforced:?}"
            );
        }
        // A memory receipt cannot stand in for a CPU one.
        let memory_only = modification_plan(
            true,
            vec![memory_resize_status(
                microsandbox::sandbox::ResourceConvergenceState::Applied,
                "512 MiB",
                "512 MiB",
                "512 MiB",
            )],
        );
        assert!(accepted_cpu_target(&memory_only, bounds, 2).is_err());
        // The two-value interval's upper target is in bounds; five is not.
        assert!(accepted_cpu_target(&accepting("2", "2", "2"), cpu_bounds(1, 2), 2).is_ok());
        assert!(accepted_cpu_target(&accepting("2", "2", "2"), cpu_bounds(1, 1), 2).is_err());
    }

    // ---- T14: the retry schedule itself ----

    #[test]
    fn the_cpu_retry_schedule_is_exactly_the_declared_one() {
        // First repeat immediate, then 5, 10, ... capped at 50, saturating for any u32 count.
        assert_eq!(cpu_retry_delay(0), 0);
        assert_eq!(cpu_retry_delay(1), 0);
        for attempts in 2..=11u32 {
            assert_eq!(cpu_retry_delay(attempts), 5 * (attempts - 1), "{attempts}");
        }
        assert_eq!(cpu_retry_delay(12), 50);
        assert_eq!(cpu_retry_delay(u32::MAX), 50);
        // The same schedule backs memory's damping, so neither axis can drift alone.
        let mut retry: ResizeRetry<CpuCorrectionAsk> = ResizeRetry::default();
        let ask = CpuCorrectionAsk { target_cpus: 2 };
        for attempt in 0..3u32 {
            assert!(
                retry.admit(ask),
                "attempt {attempt} of a new identity is immediate"
            );
            retry.damp(ask);
            // Every poll ticks the clock: after the delay the same identity is re-admitted.
            for _ in 0..cpu_retry_delay(attempt + 1) {
                retry.waited = retry.waited.saturating_add(1);
            }
        }
        // A different target never inherits the count.
        let other = CpuCorrectionAsk { target_cpus: 3 };
        retry.damp(ask);
        assert!(retry.admit(other));
        assert_eq!(retry.attempts, 0);
    }

    #[tokio::test]
    async fn a_failure_after_the_seed_keeps_recovery_and_pacing() {
        tokio::time::pause();
        let bounds = ResourceBounds {
            cpu: cpu_bounds(1, 4),
            memory: bounds(512, 1024),
        };
        let vm = FakeResources::new(1, 512);
        // A recovering CPU axis with an unmet demand, and a live failure after the seed.
        let mut from = resource_state(1, 512);
        from.cpu.authority = TargetAuthority::Recovering;
        from.cpu.outstanding = Some(CpuOutstandingDemand {
            demand: CpuDemand {
                target_cpus: 2,
                direction: CpuDirection::Up,
            },
            anchor_cpus: 1,
            no_progress_attempts: 1,
            waited_polls: 0,
        });
        vm.fail_live(1);
        let state = drive_resources_fake(
            bounds,
            from,
            futures::stream::iter(vec![Ok(Some(resource_sample(10, 0.0, 512, 256)))]),
            std::sync::Arc::clone(&vm),
            CpuLifecycle::Running,
            fresh_probes(),
        )
        .await;
        // The seed persisted and the live call failed: desired is the seed, nothing enforced.
        let applies = vm.applies();
        assert_eq!(applies[0].0, ResourceApplyMode::NextStart);
        assert_eq!(vm.enforced(), (1, 512), "no live effect was claimed");
        assert_eq!(state.cpu.authority, TargetAuthority::Recovering);
        assert!(
            state.cpu.correction_retry.failed.is_some(),
            "the correction is damped"
        );
        assert_eq!(state.cpu.policy.high_ticks, 0);
        assert!(
            !state.cpu_lifecycle.valid,
            "the failure invalidated eligibility"
        );
        // The demand and its count survive: they are not the correction's to clear.
        let demand = state.cpu.outstanding.expect("demand survives");
        assert_eq!(demand.demand.target_cpus, 2);
        assert_eq!(demand.no_progress_attempts, 1);
        // Persisted effects are never rolled back by a later failure.
        assert_eq!(
            vm.desired().0,
            2,
            "the boot-derived seed (boot + 1 for a boot target) remains saved"
        );
    }

    // ---- T18: cancellation inside a combined recovery ----

    #[tokio::test]
    async fn cancelling_during_a_combined_live_apply_leaves_the_seed_and_stops_local_calls() {
        tokio::time::pause();
        let bounds = ResourceBounds {
            cpu: cpu_bounds(1, 4),
            memory: bounds(512, 1024),
        };
        let vm = FakeResources::new(1, 512);
        let gate = std::sync::Arc::new(tokio::sync::Notify::new());
        let entered = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let driving = tokio::spawn({
            let vm = std::sync::Arc::clone(&vm);
            let gate = std::sync::Arc::clone(&gate);
            let entered = std::sync::Arc::clone(&entered);
            async move {
                resize_resources_with(
                    bounds,
                    ResourceResizeRequest {
                        cpu: Some(CpuResizeRequest {
                            baseline_cpus: 1,
                            target_cpus: 2,
                            recovering: true,
                        }),
                        memory: Some(MemoryResizeRequest {
                            baseline_mib: 512,
                            target_mib: 768,
                            recovering: true,
                        }),
                    },
                    move |mode, targets| {
                        let vm = std::sync::Arc::clone(&vm);
                        let gate = std::sync::Arc::clone(&gate);
                        let entered = std::sync::Arc::clone(&entered);
                        async move {
                            if mode == ResourceApplyMode::Live {
                                // Suspend as the live apply is delivered, after the seed
                                // persisted and before any runtime control.
                                entered.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                gate.notified().await;
                            }
                            vm.apply(mode, targets)
                        }
                    },
                )
                .await
            }
        });
        let waiter = std::sync::Arc::clone(&entered);
        while waiter.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        // One combined seed, then the live apply is in flight; abort it.
        driving.abort();
        assert!(driving.await.unwrap_err().is_cancelled());
        let after_join = vm.applies().len();
        assert_eq!(
            after_join, 1,
            "the seed went out and the live call never did"
        );
        // The seed survived and the live effect was never delivered.
        assert_eq!(
            vm.desired(),
            (1, 640),
            "the combined seed for both recovering axes is durable"
        );
        assert_eq!(vm.enforced(), (1, 512), "the live apply never took effect");
        // Nothing else may happen after the join, even when time advances.
        tokio::time::advance(METRICS_SAMPLE_INTERVAL).await;
        tokio::task::yield_now().await;
        assert_eq!(vm.applies().len(), after_join);
    }

    // ---- T15 contention convergence (injected, never native) ----

    /// Drive segments, each 200 ticks at the rate the *current enforced* commitment produces.
    async fn drive_contention(
        bounds: ResourceBounds,
        from: ResourceControllerState,
        vm: std::sync::Arc<FakeResources>,
        rate_of: impl Fn(u8) -> f32,
        seconds_from: u64,
    ) -> (ResourceControllerState, u64) {
        let mut state = from;
        let mut second = seconds_from;
        for _ in 0..40 {
            let current = vm.enforced().0;
            let percent = rate_of(current);
            let rows: Vec<_> = (0..200)
                .map(|_| {
                    second += 1;
                    Ok(Some(resource_sample(second, percent, 512, 256)))
                })
                .collect();
            state = drive_resources_fake(
                bounds,
                state,
                futures::stream::iter(rows),
                std::sync::Arc::clone(&vm),
                CpuLifecycle::Running,
                fresh_probes(),
            )
            .await;
        }
        (state, second)
    }

    fn cpu_only_bounds() -> ResourceBounds {
        ResourceBounds {
            cpu: cpu_bounds(1, 4),
            memory: bounds(512, 512),
        }
    }

    #[tokio::test]
    async fn measured_busy_host_values_reach_stable_equilibria() {
        tokio::time::pause();
        // M5's three consecutive default-interval samples, held for 8 000 ticks each.
        for (measured, expected) in [(53.5f32, 1u8), (108.7, 2), (318.5, 4)] {
            let vm = FakeResources::new(4, 512);
            let (state, mut second) = drive_contention(
                cpu_only_bounds(),
                resource_state(4, 512),
                std::sync::Arc::clone(&vm),
                |_| measured,
                0,
            )
            .await;
            assert_eq!(
                vm.enforced().0,
                expected,
                "{measured}% settles at {expected}"
            );
            assert_eq!(state.cpu.policy.current_cpus, expected);
            // After convergence there is no alternating up/down dispatch.
            let before = vm.applies().len();
            let rows: Vec<_> = (0..200)
                .map(|_| {
                    second += 1;
                    Ok(Some(resource_sample(second, measured, 512, 256)))
                })
                .collect();
            let _state = drive_resources_fake(
                cpu_only_bounds(),
                state,
                futures::stream::iter(rows),
                std::sync::Arc::clone(&vm),
                CpuLifecycle::Running,
                fresh_probes(),
            )
            .await;
            assert_eq!(
                vm.applies().len(),
                before,
                "{measured}% is a stable equilibrium"
            );
        }
    }

    #[tokio::test]
    async fn all_core_demand_steps_one_at_a_time_to_the_ceiling() {
        tokio::time::pause();
        let vm = FakeResources::new(1, 512);
        let (state, _) = drive_contention(
            cpu_only_bounds(),
            resource_state(1, 512),
            std::sync::Arc::clone(&vm),
            |cpus| 100.0 * f32::from(cpus),
            0,
        )
        .await;
        let sequence: Vec<u8> = vm
            .applies()
            .iter()
            .filter_map(|(mode, targets)| {
                (*mode == ResourceApplyMode::Live)
                    .then_some(targets.cpus)
                    .flatten()
            })
            .collect();
        assert_eq!(
            sequence,
            vec![2, 3, 4],
            "ten distinct observations per step, never a jump"
        );
        assert_eq!(state.cpu.policy.current_cpus, 4);
        assert_eq!(vm.enforced().0, 4);
    }

    #[tokio::test]
    async fn severe_contention_settles_where_demand_meets_supply() {
        tokio::time::pause();
        // A fixed 53.5% per committed core: from 4 it must reclaim to 2 and hold.
        let vm = FakeResources::new(4, 512);
        let (state, _) = drive_contention(
            cpu_only_bounds(),
            resource_state(4, 512),
            std::sync::Arc::clone(&vm),
            |cpus| 53.5 * f32::from(cpus),
            0,
        )
        .await;
        assert_eq!(vm.enforced().0, 2);
        assert_eq!(state.cpu.policy.current_cpus, 2);
        // From 1 the same model cannot grow: one core at 53.5% is below 95%.
        let vm = FakeResources::new(1, 512);
        let (state, _) = drive_contention(
            cpu_only_bounds(),
            resource_state(1, 512),
            std::sync::Arc::clone(&vm),
            |cpus| 53.5 * f32::from(cpus),
            0,
        )
        .await;
        assert_eq!(state.cpu.policy.current_cpus, 1);
        assert!(vm.applies().is_empty());
    }

    // ---- Unknown outcomes and evidence reset after a failure ----
    //
    // These model a *failed or statusless apply* against a fresh cached Running reply. They do
    // not model a real pause: no oneshot barrier orders a pause, resume, probe reply, prepare or
    // live delivery, and nothing here observes a paused sandbox. The plan's T17b and T17c
    // barriers and its observable-pause trace are NOT implemented; see `verifications.md`.

    #[tokio::test]
    async fn a_failed_apply_after_a_fresh_running_reply_leaves_the_outcome_unknown() {
        tokio::time::pause();
        let bounds = cpu_only_bounds();
        let vm = FakeResources::new(1, 512);
        let probes = fresh_probes();
        let mut from = resource_state(1, 512);
        from.cpu.policy.high_ticks = CPU_HIGH_TICKS - 1;
        // The cached Running reply is fresh (a pause starts after it), and the live apply fails.
        vm.fail_live(1);
        let state = drive_resources_fake(
            bounds,
            from,
            futures::stream::iter(vec![Ok(Some(resource_sample(10, 95.0, 512, 256)))]),
            std::sync::Arc::clone(&vm),
            CpuLifecycle::Running,
            std::sync::Arc::clone(&probes),
        )
        .await;
        // Unknown outcome: Recovering, history retained, evidence reset, cache invalidated.
        assert_eq!(state.cpu.authority, TargetAuthority::Recovering);
        assert_eq!(state.cpu.last_accepted_cpus, 1);
        assert_eq!(state.cpu.policy.high_ticks, 0);
        assert!(
            !state.cpu_lifecycle.valid,
            "no failure is read as 'no effect'"
        );
        // Resume alone confirms nothing: a later duplicate neither probes nor corrects.
        let applied = vm.applies().len();
        let state = drive_resources_fake(
            bounds,
            state,
            futures::stream::iter(vec![Ok(Some(resource_sample(10, 0.0, 512, 256)))]),
            std::sync::Arc::clone(&vm),
            CpuLifecycle::Running,
            std::sync::Arc::clone(&probes),
        )
        .await;
        assert_eq!(vm.applies().len(), applied);
        assert_eq!(state.cpu.authority, TargetAuthority::Recovering);
    }

    #[tokio::test]
    async fn a_receipt_inside_one_ttl_is_the_only_evidence_of_what_happened() {
        tokio::time::pause();
        let bounds = cpu_only_bounds();
        // Case 1: the receipt is usable. Enforcement is accepted and the runs reset; the cache
        // is never treated as proof that no pause happened.
        let vm = FakeResources::new(1, 512);
        let mut from = resource_state(1, 512);
        from.cpu.policy.high_ticks = CPU_HIGH_TICKS - 1;
        let state = drive_resources_fake(
            bounds,
            from,
            futures::stream::iter(vec![Ok(Some(resource_sample(10, 95.0, 512, 256)))]),
            std::sync::Arc::clone(&vm),
            CpuLifecycle::Running,
            fresh_probes(),
        )
        .await;
        assert_eq!(vm.enforced().0, 2);
        assert_eq!(
            state.cpu.policy.high_ticks, 0,
            "pre-pause evidence never continues"
        );
        // Case 2: the receipt is not usable. Recovering with evidence reset and no rollback.
        let vm = FakeResources::new(1, 512);
        vm.fail_live(1);
        let mut from = resource_state(1, 512);
        from.cpu.policy.high_ticks = CPU_HIGH_TICKS - 1;
        let state = drive_resources_fake(
            bounds,
            from,
            futures::stream::iter(vec![Ok(Some(resource_sample(10, 95.0, 512, 256)))]),
            std::sync::Arc::clone(&vm),
            CpuLifecycle::Running,
            fresh_probes(),
        )
        .await;
        assert_eq!(state.cpu.authority, TargetAuthority::Recovering);
        assert_eq!(state.cpu.policy.high_ticks, 0);
        assert_eq!(state.cpu.last_accepted_cpus, 1);
    }

    // ---- T17a/T16: the lifecycle cache, the probe bound and the observation clock ----

    /// A cached Running reply whose TTL has already elapsed.
    fn stale_running_cache() -> CpuLifecycleCache {
        CpuLifecycleCache {
            value: CpuLifecycle::Running,
            valid: true,
            last_probe_started: Some(tokio::time::Instant::now() - Duration::from_secs(2)),
        }
    }

    /// The bound on one lifecycle await is 50 ms: a probe that never answers must not stall
    /// the monitor or admit CPU work. Removing the timeout hangs this trace.
    #[tokio::test]
    async fn a_stalled_lifecycle_probe_times_out_without_authorising_cpu_work() {
        tokio::time::pause();
        let vm = FakeResources::new(1, 512);
        let mut from = resource_state(1, 512);
        from.cpu.policy.high_ticks = CPU_HIGH_TICKS - 1;
        from.cpu_lifecycle = stale_running_cache();
        let probes = fresh_probes();
        let counted = std::sync::Arc::clone(&probes);
        let driven = drive_resources_with_probe(
            cpu_only_bounds(),
            from,
            advancing_samples(vec![timed_row(10_000, 95.0)]),
            std::sync::Arc::clone(&vm),
            move || {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async move {
                    std::future::pending::<()>().await;
                    Ok(CpuLifecycle::Running)
                }
            },
        );
        let state = tokio::time::timeout(Duration::from_secs(1), driven)
            .await
            .expect("the 50 ms probe bound ends the poll");
        assert_eq!(probe_count(&probes), 1);
        assert!(vm.applies().is_empty(), "no CPU work without eligibility");
        assert_eq!(state.cpu.policy.high_ticks, 0);
        assert_eq!(state.cpu_lifecycle.value, CpuLifecycle::Unavailable);
        assert!(state.cpu_lifecycle.valid);
    }

    /// A probe error is `Unavailable`, never `Running`, and never dispatches.
    #[tokio::test]
    async fn a_failed_lifecycle_probe_is_unavailable_and_never_running() {
        tokio::time::pause();
        let vm = FakeResources::new(1, 512);
        let mut from = resource_state(1, 512);
        from.cpu.policy.high_ticks = CPU_HIGH_TICKS - 1;
        from.cpu_lifecycle = stale_running_cache();
        let probes = fresh_probes();
        let counted = std::sync::Arc::clone(&probes);
        let state = drive_resources_with_probe(
            cpu_only_bounds(),
            from,
            futures::stream::iter(vec![timed_row(10_000, 95.0), timed_row(10_200, 95.0)]),
            std::sync::Arc::clone(&vm),
            move || {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async move { Err(anyhow::anyhow!("the sandbox handle is gone")) }
            },
        )
        .await;
        assert_eq!(probe_count(&probes), 1, "the failed reply is cached");
        assert!(vm.applies().is_empty());
        assert_eq!(state.cpu.policy.high_ticks, 0, "both runs stay reset");
        assert_eq!(state.cpu_lifecycle.value, CpuLifecycle::Unavailable);
        assert!(state.cpu_lifecycle.valid);
    }

    /// The cached reply is reused only inside its TTL; a later distinct row re-probes.
    #[tokio::test]
    async fn the_lifecycle_reply_is_reprobed_when_its_ttl_expires() {
        tokio::time::pause();
        let vm = FakeResources::new(1, 512);
        let mut from = resource_state(1, 512);
        from.cpu_lifecycle = stale_running_cache();
        let probes = fresh_probes();
        let counted = std::sync::Arc::clone(&probes);
        let rows: Vec<_> = (0..6u64)
            .map(|poll| timed_row(10_000 + 200 * poll, 95.0))
            .collect();
        let state = drive_resources_with_probe(
            cpu_only_bounds(),
            from,
            advancing_samples(rows),
            std::sync::Arc::clone(&vm),
            move || {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async move { Ok(CpuLifecycle::Running) }
            },
        )
        .await;
        // Five nominal polls fit one TTL, so 1.2 s of rows needs a second probe.
        assert_eq!(probe_count(&probes), 2);
        assert_eq!(state.cpu.policy.high_ticks, 6);
        assert!(vm.applies().is_empty());
    }

    /// A memory-only `Err` invalidates CPU eligibility and resets its runs, without marking
    /// the CPU axis Recovering: no CPU attempt was made.
    #[tokio::test]
    async fn a_memory_only_error_invalidates_cpu_eligibility() {
        tokio::time::pause();
        let bounds = ResourceBounds {
            cpu: cpu_bounds(1, 4),
            memory: bounds(512, 1024),
        };
        let vm = FakeResources::new(1, 512);
        vm.fail_live(1);
        // One row that asks memory to grow *and* carries a usable CPU rate.
        let row: anyhow::Result<Option<ResourceSample>> = Ok(Some(ResourceSample {
            memory: sample(512, 400),
            cpu_rate: cpu_rate_of(95.0),
            timestamp: std::time::UNIX_EPOCH + Duration::from_millis(10_000),
        }));
        let state = drive_resources_fake(
            bounds,
            resource_state(1, 512),
            futures::stream::iter(vec![row]),
            std::sync::Arc::clone(&vm),
            CpuLifecycle::Running,
            fresh_probes(),
        )
        .await;
        assert_eq!(state.memory.authority, TargetAuthority::Recovering);
        assert_eq!(
            state.cpu.authority,
            TargetAuthority::Confirmed,
            "the CPU axis made no attempt, so it is not Recovering"
        );
        assert!(
            !state.cpu_lifecycle.valid,
            "a failed apply may have involved a paused runtime"
        );
        assert_eq!(state.cpu.policy.high_ticks, 0);
    }

    /// The 100th consecutive regressed poll re-anchors the epoch, and with it the cache.
    #[tokio::test]
    async fn a_clock_correction_invalidates_the_cached_reply() {
        tokio::time::pause();
        let vm = FakeResources::new(1, 512);
        let mut from = resource_state(1, 512);
        from.cpu.policy.high_ticks = 4;
        from.cpu_clock.high_water = Some(std::time::UNIX_EPOCH + Duration::from_secs(600));
        let rows: Vec<_> = (0..100u64).map(|_| timed_row(1_000, 95.0)).collect();
        let state = drive_resources_fake(
            cpu_only_bounds(),
            from,
            futures::stream::iter(rows),
            std::sync::Arc::clone(&vm),
            CpuLifecycle::Running,
            fresh_probes(),
        )
        .await;
        assert!(
            !state.cpu_lifecycle.valid,
            "a clock correction discards the cached reply"
        );
        assert_eq!(state.cpu.policy.high_ticks, 0, "and the runs");
        assert!(vm.applies().is_empty());
        assert_eq!(
            state.cpu_clock.high_water,
            Some(std::time::UNIX_EPOCH + Duration::from_secs(1)),
            "the epoch re-anchored to the last regressed row"
        );
    }

    /// A duplicate is neutral only while its rate is usable; an unusable duplicate resets.
    #[tokio::test]
    async fn a_duplicate_with_an_unusable_rate_resets_both_runs() {
        tokio::time::pause();
        let vm = FakeResources::new(1, 512);
        let mut from = resource_state(1, 512);
        from.cpu.policy.high_ticks = 5;
        let state = drive_resources_fake(
            cpu_only_bounds(),
            from,
            futures::stream::iter(vec![timed_row(10_000, 95.0), timed_row(10_000, 0.0)]),
            std::sync::Arc::clone(&vm),
            CpuLifecycle::Running,
            fresh_probes(),
        )
        .await;
        assert_eq!(state.cpu.policy.high_ticks, 0);
        assert!(vm.applies().is_empty());
    }

    /// An absent row and a lookup error each reset both runs, so neither can grow on the one
    /// following high.
    #[tokio::test]
    async fn an_absent_row_or_lookup_error_resets_both_runs() {
        tokio::time::pause();
        let vm = FakeResources::new(1, 512);
        let mut from = resource_state(1, 512);
        from.cpu.policy.high_ticks = CPU_HIGH_TICKS - 1;
        from.cpu_clock.high_water = Some(std::time::UNIX_EPOCH + Duration::from_millis(10_000));
        // An absent row on its own.
        let absent = drive_resources_fake(
            cpu_only_bounds(),
            from,
            futures::stream::iter(vec![Ok(None)]),
            std::sync::Arc::clone(&vm),
            CpuLifecycle::Running,
            fresh_probes(),
        )
        .await;
        assert_eq!(absent.cpu.policy.high_ticks, 0, "an absent row resets");
        // A lookup error on its own.
        let error = drive_resources_fake(
            cpu_only_bounds(),
            from,
            futures::stream::iter(vec![Err(anyhow::anyhow!(
                "scripted metrics lookup failure"
            ))]),
            std::sync::Arc::clone(&vm),
            CpuLifecycle::Running,
            fresh_probes(),
        )
        .await;
        assert_eq!(error.cpu.policy.high_ticks, 0, "a lookup error resets");
        // And the one following high starts a new run instead of completing the old one.
        let state = drive_resources_fake(
            cpu_only_bounds(),
            from,
            futures::stream::iter(vec![Ok(None), timed_row(10_200, 95.0)]),
            std::sync::Arc::clone(&vm),
            CpuLifecycle::Running,
            fresh_probes(),
        )
        .await;
        assert!(
            vm.applies().is_empty(),
            "a reset nine-observation run cannot grow on one following high"
        );
        assert_eq!(
            state.cpu.policy.high_ticks, 1,
            "the following high starts over"
        );
    }

    /// A duplicate inside a live run neither counts, resets, nor costs a probe.
    #[tokio::test]
    async fn a_duplicate_inside_a_live_run_neither_counts_nor_probes() {
        tokio::time::pause();
        let vm = FakeResources::new(1, 512);
        let mut from = resource_state(1, 512);
        from.cpu_lifecycle = stale_running_cache();
        let probes = fresh_probes();
        let counted = std::sync::Arc::clone(&probes);
        let first = std::sync::Arc::clone(&counted);
        let probe = move || {
            first.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async move { Ok(CpuLifecycle::Running) }
        };
        let rows: Vec<_> = (0..9u64)
            .map(|poll| timed_row(10_000 + 200 * poll, 95.0))
            .collect();
        let state = drive_resources_with_probe(
            cpu_only_bounds(),
            from,
            advancing_samples(rows),
            std::sync::Arc::clone(&vm),
            probe,
        )
        .await;
        assert_eq!(state.cpu.policy.high_ticks, 9);
        let probes_before = probe_count(&probes);
        // The same timestamp again: a duplicate, and no other change.
        let state = drive_resources_with_probe(
            cpu_only_bounds(),
            state,
            advancing_samples(vec![timed_row(10_000 + 200 * 8, 95.0)]),
            std::sync::Arc::clone(&vm),
            {
                let second = std::sync::Arc::clone(&counted);
                move || {
                    second.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    async move { Ok(CpuLifecycle::Running) }
                }
            },
        )
        .await;
        assert_eq!(
            probe_count(&probes),
            probes_before,
            "a duplicate costs no probe"
        );
        assert_eq!(
            state.cpu.policy.high_ticks, 9,
            "and neither counts nor resets"
        );
        // The next distinct high completes the dwell.
        let state = drive_resources_with_probe(
            cpu_only_bounds(),
            state,
            advancing_samples(vec![timed_row(10_000 + 200 * 9, 95.0)]),
            std::sync::Arc::clone(&vm),
            {
                let third = std::sync::Arc::clone(&counted);
                move || {
                    third.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    async move { Ok(CpuLifecycle::Running) }
                }
            },
        )
        .await;
        assert_eq!(state.cpu.policy.current_cpus, 2);
        assert_eq!(vm.enforced().0, 2);
    }

    // ---- T14a/T14b: durable demand under capped enforcement, and its restoration ----

    /// One row at a chosen wall-clock instant, with 200 ms of paused time consumed per poll.
    fn timed_row(millis: u64, percent: f32) -> anyhow::Result<Option<ResourceSample>> {
        Ok(Some(ResourceSample {
            memory: sample(512, 256),
            cpu_rate: cpu_rate_of(percent),
            timestamp: std::time::UNIX_EPOCH + Duration::from_millis(millis),
        }))
    }

    /// Exactly one advancing poll, so a trace can record what each poll did.
    async fn drive_one_poll(
        vm: &std::sync::Arc<FakeResources>,
        state: ResourceControllerState,
        millis: u64,
        percent: f32,
    ) -> ResourceControllerState {
        drive_resources_fake(
            cpu_only_bounds(),
            state,
            advancing_samples(vec![timed_row(millis, percent)]),
            std::sync::Arc::clone(vm),
            CpuLifecycle::Running,
            fresh_probes(),
        )
        .await
    }

    /// The plan's capped-window call bound: `3 * (ceil(W / 50) + 1)`.
    fn capped_window_bound(polls: u64) -> usize {
        (3 * (polls.div_ceil(50) + 1)) as usize
    }

    #[tokio::test]
    async fn t14a_capped_under_enforcement_keeps_the_demand_and_paces_every_ask() {
        tokio::time::pause();
        let vm = FakeResources::new(1, 512);
        vm.cap_enforcement(1);
        let mut from = resource_state(1, 512);
        from.cpu.policy.high_ticks = CPU_HIGH_TICKS - 1;
        let mut state = from;
        // Poll indices of the live growth asks, and of every SDK call.
        let mut ask_polls: Vec<u64> = Vec::new();
        let mut call_polls: Vec<u64> = Vec::new();
        for poll in 0..2_000u64 {
            let before = vm.applies().len();
            state = drive_one_poll(&vm, state, 10_000 + 200 * poll, 390.0).await;
            let after = vm.applies();
            if after.len() > before {
                call_polls.push(poll);
                if after[before..].iter().any(|(mode, targets)| {
                    *mode == ResourceApplyMode::Live && targets.cpus == Some(2)
                }) {
                    ask_polls.push(poll);
                }
            }
            assert!(
                after.len() - before <= 2,
                "poll {poll}: at most one prepare and one live call, got {}",
                after.len() - before
            );
        }
        // The plan's bound counts an overlapping initial correction as well.
        assert!(
            !call_polls.is_empty() && call_polls.len() <= capped_window_bound(2_000),
            "calls {} exceed the capped-window bound {}",
            call_polls.len(),
            capped_window_bound(2_000)
        );
        // Recurrence: once the no-progress count has saturated the 50-poll delay, no two
        // normal asks are closer together than the delay itself.
        assert!(ask_polls.len() >= 5, "asks: {ask_polls:?}");
        // No ask can precede its own ten-observation dwell...
        for window in ask_polls.windows(2) {
            assert!(
                window[1] - window[0] >= 10,
                "asks {window:?} are closer than one dwell: {ask_polls:?}"
            );
        }
        // ...and once the delay has saturated at 50 polls, no two normal asks are closer
        // than the delay. The early asks follow 0/5/10/... as the count climbs.
        for window in ask_polls.windows(2).filter(|window| window[1] >= 1_000) {
            assert!(
                window[1] - window[0] >= 50,
                "asks {window:?} are closer than the capped delay: {ask_polls:?}"
            );
        }
        // The demand, its identity, its anchor and its history all survive 2 000 capped polls.
        let demand = state
            .cpu
            .outstanding
            .expect("2 000 capped polls do not clear the demand");
        assert_eq!(demand.demand.target_cpus, 2);
        assert_eq!(demand.demand.direction, CpuDirection::Up);
        assert_eq!(demand.anchor_cpus, 1);
        assert!(demand.no_progress_attempts >= 5, "{demand:?}");
        assert_eq!(vm.enforced().0, 1, "enforcement stayed capped");
        assert_eq!(vm.enforced().1, 512, "the memory axis was never asked");
    }

    #[tokio::test]
    async fn t14b_restored_enforcement_at_poll_1500_clears_the_demand_and_resumes_policy() {
        tokio::time::pause();
        let vm = FakeResources::new(1, 512);
        vm.cap_enforcement(1);
        let mut from = resource_state(1, 512);
        from.cpu.policy.high_ticks = CPU_HIGH_TICKS - 1;
        let mut state = from;
        for poll in 0..1_500u64 {
            state = drive_one_poll(&vm, state, 10_000 + 200 * poll, 390.0).await;
        }
        assert_eq!(vm.enforced().0, 1, "still capped at poll 1500");
        assert!(
            state.cpu.outstanding.is_some(),
            "the capped trace leaves an unmet demand"
        );
        // Enforcement becomes available inside the same trace, not in a fresh fake.
        vm.cap_enforcement(0);
        let mut cleared_at = None;
        for poll in 1_500..1_610u64 {
            let before = vm.applies().len();
            state = drive_one_poll(&vm, state, 10_000 + 200 * poll, 390.0).await;
            let applied = vm.applies().len() > before;
            if applied && state.cpu.outstanding.is_none() {
                cleared_at = Some(poll - 1_500);
                break;
            }
        }
        let cleared_after = cleared_at.expect(
            "a real receipt at the restored enforcement clears the Up2 demand within 110 polls",
        );
        assert!(cleared_after < 110, "cleared after {cleared_after} polls");
        assert_eq!(vm.enforced().0, state.cpu.policy.current_cpus);
        assert_eq!(state.cpu.policy.current_cpus, 2, "the growth landed");
        // Normal policy resumes without an external reset: sustained demand grows again.
        for poll in 1_610..1_625u64 {
            state = drive_one_poll(&vm, state, 10_000 + 200 * poll, 390.0).await;
        }
        assert_eq!(
            state.cpu.policy.current_cpus, 3,
            "a fresh ten-observation dwell grows to 3"
        );
        assert_eq!(vm.enforced().0, 3);
    }

    // ---- S-B through the driver: an unusable rate resets a run inside a fresh cache ----

    #[tokio::test]
    async fn a_published_zero_resets_a_nine_high_run_behind_a_fresh_lifecycle_cache() {
        tokio::time::pause();
        let bounds = cpu_only_bounds();
        let vm = FakeResources::new(1, 512);
        let mut from = resource_state(1, 512);
        from.cpu.policy.high_ticks = CPU_HIGH_TICKS - 1;
        // No time advance: the cached Running reply stays fresh across both rows, which is
        // exactly the state in which a zero row used to look like a duplicate.
        let state = drive_resources_fake(
            bounds,
            from,
            futures::stream::iter(vec![
                Ok(Some(resource_sample(10, 0.0, 512, 256))),
                Ok(Some(resource_sample(11, 95.0, 512, 256))),
            ]),
            std::sync::Arc::clone(&vm),
            CpuLifecycle::Running,
            fresh_probes(),
        )
        .await;
        assert!(
            vm.applies().is_empty(),
            "the zero reset the nine-observation run, so the 95 % row is its first"
        );
        assert_eq!(state.cpu.policy.current_cpus, 1);
        assert_eq!(state.cpu.policy.high_ticks, 1);
        assert!(state.cpu.outstanding.is_none());
    }

    // ---- Plan §3.4(b): a deadband or boundary hold ends the outstanding demand ----

    /// A capped Up 1→2 demand with a chosen failure count and ready run.
    ///
    /// Built directly: the record's own pacing is what these tests isolate, not the fake's
    /// equality behaviour after a persisted-but-under-enforced target.
    fn capped_up_record(no_progress_attempts: u32, high_ticks: u32) -> ResourceControllerState {
        let mut state = resource_state(1, 512);
        state.cpu.policy.high_ticks = high_ticks;
        state.cpu.outstanding = Some(CpuOutstandingDemand {
            demand: CpuDemand {
                target_cpus: 2,
                direction: CpuDirection::Up,
            },
            anchor_cpus: 1,
            no_progress_attempts,
            waited_polls: 0,
        });
        state
    }

    fn highs(
        first_second: u64,
        count: u64,
        percent: f32,
    ) -> Vec<anyhow::Result<Option<ResourceSample>>> {
        (0..count)
            .map(|offset| {
                Ok(Some(resource_sample(
                    first_second + offset,
                    percent,
                    512,
                    256,
                )))
            })
            .collect()
    }

    async fn drive_highs(
        vm: &std::sync::Arc<FakeResources>,
        state: ResourceControllerState,
        first_second: u64,
        count: u64,
    ) -> ResourceControllerState {
        drive_rows(vm, state, highs(first_second, count, 95.0)).await
    }

    async fn drive_rows(
        vm: &std::sync::Arc<FakeResources>,
        state: ResourceControllerState,
        rows: Vec<anyhow::Result<Option<ResourceSample>>>,
    ) -> ResourceControllerState {
        drive_resources_fake(
            cpu_only_bounds(),
            state,
            futures::stream::iter(rows),
            std::sync::Arc::clone(vm),
            CpuLifecycle::Running,
            fresh_probes(),
        )
        .await
    }

    #[tokio::test]
    async fn a_deadband_observation_ends_the_demand_and_the_renewed_dwell_owes_no_deadline() {
        tokio::time::pause();
        let vm = FakeResources::new(1, 512);
        vm.cap_enforcement(1);
        // One positive eligible deadband row at C=1 (50 % < 95 %): the demand is over.
        let state = drive_rows(
            &vm,
            capped_up_record(2, 0),
            vec![Ok(Some(resource_sample(10, 50.0, 512, 256)))],
        )
        .await;
        assert!(
            vm.applies().is_empty(),
            "a deadband row is never dispatched"
        );
        assert!(
            state.cpu.outstanding.is_none(),
            "a deadband hold on positive evidence ends the demand"
        );
        assert_eq!(
            state.cpu.policy.low_ticks, 0,
            "the deadband reset both runs"
        );
        // A renewed but incomplete dwell stays silent, and the tenth high starts a *fresh*
        // demand that is admitted at once instead of waiting for the old deadline.
        let state = drive_highs(&vm, state, 11, 9).await;
        assert_eq!(
            vm.applies().len(),
            0,
            "the renewed run is its own ten-observation dwell"
        );
        assert_eq!(state.cpu.policy.high_ticks, 9);
        let state = drive_highs(&vm, state, 21, 1).await;
        assert_eq!(
            vm.applies().len(),
            1,
            "the tenth high dispatches immediately"
        );
        assert_eq!(vm.applies()[0].1.cpus, Some(2));
        let demand = state.cpu.outstanding.expect("the new ask made no progress");
        assert_eq!(demand.demand.target_cpus, 2);
        assert_eq!(
            demand.no_progress_attempts, 1,
            "the renewed demand never inherits the old record's attempts"
        );
        assert_eq!(demand.waited_polls, 0);
    }

    #[tokio::test]
    async fn continuing_highs_retain_the_demand_until_the_ten_observation_dwell() {
        tokio::time::pause();
        let vm = FakeResources::new(1, 512);
        vm.cap_enforcement(1);
        // Nine highs continue the same direction: the record survives and the run keeps its
        // ready counter, but nothing is asked before the tenth observation.
        let state = drive_highs(&vm, capped_up_record(2, 0), 10, 9).await;
        assert!(vm.applies().is_empty(), "no ask before the tenth high");
        let demand = state
            .cpu
            .outstanding
            .expect("a continuing direction retains it");
        assert_eq!(demand.no_progress_attempts, 2);
        assert_eq!(demand.waited_polls, 9);
        assert_eq!(state.cpu.policy.high_ticks, 9, "the run keeps counting");
        // The tenth high proposes, and the five-poll delay has already passed: one ask.
        let state = drive_highs(&vm, state, 19, 1).await;
        assert_eq!(vm.applies().len(), 1, "the deadline admits exactly one ask");
        let demand = state.cpu.outstanding.expect("still unmet");
        assert_eq!(demand.no_progress_attempts, 3);
        assert_eq!(demand.waited_polls, 0);
    }

    #[tokio::test]
    async fn a_fourth_failure_holds_the_ready_run_until_its_fifteen_poll_deadline() {
        tokio::time::pause();
        let vm = FakeResources::new(1, 512);
        vm.cap_enforcement(1);
        // Three failures need ten polls and four need fifteen; a ready run re-proposes on
        // every high, so this is the state in which the delay refuses an ask.
        let state = drive_highs(&vm, capped_up_record(4, CPU_HIGH_TICKS - 1), 10, 14).await;
        assert!(
            vm.applies().is_empty(),
            "fourteen polls are below the fifteen-poll deadline"
        );
        let demand = state.cpu.outstanding.expect("retained across refusals");
        assert_eq!(demand.no_progress_attempts, 4);
        assert_eq!(demand.waited_polls, 14);
        assert_eq!(
            state.cpu.policy.high_ticks,
            CPU_HIGH_TICKS - 1,
            "a refused ask keeps the ready run for the next observation"
        );
        let state = drive_highs(&vm, state, 24, 1).await;
        assert_eq!(vm.applies().len(), 1, "the fifteenth poll admits the ask");
        assert_eq!(
            state
                .cpu
                .outstanding
                .map(|demand| demand.no_progress_attempts),
            Some(5)
        );
    }

    #[tokio::test]
    async fn a_down_supporting_observation_ends_an_up_demand() {
        tokio::time::pause();
        let vm = FakeResources::new(2, 512);
        vm.cap_enforcement(2);
        let mut from = resource_state(2, 512);
        from.cpu.policy.high_ticks = CPU_HIGH_TICKS - 1;
        let state = drive_resources_fake(
            cpu_only_bounds(),
            from,
            futures::stream::iter(vec![Ok(Some(resource_sample(10, 190.0, 512, 256)))]),
            std::sync::Arc::clone(&vm),
            CpuLifecycle::Running,
            fresh_probes(),
        )
        .await;
        assert_eq!(
            state.cpu.outstanding.map(|demand| demand.demand),
            Some(CpuDemand {
                target_cpus: 3,
                direction: CpuDirection::Up,
            })
        );
        // 80 % at C=2 is below the 85 % reclamation threshold: it supports a downward step, so
        // it is not evidence for the outstanding upward demand.
        let state = drive_resources_fake(
            cpu_only_bounds(),
            state,
            futures::stream::iter(vec![Ok(Some(resource_sample(11, 80.0, 512, 256)))]),
            std::sync::Arc::clone(&vm),
            CpuLifecycle::Running,
            fresh_probes(),
        )
        .await;
        assert!(
            state.cpu.outstanding.is_none(),
            "the opposite direction ends the demand"
        );
        assert_eq!(
            state.cpu.policy.low_ticks, 1,
            "the hold kept its downward run"
        );
        assert_eq!(vm.applies().len(), 1, "no second ask was made");
    }

    // ---- #647 CPU kernels: T1-T6 of the implementation plan ----

    fn cpu_bounds(boot_cpus: u8, max_cpus: u8) -> CpuBounds {
        CpuBounds {
            boot_cpus,
            max_cpus,
        }
    }

    /// `1..=4 vCPU`: the shape every adjustable production CPU launch has.
    fn adjustable_cpus() -> CpuBounds {
        cpu_bounds(1, 4)
    }

    fn cpu_state(current_cpus: u8, high_ticks: u32, low_ticks: u32) -> CpuState {
        CpuState {
            current_cpus,
            high_ticks,
            low_ticks,
        }
    }

    fn tenths(lower_tenths: u32, upper_tenths: u32) -> CpuRate {
        CpuRate {
            lower_tenths,
            upper_tenths,
        }
    }

    /// The production adapter over an SDK-shaped, non-optional percentage.
    fn rate(percent: f32) -> Option<CpuRate> {
        cpu_rate_of(percent)
    }

    /// One distinct demand-eligible observation at the adjustable production bounds.
    fn tick(state: CpuState, percent: f32) -> CpuState {
        cpu_tick(adjustable_cpus(), state, rate(percent))
    }

    fn run_high(state: CpuState, percent: f32, observations: usize) -> CpuState {
        let mut state = state;
        for _ in 0..observations {
            state = tick(state, percent);
        }
        state
    }

    fn run_low(state: CpuState, percent: f32, observations: usize) -> CpuState {
        run_high(state, percent, observations)
    }

    /// Independent widened arithmetic: f64 has room for the exact product, so this oracle
    /// is exact rather than approximate.
    fn tenths_oracle(value: f32) -> (u32, u32) {
        if value >= 25500.0 {
            return (MAX_CPU_RATE_TENTHS, MAX_CPU_RATE_TENTHS);
        }
        let exact = f64::from(value) * 10.0;
        let cap = f64::from(MAX_CPU_RATE_TENTHS);
        (exact.floor().min(cap) as u32, exact.ceil().min(cap) as u32)
    }

    #[test]
    fn cpu_rate_rejects_every_absence_and_non_finite_bit_pattern() {
        assert_eq!(cpu_rate_from_bits(0), None, "+0 publishes no rate");
        assert_eq!(cpu_rate_from_bits((-0.0f32).to_bits()), None);
        assert_eq!(cpu_rate_from_bits((-1.0f32).to_bits()), None);
        assert_eq!(cpu_rate_from_bits((-0.5f32).to_bits()), None);
        assert_eq!(cpu_rate_from_bits(f32::NAN.to_bits()), None);
        assert_eq!(cpu_rate_from_bits((-f32::NAN).to_bits()), None);
        assert_eq!(cpu_rate_from_bits(f32::INFINITY.to_bits()), None);
        assert_eq!(cpu_rate_from_bits(f32::NEG_INFINITY.to_bits()), None);
        assert_eq!(cpu_rate_of(0.0), None);
        // Positive values are observations, however small: the smallest subnormal and the
        // smallest normal are both below one tenth, not absent.
        assert_eq!(cpu_rate_from_bits(1), Some(tenths(0, 1)));
        assert_eq!(
            cpu_rate_from_bits(f32::MIN_POSITIVE.to_bits()),
            Some(tenths(0, 1))
        );
        assert_eq!(rate(0.05), Some(tenths(0, 1)));
    }

    #[test]
    fn cpu_rate_is_exact_at_both_policy_thresholds() {
        assert_eq!(rate(85.0), Some(tenths(850, 850)));
        assert_eq!(rate(95.0), Some(tenths(950, 950)));
        // The next representable float either side of a threshold must not cross it: scale
        // up uses the lower endpoint, scale down the upper one.
        let below_85 = f32::from_bits(85.0f32.to_bits() - 1);
        let above_85 = f32::from_bits(85.0f32.to_bits() + 1);
        assert!(below_85 < 85.0 && above_85 > 85.0);
        let below = rate(below_85).expect("a positive rate");
        let above = rate(above_85).expect("a positive rate");
        assert!(below.upper_tenths <= 850);
        assert_ne!(below, tenths(850, 850));
        assert!(above.lower_tenths >= 850);
        assert!(above.upper_tenths > 850);
        let below_95 = f32::from_bits(95.0f32.to_bits() - 1);
        let above_95 = f32::from_bits(95.0f32.to_bits() + 1);
        assert!(below_95 < 95.0 && above_95 > 95.0);
        assert!(rate(below_95).expect("a rate").lower_tenths < 950);
        assert!(rate(above_95).expect("a rate").lower_tenths >= 950);
    }

    #[test]
    fn cpu_rate_saturates_at_the_largest_realizable_ceiling() {
        assert_eq!(CPU_RATE_CAP_BITS, 25500.0f32.to_bits());
        let capped = Some(tenths(MAX_CPU_RATE_TENTHS, MAX_CPU_RATE_TENTHS));
        assert_eq!(rate(25500.0), capped);
        assert_eq!(rate(1.0e9), capped);
        assert_eq!(rate(f32::MAX), capped);
        let below_cap = f32::from_bits(CPU_RATE_CAP_BITS - 1);
        assert!(below_cap < 25500.0);
        let exact = rate(below_cap).expect("a rate");
        assert_eq!(exact.upper_tenths, MAX_CPU_RATE_TENTHS);
        assert_eq!(exact.lower_tenths, MAX_CPU_RATE_TENTHS - 1);
    }

    #[test]
    fn cpu_rate_conversion_matches_a_widened_float_oracle() {
        for value in [
            0.0001f32, 0.001, 0.1, 1.0, 10.0, 33.333, 84.999, 85.0, 94.999, 95.0, 100.0, 199.9,
            318.5, 1000.0, 25499.9,
        ] {
            let (lower, upper) = tenths_oracle(value);
            assert_eq!(rate(value), Some(tenths(lower, upper)), "{value}");
        }
        // A deterministic walk over positive finite encodings, including denormals.
        let mut bits = 1u32;
        let mut seen = 0u32;
        while seen < 20_000 {
            bits = bits.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let value = f32::from_bits(bits & 0x7fff_ffff);
            if !(value.is_finite() && value > 0.0) {
                continue;
            }
            seen += 1;
            let (lower, upper) = tenths_oracle(value);
            assert_eq!(
                cpu_rate_of(value),
                Some(tenths(lower, upper)),
                "bits {bits:#010x} value {value}"
            );
        }
    }

    #[test]
    fn cpu_rate_ratio_is_total_over_u32_inputs() {
        assert_eq!(cpu_rate_tenths(0, 5), None);
        assert_eq!(cpu_rate_tenths(5, 0), None);
        assert_eq!(cpu_rate_tenths(0, 0), None);
        assert_eq!(cpu_rate_tenths(1, u32::MAX), Some(tenths(0, 1)));
        assert_eq!(
            cpu_rate_tenths(u32::MAX, 1),
            Some(tenths(MAX_CPU_RATE_TENTHS, MAX_CPU_RATE_TENTHS))
        );
        assert_eq!(cpu_rate_tenths(u32::MAX, u32::MAX), Some(tenths(1, 1)));
        assert_eq!(cpu_rate_tenths(10, 3), Some(tenths(3, 4)));
        assert_eq!(cpu_rate_tenths(20, 3), Some(tenths(6, 7)));
        assert_eq!(cpu_rate_tenths(255_000, 1), Some(tenths(255_000, 255_000)));
        assert_eq!(cpu_rate_tenths(255_001, 1), Some(tenths(255_000, 255_000)));
        for numerator in 0..=64u32 {
            for denominator in 0..=64u32 {
                match cpu_rate_tenths(numerator, denominator) {
                    None => assert!(numerator == 0 || denominator == 0),
                    Some(measured) => {
                        assert!(numerator != 0 && denominator != 0);
                        assert!(measured.lower_tenths <= measured.upper_tenths);
                        assert!(measured.upper_tenths - measured.lower_tenths <= 1);
                        assert!(measured.upper_tenths > 0);
                        assert!(measured.upper_tenths <= MAX_CPU_RATE_TENTHS);
                    }
                }
            }
        }
    }

    #[test]
    fn ten_distinct_highs_grow_one_cpu_and_clear_both_runs() {
        let mut state = cpu_state(1, 0, 0);
        for observation in 1..=9u32 {
            state = tick(state, 95.0);
            assert_eq!(state, cpu_state(1, observation, 0));
        }
        state = tick(state, 95.0);
        assert_eq!(state, cpu_state(2, 0, 0));
        // The next step needs its own ten observations at the new commitment.
        state = run_high(state, 190.0, 9);
        assert_eq!(state, cpu_state(2, 9, 0));
        state = tick(state, 190.0);
        assert_eq!(state, cpu_state(3, 0, 0));
    }

    #[test]
    fn a_rounded_float_cannot_manufacture_a_high_observation() {
        assert_eq!(rate(94.999), Some(tenths(949, 950)));
        assert_eq!(run_high(cpu_state(1, 0, 0), 94.999, 20), cpu_state(1, 0, 0));
        assert_eq!(rate(189.999), Some(tenths(1899, 1900)));
        assert_eq!(
            run_high(cpu_state(2, 0, 0), 189.999, 20),
            cpu_state(2, 0, 0)
        );
    }

    #[test]
    fn interrupted_runs_never_grow() {
        // Nine highs then a deadband, repeated: the deadband resets the run.
        let mut state = cpu_state(1, 0, 0);
        for _ in 0..5 {
            state = run_high(state, 95.0, 9);
            assert_eq!(state, cpu_state(1, 9, 0));
            state = tick(state, 90.0);
            assert_eq!(state, cpu_state(1, 0, 0));
        }
        // A low observation breaks a high run.
        let state = run_high(cpu_state(2, 0, 0), 190.0, 4);
        assert_eq!(state, cpu_state(2, 4, 0));
        let state = tick(state, 85.0);
        assert_eq!(state, cpu_state(2, 0, 1));
        // A high observation breaks a low run.
        let state = tick(cpu_state(3, 0, 0), 170.0);
        assert_eq!(state, cpu_state(3, 0, 1));
        let state = run_high(state, 285.0, 1);
        assert_eq!(state, cpu_state(3, 1, 0));
    }

    #[test]
    fn one_busy_core_at_two_or_more_committed_cpus_is_deadband() {
        let mut state = cpu_state(2, 0, 0);
        for _ in 0..1000 {
            state = tick(state, 100.0);
        }
        assert_eq!(state, cpu_state(2, 0, 0));
        let mut state = cpu_state(2, 0, 0);
        for _ in 0..1000 {
            state = tick(state, 90.0);
        }
        assert_eq!(state, cpu_state(2, 0, 0));
        let mut state = cpu_state(4, 0, 0);
        for _ in 0..1000 {
            state = tick(state, 300.0);
        }
        assert_eq!(state, cpu_state(4, 0, 0));
    }

    #[test]
    fn five_distinct_lows_shrink_one_cpu_and_the_floor_holds() {
        let mut state = cpu_state(3, 0, 0);
        for observation in 1..=4u32 {
            state = tick(state, 170.0);
            assert_eq!(state, cpu_state(3, 0, observation));
        }
        state = tick(state, 170.0);
        assert_eq!(state, cpu_state(2, 0, 0));
        // 85% at C=2 is exactly the released-core threshold.
        let mut state = cpu_state(2, 0, 0);
        for observation in 1..=4u32 {
            state = tick(state, 85.0);
            assert_eq!(state, cpu_state(2, 0, observation));
        }
        state = tick(state, 85.0);
        assert_eq!(state, cpu_state(1, 0, 0));
        // The boot commitment is the floor: low demand holds it forever.
        let mut state = cpu_state(1, 0, 0);
        for _ in 0..50 {
            state = tick(state, 1.0);
        }
        assert_eq!(state, cpu_state(1, 0, 0));
    }

    #[test]
    fn a_rounded_float_cannot_manufacture_a_low_observation() {
        assert_eq!(rate(170.001), Some(tenths(1700, 1701)));
        assert_eq!(run_low(cpu_state(3, 0, 0), 170.001, 20), cpu_state(3, 0, 0));
        assert_eq!(rate(85.001), Some(tenths(850, 851)));
        assert_eq!(run_low(cpu_state(2, 0, 0), 85.001, 20), cpu_state(2, 0, 0));
    }

    #[test]
    fn the_ceiling_holds_saturated_load_without_overflow() {
        assert_eq!(run_high(cpu_state(4, 0, 0), 400.0, 100), cpu_state(4, 0, 0));
        // Over-long counters are normalized before any arithmetic, never wrapped.
        assert_eq!(
            run_high(cpu_state(4, u32::MAX, u32::MAX), 400.0, 10),
            cpu_state(4, 0, 0)
        );
        assert_eq!(
            run_low(cpu_state(1, u32::MAX, u32::MAX), 0.5, 10),
            cpu_state(1, 0, 0)
        );
    }

    /// What the runtime publishes after two equal cumulative vCPU-counter reads: a computed
    /// `0.0`. The registry encodes an absent rate the same way, which is the S-B ambiguity.
    fn rate_from_vcpu_counters(vcpu_time_ns: u64, elapsed_ns: u64) -> f32 {
        if elapsed_ns == 0 {
            return 0.0;
        }
        (vcpu_time_ns as f64 / elapsed_ns as f64 * 100.0) as f32
    }

    #[test]
    fn published_zero_never_authorises_a_cpu_decision() {
        let computed_zero = rate_from_vcpu_counters(0, 1_000_000_000);
        let missing_encoded_zero = 0.0f32;
        assert_eq!(computed_zero, missing_encoded_zero);
        assert_eq!(cpu_rate_of(computed_zero), None);
        assert_eq!(cpu_rate_of(missing_encoded_zero), None);
        // A thousand advancing zero rows cannot hold a low run, let alone shrink.
        let mut state = cpu_state(3, 0, 4);
        for _ in 0..1000 {
            state = cpu_tick(adjustable_cpus(), state, cpu_rate_of(computed_zero));
        }
        assert_eq!(state, cpu_state(3, 0, 0));
        // The next small positive rate starts a fresh low run from zero.
        for observation in 1..=4u32 {
            state = cpu_tick(adjustable_cpus(), state, cpu_rate_of(1.0));
            assert_eq!(state, cpu_state(3, 0, observation));
        }
        state = cpu_tick(adjustable_cpus(), state, cpu_rate_of(1.0));
        assert_eq!(state, cpu_state(2, 0, 0));
    }

    #[test]
    fn an_absent_or_invalid_rate_resets_the_run() {
        for absent in [
            None,
            Some(tenths(500, 600)),
            Some(tenths(901, 900)),
            Some(tenths(0, 0)),
            Some(tenths(0, 255_001)),
            cpu_rate_of(f32::NAN),
        ] {
            let state = cpu_tick(adjustable_cpus(), cpu_state(1, 9, 0), absent);
            assert_eq!(state, cpu_state(1, 0, 0), "{absent:?}");
            let state = cpu_tick(adjustable_cpus(), cpu_state(3, 0, 4), absent);
            assert_eq!(state, cpu_state(3, 0, 0), "{absent:?}");
        }
        // A gap before a high means the following high is the first of a new run.
        let mut state = cpu_state(1, 9, 0);
        state = cpu_tick(adjustable_cpus(), state, None);
        state = tick(state, 95.0);
        assert_eq!(state, cpu_state(1, 1, 0));
    }

    /// Independently written in widened `i64`: the whole ordered transition table, not the
    /// production expression.
    fn cpu_tick_oracle(bounds: CpuBounds, state: CpuState, measured: Option<CpuRate>) -> CpuState {
        let boot = i64::from(bounds.boot_cpus);
        let max = i64::from(bounds.max_cpus);
        if !(1 <= boot && boot <= max) {
            return cpu_state(bounds.boot_cpus, 0, 0);
        }
        let current = i64::from(state.current_cpus);
        let base = current.max(boot).min(max);
        let high = i64::from(state.high_ticks).min(9);
        let low = i64::from(state.low_ticks).min(4);
        let Some(measured) = measured else {
            return cpu_state(base as u8, 0, 0);
        };
        let lo = i64::from(measured.lower_tenths);
        let hi = i64::from(measured.upper_tenths);
        let usable = lo <= hi && hi <= 255_000 && hi - lo <= 1 && hi > 0;
        if !usable || !(boot <= current && current <= max) {
            return cpu_state(base as u8, 0, 0);
        }
        if base < max && lo >= 950 * base {
            return if high < 9 {
                cpu_state(base as u8, (high + 1) as u32, 0)
            } else {
                cpu_state((base + 1) as u8, 0, 0)
            };
        }
        if base > boot && hi <= 850 * (base - 1) {
            return if low < 4 {
                cpu_state(base as u8, 0, (low + 1) as u32)
            } else {
                cpu_state((base - 1) as u8, 0, 0)
            };
        }
        cpu_state(base as u8, 0, 0)
    }

    #[test]
    fn cpu_tick_matches_an_independent_widened_table() {
        // A valid session state and a rate centred on one of the two policy thresholds, so
        // every row of the transition table is reached. Drawing the endpoints independently
        // made a usable interval a 2-in-300 000 accident, and random bounds made a valid
        // state nearly impossible, so the threshold rows were never exercised at all.
        for_each_case(
            (
                (1u8..=4).prop_flat_map(|boot| (Just(boot), boot..=4u8)),
                0u8..=5,
                0u32..=12,
                0u32..=7,
                0u32..=1,
                prop_oneof![
                    3 => Just(0i64),
                    1 => -2i64..=-1,
                    1 => 1i64..=2,
                ],
                0u32..=4,
                0u8..=4,
            ),
            |(
                (boot_cpus, max_cpus),
                current_cpus,
                high_ticks,
                low_ticks,
                which_threshold,
                offset,
                width,
                kind,
            )| {
                let bounds = cpu_bounds(boot_cpus, max_cpus);
                let state = cpu_state(current_cpus, high_ticks, low_ticks);
                // Thresholds of the state's own commitment, and of the released vCPU below it.
                let up = i64::from(current_cpus) * i64::from(CPU_UP_TENTHS_PER_CORE);
                let down =
                    i64::from(current_cpus.saturating_sub(1)) * i64::from(CPU_DOWN_TENTHS_PER_CORE);
                let centre = if which_threshold == 0 { up } else { down };
                let lower_tenths =
                    (centre + offset).clamp(0, i64::from(MAX_CPU_RATE_TENTHS)) as u32;
                let measured = match kind {
                    // Usable when the interval is at most one tenth wide, which most cases
                    // are; wider ones are an unusable observation.
                    0..=2 => Some(tenths(lower_tenths, lower_tenths.saturating_add(width))),
                    // A published zero proves no demand decision.
                    3 => Some(tenths(0, 0)),
                    // An absent rate.
                    _ => None,
                };
                let next = cpu_tick(bounds, state, measured);
                prop_assert_eq!(next, cpu_tick_oracle(bounds, state, measured));
                prop_assert!(next.high_ticks < CPU_HIGH_TICKS);
                prop_assert!(next.low_ticks < CPU_LOW_TICKS);
                if boot_cpus >= 1 && boot_cpus <= max_cpus {
                    prop_assert!(next.current_cpus >= boot_cpus);
                    prop_assert!(next.current_cpus <= max_cpus);
                    prop_assert!(next.high_ticks == 0 || next.low_ticks == 0);
                    if current_cpus >= boot_cpus && current_cpus <= max_cpus {
                        let delta = i64::from(next.current_cpus) - i64::from(current_cpus);
                        prop_assert!((-1..=1).contains(&delta));
                    }
                }
                Ok(())
            },
        );
    }

    fn cpu_seed_oracle(bounds: CpuBounds, target: u8) -> Option<u8> {
        if bounds.boot_cpus < 1 || bounds.boot_cpus > bounds.max_cpus {
            return None;
        }
        if target < bounds.boot_cpus || target > bounds.max_cpus {
            return None;
        }
        if bounds.boot_cpus != target {
            return Some(bounds.boot_cpus);
        }
        if bounds.boot_cpus < bounds.max_cpus {
            return Some(bounds.boot_cpus + 1);
        }
        None
    }

    #[test]
    fn cpu_recovery_seed_is_total_and_complete() {
        for boot_cpus in 0..=255u8 {
            for max_cpus in [
                boot_cpus,
                boot_cpus.saturating_add(1),
                boot_cpus.saturating_add(7),
                255,
            ] {
                let bounds = cpu_bounds(boot_cpus, max_cpus);
                for target in 0..=255u8 {
                    let seed = cpu_recovery_seed(bounds, target);
                    assert_eq!(
                        seed,
                        cpu_seed_oracle(bounds, target),
                        "bounds {bounds:?} target {target}"
                    );
                    if let Some(chosen) = seed {
                        assert!(cpu_target_in_bounds(bounds, chosen));
                        assert_ne!(chosen, target);
                    }
                }
            }
        }
        // The declared two-value interval works for either target.
        assert_eq!(cpu_recovery_seed(cpu_bounds(1, 2), 1), Some(2));
        assert_eq!(cpu_recovery_seed(cpu_bounds(1, 2), 2), Some(1));
        assert_eq!(cpu_recovery_seed(cpu_bounds(254, 255), 254), Some(255));
        // A fixed interval, malformed bounds and an out-of-range target seed nothing.
        assert_eq!(cpu_recovery_seed(cpu_bounds(3, 3), 3), None);
        assert_eq!(cpu_recovery_seed(cpu_bounds(1, 1), 1), None);
        assert_eq!(cpu_recovery_seed(cpu_bounds(0, 4), 0), None);
        assert_eq!(cpu_recovery_seed(cpu_bounds(3, 2), 3), None);
        assert_eq!(cpu_recovery_seed(cpu_bounds(1, 4), 0), None);
        assert_eq!(cpu_recovery_seed(cpu_bounds(1, 4), 5), None);
    }

    #[test]
    fn cpu_target_bounds_reject_every_invalid_interval() {
        for boot_cpus in 0..=255u8 {
            for max_cpus in [0, boot_cpus, boot_cpus.saturating_add(1), 255] {
                let bounds = cpu_bounds(boot_cpus, max_cpus);
                for target in 0..=255u8 {
                    let expected = boot_cpus >= 1 && boot_cpus <= target && target <= max_cpus;
                    assert_eq!(
                        cpu_target_in_bounds(bounds, target),
                        expected,
                        "{bounds:?} {target}"
                    );
                }
            }
        }
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
                    (ResourceApplyMode::Live, 512),
                    (ResourceApplyMode::NextStart, 640),
                    (ResourceApplyMode::Live, 768),
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
                (ResourceApplyMode::Live, 768),
                (ResourceApplyMode::NextStart, 640),
                (ResourceApplyMode::Live, 768),
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
        assert_eq!(vm.sdk_actions(), vec![(ResourceApplyMode::Live, 768)]);
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
        assert_eq!(vm.sdk_actions(), vec![(ResourceApplyMode::Live, 768)]);
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
                (ResourceApplyMode::Live, 768),
                (ResourceApplyMode::NextStart, 640),
                (ResourceApplyMode::Live, 512),
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
        assert!(matches!(outcome, Err(ResourceResizeError::Unconfirmed(_))));
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
            vec![(ResourceApplyMode::NextStart, 512)],
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
                (ResourceApplyMode::NextStart, 512),
                (ResourceApplyMode::Live, 1024),
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
                (ResourceApplyMode::NextStart, 640),
                (ResourceApplyMode::Live, 512),
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
                (ResourceApplyMode::NextStart, 640),
                (ResourceApplyMode::Live, 512),
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
                    (ResourceApplyMode::NextStart, 640),
                    (ResourceApplyMode::NextStart, 768),
                    (ResourceApplyMode::Live, 640),
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
            .apply(ResourceApplyMode::Live, 640)
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

    /// Capture one fresh run through the driver into `capture`, at `max_level`.
    fn start_capture(capture: &Capture, case_id: &'static str, max_level: tracing::Level) {
        install_capture_subscriber();
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
    }

    fn stop_capture() {
        ACTIVE_CAPTURE.with(|slot| *slot.borrow_mut() = None);
    }

    /// M31: the CPU axis's own records are DEBUG only. A transition raised to `info` would
    /// reach normal output, so this asserts the event exists and that no monitor record rises
    /// above DEBUG, under a TRACE capture and again under a WARN filter.
    #[tokio::test]
    async fn cpu_evidence_logs_only_at_debug() {
        tokio::time::pause();
        for max_level in [tracing::Level::TRACE, tracing::Level::WARN] {
            let capture = Capture::default();
            start_capture(&capture, "cpu_transition", max_level);
            let bounds = cpu_only_bounds();
            let vm = FakeResources::new(1, 512);
            let mut from = resource_state(1, 512);
            from.cpu.policy.high_ticks = CPU_HIGH_TICKS - 1;
            let span = tracing::debug_span!(
                target: MONITOR_TARGET,
                "resource_commitment",
                sandbox = "unit-test-sandbox",
                case_id = "cpu_transition",
            );
            let driven = drive_resources_fake(
                bounds,
                from,
                futures::stream::iter(vec![Ok(Some(resource_sample(10, 95.0, 512, 256)))]),
                std::sync::Arc::clone(&vm),
                CpuLifecycle::Running,
                fresh_probes(),
            );
            let state = tracing::Instrument::instrument(driven, span).await;
            stop_capture();
            assert_eq!(
                state.cpu.policy.current_cpus, 2,
                "a real transition happened"
            );
            let events = capture.events();
            let monitor: Vec<&CapturedEvent> = events
                .iter()
                .filter(|event| event.target == MONITOR_TARGET)
                .collect();
            let named: Vec<&str> = monitor
                .iter()
                .filter_map(|event| event.fields.get("event").map(String::as_str))
                .collect();
            if max_level >= tracing::Level::DEBUG {
                assert!(
                    named.contains(&"cpu_transition"),
                    "the transition is recorded: {named:?}"
                );
                assert!(named.contains(&"cpu_poll"), "every poll is recorded");
                for event in &monitor {
                    assert_eq!(
                        event.level,
                        tracing::Level::DEBUG,
                        "CPU event {:?} is not DEBUG",
                        event.fields.get("event")
                    );
                }
            } else {
                assert!(
                    monitor.is_empty(),
                    "no CPU record survives a WARN filter: {named:?}"
                );
            }
        }
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
        let mut stream = std::pin::pin!(resource_samples(move || {
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
        assert_eq!(vm.sdk_actions(), vec![(ResourceApplyMode::NextStart, 640)]);
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

    /// Phase 0 native evidence for #647 (plan P0-A..P0-F). Ignored by default because it
    /// boots VMs; the only supported entry point is
    /// `script/test/cpu-commitment-native.sh`, which owns the isolated build, the explicit
    /// runtime/firmware pair and the retained evidence directory.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "native Phase 0 CPU evidence; run script/test/cpu-commitment-native.sh"]
    async fn native_cpu_commitment_evidence() {
        let report = crate::cpu_evidence::native::run().await;
        assert_eq!(
            report.verdict, "PASS",
            "native Phase 0 evidence did not pass: {}",
            report.detail
        );
    }
}
