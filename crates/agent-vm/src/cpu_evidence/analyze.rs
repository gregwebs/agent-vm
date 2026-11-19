//! VM-free analyzer for the Phase 0 native CPU-commitment evidence (plan P0-C, P0-D, T19).
//!
//! Everything here is a pure function over the authoritative raw poll log. It is written
//! independently of the (future) controller: a shadow policy counts opportunities at a
//! fixed commitment but never resizes, and the gate rejects the input contract before any
//! threshold could be retuned. Numeric verdicts use exact integers and exact binary
//! rationals, never displayed decimals (P0-D / N4).

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

/// Fraction of one core that counts as saturation of one committed vCPU, in tenths.
///
/// Calibration gate only: the analyzer applies the same predeclared 95/85/10/5 numbers the
/// future controller must use, so a measurement cannot silently pick its own thresholds.
pub(crate) const THRESHOLD_UP_TENTHS_PER_CORE: u32 = 950;
pub(crate) const THRESHOLD_DOWN_TENTHS_PER_CORE: u32 = 850;
pub(crate) const HIGH_TICKS: u32 = 10;
pub(crate) const LOW_TICKS: u32 = 5;

/// P0-B/P0-C declared volumes.
pub(crate) const SETTLING_DISTINCT_ROWS: usize = 5;
pub(crate) const COUNTED_DISTINCT_ROWS: usize = 60;
pub(crate) const COLLECTION_DEADLINE_NS: u128 = 180 * 1_000_000_000;

/// The first attempted poll after the fifth settling distinct row opens the counted span;
/// its clock is this many consecutive below-high-water polls (§3.2 N2).
pub(crate) const CLOCK_CORRECTION_REGRESSED_POLLS: u32 = 100;

/// P0-B quiet-host limits. Percentages are hundredths of a percent; core use is a rational.
pub(crate) const HOST_IDLE_MIN_HUNDREDTHS: u32 = 9_000;
pub(crate) const HOST_IDLE_SAMPLES: usize = 10;
pub(crate) const HOST_IDLE_MIN_PASSING: usize = 9;
pub(crate) const NON_OWNED_MEAN_MAX_NUM: u128 = 1;
pub(crate) const NON_OWNED_MEAN_MAX_DEN: u128 = 10;
pub(crate) const NON_OWNED_P95_MAX_NUM: u128 = 1;
pub(crate) const NON_OWNED_P95_MAX_DEN: u128 = 4;
pub(crate) const WORKLOAD_CHECKPOINT_MAX_GAP_NS: u128 = 2_000_000_000;

// ---------------------------------------------------------------------------
// Exact rates
// ---------------------------------------------------------------------------

/// Largest tenths value the policy accepts: 255 CPUs x 100% x 10 (plan §3.1).
const MAX_RATE_TENTHS: u128 = 255_000;

/// A positive finite `f32` percentage as an exact binary value `significand * 2^exponent`.
///
/// Every finite `f32` is such a value with a significand of at most 24 bits: the smallest
/// positive subnormal is `1 * 2^-149` and the largest finite value is `(2^24 - 1) * 2^104`.
/// Keeping the exponent symbolic means no power of two is ever materialised, so the whole
/// finite domain decodes exactly and no comparison can overflow (N4, P0-D). Verdicts use
/// these values, never the rounded decimal a log shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Rate {
    pub significand: u128,
    /// Signed binary exponent: the value is `significand * 2^exponent`.
    pub exponent: i32,
}

impl Rate {
    fn new(significand: u128, exponent: i32) -> Self {
        assert!(significand > 0, "a rate must be strictly positive");
        Self {
            significand,
            exponent,
        }
    }

    /// `self * factor`: exact while the product fits, which every caller keeps below 2^32.
    ///
    /// Used to compare median ratios as cross-multiplied binary values (`20 * C2` against
    /// `17 * C1`) instead of materialising a rational that could overflow.
    fn scaled(&self, factor: u128) -> Self {
        Self::new(self.significand * factor, self.exponent)
    }

    /// Position of the most significant bit: the value lies in `[2^(m-1), 2^m)`.
    ///
    /// Two values with equal `m` differ by a shift no larger than the smaller significand is
    /// long, so shifting both by the smaller exponent lands on integers that still fit in
    /// `u128`. That is what keeps every comparison exact without materialising powers.
    fn magnitude(&self) -> i64 {
        i64::from(128 - self.significand.leading_zeros()) + i64::from(self.exponent)
    }

    fn cmp_value(&self, other: &Self) -> Ordering {
        match self.magnitude().cmp(&other.magnitude()) {
            Ordering::Equal => {
                let pivot = self.exponent.min(other.exponent);
                let left = self.significand << (self.exponent - pivot) as u32;
                let right = other.significand << (other.exponent - pivot) as u32;
                left.cmp(&right)
            }
            decided => decided,
        }
    }

    /// Non-negative integer percentage such as 95 or 190, compared exactly.
    fn cmp_percent(&self, percent: u128) -> Ordering {
        if percent == 0 {
            return Ordering::Greater;
        }
        let bits = i64::from(128 - percent.leading_zeros());
        match self.magnitude().cmp(&bits) {
            Ordering::Equal if self.exponent >= 0 => {
                (self.significand << self.exponent as u32).cmp(&percent)
            }
            Ordering::Equal => self.significand.cmp(&(percent << (-self.exponent) as u32)),
            decided => decided,
        }
    }

    pub(crate) fn at_or_above(&self, percent: u128) -> bool {
        self.cmp_percent(percent) != Ordering::Less
    }

    pub(crate) fn at_or_below(&self, percent: u128) -> bool {
        self.cmp_percent(percent) != Ordering::Greater
    }

    pub(crate) fn below(&self, percent: u128) -> bool {
        self.cmp_percent(percent) == Ordering::Less
    }

    pub(crate) fn strictly_between(&self, low: u128, high: u128) -> bool {
        self.cmp_percent(low) == Ordering::Greater && self.cmp_percent(high) == Ordering::Less
    }

    /// `[floor(10 * value), ceil(10 * value)]`, both saturated at the declared cap.
    ///
    /// This interval is the only saturated quantity: the policy boundary scales up on
    /// `floor` and down on `ceil`, so a rate just below a threshold can never round into it
    /// (§3.1), while ordering and quantiles keep using the exact value.
    fn tenths(&self) -> (u32, u32) {
        let cap = MAX_RATE_TENTHS as u32;
        let scaled = self.significand * 10;
        if self.exponent >= 0 {
            // Integer value. Saturation is decided from bit lengths, never by overflow.
            if i64::from(128 - scaled.leading_zeros()) + i64::from(self.exponent) > 18 {
                return (cap, cap);
            }
            let whole = (scaled << self.exponent as u32).min(MAX_RATE_TENTHS) as u32;
            return (whole, whole);
        }
        let shift = -self.exponent as u32;
        if shift >= 128 {
            // Below one tenth of a percent, but strictly positive: `[0, 1]`, not absence.
            return (0, 1);
        }
        let whole = scaled >> shift;
        let exact = scaled.is_multiple_of(1u128 << shift);
        let lo = whole.min(MAX_RATE_TENTHS) as u32;
        let hi = if exact {
            lo
        } else {
            (whole + 1).min(MAX_RATE_TENTHS) as u32
        };
        (lo, hi)
    }

    /// Presentation only; every verdict uses the exact value.
    pub(crate) fn as_f64(&self) -> f64 {
        // `2^exponent` for -149 <= exponent <= 104 is an ordinary normal `f64`.
        let power = f64::from_bits(((i64::from(self.exponent) + 1023) as u64) << 52);
        self.significand as f64 * power
    }
}

/// An exact host-core ratio `num / den`, e.g. CPU nanoseconds over wall nanoseconds.
///
/// Host deltas are not dyadic, so they stay a rational; comparison cross-multiplies into a
/// full 256-bit product, so no pair of `u128` operands can overflow (N4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ratio {
    num: u128,
    den: u128,
}

impl Ratio {
    fn new(num: u128, den: u128) -> Self {
        assert!(den > 0, "a ratio needs a positive denominator");
        Self { num, den }
    }

    fn cmp_ratio(&self, other: &Self) -> Ordering {
        mul_wide(self.num, other.den).cmp(&mul_wide(other.num, self.den))
    }

    fn as_f64(&self) -> f64 {
        self.num as f64 / self.den as f64
    }
}

/// The full 256-bit product of two `u128`s as `(high, low)`; exact for every input pair.
fn mul_wide(a: u128, b: u128) -> (u128, u128) {
    const MASK: u128 = u64::MAX as u128;
    let (a_high, a_low) = (a >> 64, a & MASK);
    let (b_high, b_low) = (b >> 64, b & MASK);
    let low_low = a_low * b_low;
    let low_high = a_low * b_high;
    let high_low = a_high * b_low;
    let high_high = a_high * b_high;
    let middle = (low_low >> 64) + (low_high & MASK) + (high_low & MASK);
    let low = (low_low & MASK) | (middle << 64);
    let high = high_high + (low_high >> 64) + (high_low >> 64) + (middle >> 64);
    (high, low)
}

/// What a raw `f32` bit pattern means to the calibration gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Decoded {
    /// Sign set, NaN or infinity: retained as invalid, excluded from rate quantiles.
    Invalid,
    /// Positive (or negative) zero: a published zero is ambiguous, never demand.
    Zero,
    Positive(Rate),
}

/// Lossless decode of the SDK's `cpu_percent` bits over the whole finite `f32` domain.
pub(crate) fn decode_rate(bits: u32) -> Decoded {
    let sign = bits >> 31;
    let exponent = (bits >> 23) & 0xff;
    let fraction = bits & 0x7f_ffff;
    if sign == 1 || exponent == 0xff {
        return Decoded::Invalid;
    }
    if exponent == 0 {
        if fraction == 0 {
            return Decoded::Zero;
        }
        // Positive subnormal: `fraction * 2^-149`, exact at its true magnitude.
        return Decoded::Positive(Rate::new(u128::from(fraction), -149));
    }
    // Normal: `(2^23 + fraction) * 2^(exponent - 150)`, exact up to `(2^24 - 1) * 2^104`.
    Decoded::Positive(Rate::new(
        (1 << 23) | u128::from(fraction),
        exponent as i32 - 150,
    ))
}

/// Tenths-of-a-percent interval for the shadow threshold comparisons, using the
/// conservative floor/ceiling split the production boundary must also use (§3.1).
///
/// Returns `None` for anything the gate must not treat as a demand observation.
pub(crate) fn tenths_bounds(decoded: Decoded) -> Option<(u32, u32)> {
    let Decoded::Positive(rate) = decoded else {
        return None;
    };
    Some(rate.tenths())
}

// ---------------------------------------------------------------------------
// Raw evidence records
// ---------------------------------------------------------------------------

/// One attempted metrics read, in original attempted order. Every attempt is a record:
/// absent rows, timeouts and lookup errors are lines, not deletions (P0-C).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct PollRecord {
    pub poll_id: u64,
    pub trial: String,
    pub config: String,
    /// Monotonic host clock, ns. Scheduled and observed separately so lateness is visible.
    pub scheduled_ns: u64,
    pub read_start_ns: u64,
    pub read_end_ns: u64,
    /// SDK row timestamp in Unix nanoseconds; absent for a missing row or lookup error.
    pub sdk_timestamp_ns: Option<i128>,
    /// Raw `cpu_percent` bits, retained undecoded.
    pub cpu_percent_bits: Option<u32>,
    pub vcpu_time_ns: Option<u64>,
    pub memory_limit_bytes: Option<u64>,
    pub memory_available_bytes: Option<u64>,
    pub residency_present: Option<bool>,
    pub lifecycle_valid: bool,
    pub lifecycle_value: String,
    pub lifecycle_cache_age_ns: Option<u64>,
    pub probe_started_ns: Option<u64>,
    pub probe_ended_ns: Option<u64>,
    pub probe_result: Option<String>,
    pub probe_skipped: Option<String>,
    pub runtime_identity: Option<String>,
    pub error: Option<String>,
}

/// One host-quietness sample; percentages are hundredths so comparisons stay integral.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct HostSample {
    pub kind: String,
    pub at_ns: u64,
    pub idle_hundredths: u32,
}

/// One one-second CPU-time delta for one non-owned process.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ProcessDelta {
    /// Which sampling interval this delta belongs to; intervals are aggregated before the
    /// host-core mean/p95, because the limit is on host load, not on one process's share.
    pub sample_id: u64,
    pub pid: u32,
    pub command: String,
    pub cpu_ns: u64,
    pub wall_ns: u64,
    pub excluded: bool,
}

/// Guest workload checkpoints, one per worker per second, plus start/end records.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct WorkloadCheckpoint {
    pub worker: u32,
    pub pid: u32,
    pub kind: String,
    pub monotonic_ns: u128,
    pub process_time_ns: u128,
    pub iterations: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct WorkloadReport {
    pub workers: u32,
    pub duty_percent: u32,
    pub ready: bool,
    pub checkpoints: Vec<WorkloadCheckpoint>,
}

// ---------------------------------------------------------------------------
// Observation clock (§3.2 N2), independently implemented
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Clock {
    /// No row or a lookup error: interrupt evidence, keep the high-water.
    Gap,
    /// A timestamp strictly above the high-water.
    Distinct,
    /// The same timestamp as the high-water.
    Duplicate,
    /// A timestamp below the high-water, before the correction threshold.
    Regressed,
    /// The 100th consecutive regression: re-anchor and discard this row.
    Reanchor,
}

/// The same-owned-slot host-UTC epoch rule. The high-water never decreases except at the
/// declared correction, which bounds replay re-admission to one row per streak.
#[derive(Default)]
pub(crate) struct ObservationClock {
    high_water: Option<i128>,
    regressed: u32,
}

impl ObservationClock {
    pub(crate) fn observe(&mut self, timestamp: Option<i128>) -> Clock {
        let Some(stamp) = timestamp else {
            self.regressed = 0;
            return Clock::Gap;
        };
        match self.high_water {
            None => {
                self.high_water = Some(stamp);
                self.regressed = 0;
                Clock::Distinct
            }
            Some(high) if stamp > high => {
                self.high_water = Some(stamp);
                self.regressed = 0;
                Clock::Distinct
            }
            Some(high) if stamp == high => {
                self.regressed = 0;
                Clock::Duplicate
            }
            Some(_) => {
                self.regressed = self.regressed.saturating_add(1);
                if self.regressed >= CLOCK_CORRECTION_REGRESSED_POLLS {
                    self.high_water = Some(stamp);
                    self.regressed = 0;
                    Clock::Reanchor
                } else {
                    Clock::Regressed
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Shadow policy runs (fixed C, no resize)
// ---------------------------------------------------------------------------

/// The fixed commitment a shadow run observes, with the declared interval bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Commitment {
    /// The commitment held for the whole calibration trial.
    pub cpus: u8,
    pub boot_cpus: u8,
    pub max_cpus: u8,
}

/// Which ceiling rule a shadow run applies to growth opportunities.
///
/// The production controller only proposes growth while `cpus < max_cpus`, so a shadow of
/// that policy must stay silent at the ceiling. The calibration criterion is different: it
/// grades a *threshold* opportunity at the declared fixed commitment, and the C=4
/// all-workers trial is deliberately measured at the 4-CPU ceiling, where four complete high
/// runs still have to be visible (P0-D). Both are counted, so the ceiling hold stays modelled
/// and testable next to the criterion it must not change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GrowthPolicy {
    /// Threshold opportunity at the fixed commitment, ceiling ignored: the calibration row.
    FixedThreshold,
    /// Opportunity the production controller would propose: none without headroom.
    CeilingInhibited,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Runs {
    pub high: u32,
    pub low: u32,
    pub longest_high: u32,
    pub longest_low: u32,
    pub high_opportunities: u32,
    pub low_opportunities: u32,
}

impl Runs {
    /// One attempted poll at the fixed `commitment`.
    ///
    /// `lifecycle_running` is the cached/probed eligibility; `rate` is the raw observation.
    pub(crate) fn step(
        &mut self,
        policy: GrowthPolicy,
        clock: Clock,
        lifecycle_running: bool,
        rate: Option<Decoded>,
        commitment: Commitment,
    ) {
        let Commitment {
            cpus,
            boot_cpus,
            max_cpus,
        } = commitment;
        let usable = lifecycle_running
            && matches!(rate, Some(Decoded::Positive(_)))
            && tenths_bounds(rate.unwrap_or(Decoded::Invalid)).is_some();
        match clock {
            Clock::Duplicate => {
                // A duplicate neither advances nor resets a run when it is still usable;
                // an unusable rate or an observed-blocked lifecycle resets evidence.
                if !usable {
                    self.reset();
                }
            }
            Clock::Distinct if usable => {
                let (lo, hi) = tenths_bounds(rate.expect("checked positive")).expect("bounds");
                let up = u32::from(cpus) * THRESHOLD_UP_TENTHS_PER_CORE;
                let down = u32::from(cpus.saturating_sub(1)) * THRESHOLD_DOWN_TENTHS_PER_CORE;
                let may_grow = match policy {
                    GrowthPolicy::FixedThreshold => true,
                    GrowthPolicy::CeilingInhibited => cpus < max_cpus,
                };
                if may_grow && lo >= up {
                    self.high = self.high.saturating_add(1);
                    self.low = 0;
                    self.longest_high = self.longest_high.max(self.high);
                    if self.high >= HIGH_TICKS {
                        self.high_opportunities = self.high_opportunities.saturating_add(1);
                        self.high = 0;
                    }
                } else if cpus > boot_cpus && hi <= down {
                    self.low = self.low.saturating_add(1);
                    self.high = 0;
                    self.longest_low = self.longest_low.max(self.low);
                    if self.low >= LOW_TICKS {
                        self.low_opportunities = self.low_opportunities.saturating_add(1);
                        self.low = 0;
                    }
                } else {
                    // Deadband, a ceiling-inhibited high row, or the boot floor: reset both.
                    self.reset();
                }
            }
            // Gap, regression, correction row, or an unusable distinct observation.
            _ => self.reset(),
        }
    }

    fn reset(&mut self) {
        self.high = 0;
        self.low = 0;
    }
}

/// Whether a block of counted distinct rows supplies a complete run.
///
/// Each block starts empty and sees every raw attempt between its first and last distinct
/// row, so an interleaved gap/regression/zero breaks it (P0-C).
fn block_completes(
    attempts: &[PollRecord],
    first: usize,
    last: usize,
    commitment: Commitment,
    want_high: bool,
) -> bool {
    let mut runs = Runs::default();
    let mut clock = ObservationClock::default();
    for record in &attempts[first..=last] {
        let observation = clock.observe(record.sdk_timestamp_ns);
        let lifecycle = record.lifecycle_valid && record.lifecycle_value == "running";
        let rate = record.cpu_percent_bits.map(decode_rate);
        // A block is a calibration criterion, so it counts threshold opportunities at the
        // declared fixed commitment (the C=4 row is at the ceiling by construction).
        runs.step(
            GrowthPolicy::FixedThreshold,
            observation,
            lifecycle,
            rate,
            commitment,
        );
    }
    if want_high {
        runs.high_opportunities > 0
    } else {
        runs.low_opportunities > 0
    }
}

// ---------------------------------------------------------------------------
// Per-trial specification and verdicts
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum TrialShape {
    /// One worker at 100%: unit separation and the one-core interpretation.
    OneWorkerFull,
    /// `C` workers at 100%: all-core saturation.
    AllWorkersFull,
    /// One worker at 80%: low-run/shrink evidence.
    OneWorkerEighty,
    /// One worker at 90%: deadband evidence.
    OneWorkerNinety,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct TrialSpec {
    pub trial: String,
    pub config: String,
    pub memory_mib: u32,
    pub boot_cpus: u8,
    pub max_cpus: u8,
    /// Fixed commitment during calibration; the shadow controller never moves it.
    pub cpus: u8,
    pub workers: u32,
    pub duty_percent: u32,
    pub phase_ms: u64,
    /// 1 or 2: which matched trial of the configuration. Cross-configuration comparisons use
    /// the same trial number, never a pooled statistic.
    pub trial_index: u8,
    pub shape: TrialShape,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct TrialAnalysis {
    pub trial: String,
    pub config: String,
    pub attempts: usize,
    pub distinct_total: usize,
    pub counted_distinct: usize,
    pub invalid: usize,
    pub zero: usize,
    pub positive: usize,
    pub duplicates: usize,
    pub gaps: usize,
    pub regressed: usize,
    pub corrections: usize,
    pub longest_high: u32,
    pub longest_low: u32,
    /// Threshold opportunities at the declared fixed commitment: the calibration criterion.
    pub high_opportunities: u32,
    pub low_opportunities: u32,
    /// Growth opportunities the production ceiling-inhibited policy would propose. Identical
    /// to `high_opportunities` below the ceiling and zero at it.
    pub proposal_high_opportunities: u32,
    pub high_blocks_complete: usize,
    pub low_blocks_complete: usize,
    pub median: Option<Rate>,
    pub p5: Option<Rate>,
    pub p95: Option<Rate>,
    pub elapsed_ns: u128,
    pub failures: Vec<String>,
    pub inconclusive: Vec<String>,
}

impl TrialAnalysis {
    pub(crate) fn passed(&self) -> bool {
        self.failures.is_empty() && self.inconclusive.is_empty()
    }

    pub(crate) fn verdict(&self) -> &'static str {
        if !self.inconclusive.is_empty() {
            "INCONCLUSIVE"
        } else if !self.failures.is_empty() {
            "FAIL"
        } else {
            "PASS"
        }
    }
}

/// Nearest-rank quantile on ascending samples: `x[max(1, ceil(p*n/100))]`, no interpolation.
pub(crate) fn nearest_rank<T: Copy>(sorted: &[T], percentile: u32) -> Option<T> {
    if sorted.is_empty() || percentile == 0 || percentile > 100 {
        return None;
    }
    let n = sorted.len() as u128;
    let rank = (n * u128::from(percentile)).div_ceil(100).max(1);
    sorted.get((rank - 1) as usize).copied()
}

fn median_rate(sorted: &[Rate]) -> Option<Rate> {
    sorted
        .get((sorted.len() / 2).saturating_sub(usize::from(sorted.len().is_multiple_of(2))))
        .copied()
}

fn quantile_rate(sorted: &[Rate], percentile: u32) -> Option<Rate> {
    nearest_rank(sorted, percentile)
}

/// P0-B workload qualification: delivered duty per worker and checkpoint continuity.
pub(crate) fn qualify_workload(report: &WorkloadReport) -> Vec<String> {
    let mut reasons = Vec::new();
    if !report.ready {
        reasons.push("guest parent never reported all workers ready".to_string());
    }
    let mut workers: Vec<u32> = report.checkpoints.iter().map(|c| c.worker).collect();
    workers.sort_unstable();
    workers.dedup();
    if workers.len() as u32 != report.workers {
        reasons.push(format!(
            "expected {} workers in the workload report, saw {}",
            report.workers,
            workers.len()
        ));
    }
    let (low, high) = match report.duty_percent {
        80 => (75u128, 85u128),
        90 => (86, 94),
        100 => (95, 105),
        other => {
            reasons.push(format!("undeclared duty {other}%"));
            (0, 0)
        }
    };
    for worker in workers {
        let mut points: Vec<&WorkloadCheckpoint> = report
            .checkpoints
            .iter()
            .filter(|c| c.worker == worker)
            .collect();
        points.sort_by_key(|c| c.monotonic_ns);
        let Some(first) = points.first().copied() else {
            reasons.push(format!("worker {worker} has no checkpoints"));
            continue;
        };
        let Some(last) = points.last().copied() else {
            continue;
        };
        let elapsed = last.monotonic_ns.saturating_sub(first.monotonic_ns);
        let delivered = last.process_time_ns.saturating_sub(first.process_time_ns);
        if elapsed == 0 {
            reasons.push(format!("worker {worker} has a zero-length delivery window"));
            continue;
        }
        // percent = delivered * 100 / elapsed, compared exactly.
        let percent_num = delivered * 100;
        if percent_num < low * elapsed || percent_num > high * elapsed {
            reasons.push(format!(
                "worker {worker} delivered {:.2}% CPU, outside {low}..={high}%",
                delivered as f64 * 100.0 / elapsed as f64
            ));
        }
        for pair in points.windows(2) {
            if pair[1].monotonic_ns.saturating_sub(pair[0].monotonic_ns)
                > WORKLOAD_CHECKPOINT_MAX_GAP_NS
            {
                reasons.push(format!(
                    "worker {worker} checkpoint gap exceeds 2 s at {}",
                    pair[1].monotonic_ns
                ));
            }
        }
    }
    reasons
}

/// P0-B quiet-host qualification from the ten pre-trial idle samples.
pub(crate) fn qualify_idle(samples: &[HostSample]) -> Vec<String> {
    let mut reasons = Vec::new();
    if samples.len() < HOST_IDLE_SAMPLES {
        reasons.push(format!(
            "only {} of {HOST_IDLE_SAMPLES} pre-trial idle samples were recorded",
            samples.len()
        ));
    }
    let passing = samples
        .iter()
        .filter(|sample| sample.idle_hundredths >= HOST_IDLE_MIN_HUNDREDTHS)
        .count();
    if passing < HOST_IDLE_MIN_PASSING {
        reasons.push(format!(
            "host idle >= 90% in only {passing} of {} samples",
            samples.len()
        ));
    }
    reasons
}

/// P0-B quiet-host qualification from the in-trial non-owned process deltas.
///
/// Deltas are aggregated per one-second interval first: the declared limit is host-core use
/// (100 % = one core) across all non-owned processes, not any single process's share.
pub(crate) fn qualify_non_owned(deltas: &[ProcessDelta]) -> Vec<String> {
    use std::collections::BTreeMap;
    let mut reasons = Vec::new();
    let mut intervals: BTreeMap<u64, (u128, u128)> = BTreeMap::new();
    for delta in deltas.iter().filter(|delta| !delta.excluded) {
        if delta.wall_ns == 0 {
            continue;
        }
        let entry = intervals.entry(delta.sample_id).or_insert((0, 0));
        entry.0 += delta.cpu_ns as u128;
        entry.1 = entry.1.max(delta.wall_ns as u128);
    }
    let mut cores: Vec<Ratio> = intervals
        .values()
        .filter(|(_, wall)| *wall > 0)
        .map(|(cpu, wall)| Ratio::new(*cpu, *wall))
        .collect();
    if cores.is_empty() {
        reasons.push("no in-trial non-owned process samples were recorded".to_string());
        return reasons;
    }
    cores.sort_by(Ratio::cmp_ratio);
    let total: u128 = intervals.values().map(|(cpu, _)| *cpu).sum();
    let wall_total: u128 = intervals.values().map(|(_, wall)| *wall).sum();
    if wall_total == 0 {
        reasons.push("in-trial process samples had zero wall time".to_string());
        return reasons;
    }
    let mean = Ratio::new(total, wall_total);
    let p95 = nearest_rank(&cores, 95).expect("non-empty");
    if mean.cmp_ratio(&Ratio::new(NON_OWNED_MEAN_MAX_NUM, NON_OWNED_MEAN_MAX_DEN))
        == Ordering::Greater
    {
        reasons.push(format!(
            "non-owned host use mean {:.3} cores exceeds 0.10",
            mean.as_f64()
        ));
    }
    if p95.cmp_ratio(&Ratio::new(NON_OWNED_P95_MAX_NUM, NON_OWNED_P95_MAX_DEN)) == Ordering::Greater
    {
        reasons.push(format!(
            "non-owned host use p95 {:.3} cores exceeds 0.25",
            p95.as_f64()
        ));
    }
    reasons
}

/// Analyze one trial's original poll attempts against the predeclared P0-D rows.
pub(crate) fn analyze_trial(
    spec: &TrialSpec,
    attempts: &[PollRecord],
    idle: &[HostSample],
    deltas: &[ProcessDelta],
    workload: &WorkloadReport,
) -> TrialAnalysis {
    let mut out = TrialAnalysis {
        trial: spec.trial.clone(),
        config: spec.config.clone(),
        attempts: attempts.len(),
        ..TrialAnalysis::default()
    };
    out.inconclusive.extend(qualify_idle(idle));
    out.inconclusive.extend(qualify_non_owned(deltas));
    out.inconclusive.extend(qualify_workload(workload));

    // Classify the whole attempt log, retaining every row in attempted order.
    let mut clock = ObservationClock::default();
    let mut clocks: Vec<Clock> = Vec::with_capacity(attempts.len());
    for record in attempts {
        clocks.push(clock.observe(record.sdk_timestamp_ns));
    }
    let distinct_rows: Vec<usize> = clocks
        .iter()
        .enumerate()
        .filter_map(|(index, clock)| (*clock == Clock::Distinct).then_some(index))
        .collect();
    out.duplicates = clocks.iter().filter(|c| **c == Clock::Duplicate).count();
    out.gaps = clocks.iter().filter(|c| **c == Clock::Gap).count();
    out.regressed = clocks.iter().filter(|c| **c == Clock::Regressed).count();
    out.corrections = clocks.iter().filter(|c| **c == Clock::Reanchor).count();
    out.distinct_total = distinct_rows.len();

    if distinct_rows.len() <= SETTLING_DISTINCT_ROWS {
        out.inconclusive.push(format!(
            "only {} distinct rows; {SETTLING_DISTINCT_ROWS} settling plus {COUNTED_DISTINCT_ROWS} counted are required",
            distinct_rows.len()
        ));
        return out;
    }
    // The counted span opens at the next attempted poll after the fifth settling row.
    let span_start = distinct_rows[SETTLING_DISTINCT_ROWS - 1] + 1;
    // ...and closes on the 60th distinct row after settling, if it exists.
    let counted_row_indices: Vec<usize> = distinct_rows[SETTLING_DISTINCT_ROWS..].to_vec();
    if counted_row_indices.len() < COUNTED_DISTINCT_ROWS {
        out.inconclusive.push(format!(
            "only {} counted distinct rows; {COUNTED_DISTINCT_ROWS} are required",
            counted_row_indices.len()
        ));
        return out;
    }
    let span_end = counted_row_indices[COUNTED_DISTINCT_ROWS - 1];
    out.counted_distinct = COUNTED_DISTINCT_ROWS;
    let span = &attempts[span_start..=span_end];
    let span_clocks = &clocks[span_start..=span_end];

    // The declared memory size is part of the trial identity: a row reporting another live
    // limit means the page walk measured something else, so the trial cannot be graded.
    let declared_bytes = u64::from(spec.memory_mib) * 1024 * 1024;
    if let Some(record) = counted_row_indices[..COUNTED_DISTINCT_ROWS]
        .iter()
        .map(|index| &attempts[*index])
        .find(|record| record.memory_limit_bytes != Some(declared_bytes))
    {
        out.inconclusive.push(format!(
            "counted row {} reports memory limit {:?} bytes, not the declared {} MiB",
            record.poll_id, record.memory_limit_bytes, spec.memory_mib
        ));
    }

    let deadline_start = attempts[distinct_rows[SETTLING_DISTINCT_ROWS - 1]].read_end_ns;
    let collection_end = attempts[span_end].read_end_ns;
    out.elapsed_ns = u128::from(collection_end.saturating_sub(deadline_start));
    if out.elapsed_ns > COLLECTION_DEADLINE_NS {
        out.inconclusive.push(format!(
            "collecting the 60 counted rows took {} ns, above the 180 s budget",
            out.elapsed_ns
        ));
    }

    // One shadow run over the whole counted span: non-overlapping opportunities.
    // Two shadows over the same counted span: the calibration criterion's threshold
    // opportunities at the fixed commitment, and the production-shaped proposals that stay
    // ceiling-inhibited. They differ only at `cpus == max_cpus`, never in the run counters
    // a verdict would otherwise read.
    let commitment = Commitment {
        cpus: spec.cpus,
        boot_cpus: spec.boot_cpus,
        max_cpus: spec.max_cpus,
    };
    let mut runs = Runs::default();
    let mut proposals = Runs::default();
    let mut rates: Vec<Rate> = Vec::new();
    let mut rows_positive = 0usize;
    let mut rows_at_or_above_95c = 0usize;
    let mut rows_at_or_below_85 = 0usize;
    let mut rows_in_deadband = 0usize;
    let mut rows_at_or_below_255 = 0usize;
    let mut identity: Option<&str> = None;
    let mut identity_changed = false;
    for (record, observation) in span.iter().zip(span_clocks) {
        let lifecycle = record.lifecycle_valid && record.lifecycle_value == "running";
        let decoded = record.cpu_percent_bits.map(decode_rate);
        match decoded {
            Some(Decoded::Invalid) => out.invalid += 1,
            Some(Decoded::Zero) => out.zero += 1,
            Some(Decoded::Positive(rate)) if *observation == Clock::Distinct => {
                out.positive += 1;
                rows_positive += 1;
                rates.push(rate);
                let up = u128::from(spec.cpus) * u128::from(THRESHOLD_UP_TENTHS_PER_CORE) / 10;
                if rate.at_or_above(up) {
                    rows_at_or_above_95c += 1;
                }
                if rate.at_or_below(85) {
                    rows_at_or_below_85 += 1;
                }
                if rate.strictly_between(85, 95) {
                    rows_in_deadband += 1;
                }
                if rate.at_or_below(255) {
                    rows_at_or_below_255 += 1;
                }
            }
            // A positive rate on a duplicate/regressed attempt counts toward neither the
            // rate distribution nor the 60-row volume.
            Some(Decoded::Positive(_)) | None => {}
        }
        match record.runtime_identity.as_deref() {
            Some(current) => match identity {
                None => identity = Some(current),
                Some(first) if first != current => identity_changed = true,
                _ => {}
            },
            None => identity_changed = true,
        }
        runs.step(
            GrowthPolicy::FixedThreshold,
            *observation,
            lifecycle,
            decoded,
            commitment,
        );
        proposals.step(
            GrowthPolicy::CeilingInhibited,
            *observation,
            lifecycle,
            decoded,
            commitment,
        );
    }
    if identity_changed {
        out.inconclusive
            .push("runtime identity was absent or changed during the counted span".to_string());
    }
    out.longest_high = runs.longest_high;
    out.longest_low = runs.longest_low;
    out.high_opportunities = runs.high_opportunities;
    out.low_opportunities = runs.low_opportunities;
    out.proposal_high_opportunities = proposals.high_opportunities;

    // Independent blocks: six ten-row (growth) and twelve five-row (low) blocks.
    for block in counted_row_indices[..COUNTED_DISTINCT_ROWS]
        .chunks(10)
        .take(6)
    {
        if block.len() != 10 {
            continue;
        }
        let first = *block.first().expect("non-empty");
        let last = *block.last().expect("non-empty");
        if block_completes(attempts, first, last, commitment, true) {
            out.high_blocks_complete += 1;
        }
    }
    for block in counted_row_indices[..COUNTED_DISTINCT_ROWS]
        .chunks(5)
        .take(12)
    {
        if block.len() != 5 {
            continue;
        }
        let first = *block.first().expect("non-empty");
        let last = *block.last().expect("non-empty");
        if block_completes(attempts, first, last, commitment, false) {
            out.low_blocks_complete += 1;
        }
    }

    rates.sort_by(Rate::cmp_value);
    out.median = median_rate(&rates);
    out.p5 = quantile_rate(&rates, 5);
    out.p95 = quantile_rate(&rates, 95);

    // P0-D rows.
    let median = median_rate(&rates);
    let mut failures: Vec<String> = Vec::new();
    match spec.shape {
        TrialShape::OneWorkerFull => {
            if let Some(median) = median {
                if !(median.at_or_above(90) && median.at_or_below(110)) {
                    failures.push(format!(
                        "one-worker median {:.3}% is outside 90..=110",
                        median.as_f64()
                    ));
                }
            } else {
                failures.push("no positive valid rates to take a median of".to_string());
            }
            if rows_positive < 54 {
                failures.push(format!(
                    "only {rows_positive}/60 counted rows had a positive valid rate (54 required)"
                ));
            }
        }
        TrialShape::AllWorkersFull => {
            let expected = spec.workers;
            let low = u128::from(expected) * 90;
            let high = u128::from(expected) * 110;
            if let Some(median) = median {
                if !(median.at_or_above(low) && median.at_or_below(high)) {
                    failures.push(format!(
                        "all-workers median {:.3}% is outside {low}..={high}",
                        median.as_f64()
                    ));
                }
            } else {
                failures.push("no positive valid rates to take a median of".to_string());
            }
            if rows_at_or_above_95c < 54 {
                failures.push(format!(
                    "only {rows_at_or_above_95c}/60 rows were >= 95 x C (54 required)"
                ));
            }
            if out.high_blocks_complete < 4 {
                failures.push(format!(
                    "only {}/6 ten-row blocks supplied a complete high run (4 required)",
                    out.high_blocks_complete
                ));
            }
            if out.high_opportunities < 4 {
                failures.push(format!(
                    "only {} non-overlapping high opportunities (4 required)",
                    out.high_opportunities
                ));
            }
        }
        TrialShape::OneWorkerEighty => {
            if let Some(median) = median {
                if !(median.at_or_above(75) && median.at_or_below(85)) {
                    failures.push(format!(
                        "80% median {:.3}% is outside 75..=85",
                        median.as_f64()
                    ));
                }
            } else {
                failures.push("no positive valid rates to take a median of".to_string());
            }
            if spec.cpus >= 2 {
                if rows_at_or_below_85 < 54 {
                    failures.push(format!(
                        "only {rows_at_or_below_85}/60 rows were positive and <= 85 (54 required)"
                    ));
                }
                if out.low_blocks_complete < 8 {
                    failures.push(format!(
                        "only {}/12 five-row blocks supplied a complete low run (8 required)",
                        out.low_blocks_complete
                    ));
                }
                if out.low_opportunities < 8 {
                    failures.push(format!(
                        "only {} non-overlapping low opportunities (8 required)",
                        out.low_opportunities
                    ));
                }
            }
            if out.high_opportunities != 0 {
                failures.push("80% load completed a high run".to_string());
            }
        }
        TrialShape::OneWorkerNinety => {
            if let Some(median) = median {
                if !(median.at_or_above(86) && median.at_or_below(94)) {
                    failures.push(format!(
                        "90% median {:.3}% is outside 86..=94",
                        median.as_f64()
                    ));
                }
            } else {
                failures.push("no positive valid rates to take a median of".to_string());
            }
            if spec.cpus >= 2 {
                if rows_in_deadband < 54 {
                    failures.push(format!(
                        "only {rows_in_deadband}/60 rows were in 85 < rate < 95 (54 required)"
                    ));
                }
                if out.high_opportunities != 0 || out.low_opportunities != 0 {
                    failures.push("90% load completed a high or low run at C=2".to_string());
                }
            }
            if out.high_opportunities != 0 {
                failures.push("90% load completed a high run".to_string());
            }
        }
    }
    if spec.shape == TrialShape::OneWorkerFull
        && spec.cpus == 2
        && (out.high_opportunities != 0 || out.low_opportunities != 0)
    {
        failures.push(
            "one full core at C=2 completed a high or low run instead of holding".to_string(),
        );
    }
    if spec.shape == TrialShape::OneWorkerFull && spec.cpus == 4 {
        if rows_at_or_below_255 < 54 {
            failures.push(format!(
                "only {rows_at_or_below_255}/60 positive rows were <= 255 (54 required)"
            ));
        }
        if out.low_blocks_complete < 8 {
            failures.push(format!(
                "only {}/12 five-row blocks supplied a complete low run (8 required)",
                out.low_blocks_complete
            ));
        }
        if out.low_opportunities < 8 {
            failures.push(format!(
                "only {} non-overlapping low opportunities (8 required)",
                out.low_opportunities
            ));
        }
        if out.high_opportunities != 0 {
            failures.push("one busy core at C=4 completed a high run".to_string());
        }
    }
    out.failures = failures;
    out
}

/// The suite-level gate: every declared trial must pass, and the matched one-worker
/// medians must stay proportional across commitments (P0-D cross-configuration rows).
pub(crate) fn analyze_suite(analyses: &[TrialAnalysis], specs: &[TrialSpec]) -> SuiteVerdict {
    let mut verdict = SuiteVerdict {
        trials: analyses.to_vec(),
        failures: Vec::new(),
        inconclusive: Vec::new(),
    };
    if analyses.len() != specs.len() {
        verdict
            .inconclusive
            .push("trial count does not match the declared matrix".to_string());
        return verdict;
    }
    for analysis in analyses {
        for reason in &analysis.inconclusive {
            verdict
                .inconclusive
                .push(format!("{}: {reason}", analysis.trial));
        }
        for reason in &analysis.failures {
            verdict
                .failures
                .push(format!("{}: {reason}", analysis.trial));
        }
    }
    // Cross-configuration: for each memory size, C2/C1 and C4/C1 in 0.85..=1.15.
    let memories: Vec<u32> = {
        let mut values: Vec<u32> = specs.iter().map(|spec| spec.memory_mib).collect();
        values.sort_unstable();
        values.dedup();
        values
    };
    for memory in memories {
        for trial_index in [1u8, 2] {
            let median_for = |cpus: u8| -> Option<Rate> {
                specs
                    .iter()
                    .zip(analyses)
                    .filter(|(spec, _)| {
                        spec.memory_mib == memory
                            && spec.cpus == cpus
                            && spec.trial_index == trial_index
                            && spec.shape == TrialShape::OneWorkerFull
                    })
                    .filter_map(|(_, analysis)| analysis.median)
                    .next()
            };
            let (Some(c1), Some(c2), Some(c4)) = (median_for(1), median_for(2), median_for(4))
            else {
                verdict.inconclusive.push(format!(
                    "M={memory} MiB trial {trial_index} lacks matched one-worker medians for C=1/2/4"
                ));
                continue;
            };
            for (label, measured) in [("C2/C1", c2), ("C4/C1", c4)] {
                // 0.85..=1.15 == 17/20..=23/20: compare 20*median with 17/20*C1 median as
                // binary values, so no cross-multiplied rational is ever materialised.
                let scaled = measured.scaled(20);
                let ratio = measured.as_f64() / c1.as_f64();
                if scaled.cmp_value(&c1.scaled(17)) == Ordering::Less
                    || scaled.cmp_value(&c1.scaled(23)) == Ordering::Greater
                {
                    verdict.failures.push(format!(
                        "M={memory} MiB trial {trial_index} {label} median ratio {ratio:.3} is outside 0.85..=1.15"
                    ));
                }
            }
        }
    }
    verdict
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct SuiteVerdict {
    pub trials: Vec<TrialAnalysis>,
    pub failures: Vec<String>,
    pub inconclusive: Vec<String>,
}

impl SuiteVerdict {
    pub(crate) fn verdict(&self) -> &'static str {
        if !self.inconclusive.is_empty() {
            "INCONCLUSIVE"
        } else if !self.failures.is_empty() {
            "FAIL"
        } else {
            "PASS"
        }
    }
}

/// The declared calibration matrix for one memory size, in execution order.
pub(crate) fn calibration_matrix(memory_mib: u32) -> Vec<TrialSpec> {
    let configs: [(u8, u32, u32, TrialShape); 9] = [
        (1, 1, 80, TrialShape::OneWorkerEighty),
        (1, 1, 90, TrialShape::OneWorkerNinety),
        (1, 1, 100, TrialShape::OneWorkerFull),
        (2, 1, 80, TrialShape::OneWorkerEighty),
        (2, 1, 90, TrialShape::OneWorkerNinety),
        (2, 1, 100, TrialShape::OneWorkerFull),
        (2, 2, 100, TrialShape::AllWorkersFull),
        (4, 1, 100, TrialShape::OneWorkerFull),
        (4, 4, 100, TrialShape::AllWorkersFull),
    ];
    let mut specs = Vec::new();
    for (cpus, workers, duty, shape) in configs {
        for (index, phase_ms) in [0u64, 100].into_iter().enumerate() {
            specs.push(TrialSpec {
                trial: format!(
                    "cal-m{memory_mib}-c{cpus}-w{workers}-d{duty}-t{}",
                    index + 1
                ),
                config: format!("M={memory_mib}MiB C={cpus} workers={workers} duty={duty}%"),
                memory_mib,
                boot_cpus: 1,
                max_cpus: 4,
                cpus,
                workers,
                duty_percent: duty,
                phase_ms,
                trial_index: (index + 1) as u8,
                shape,
            });
        }
    }
    specs
}

#[cfg(test)]
mod tests;
