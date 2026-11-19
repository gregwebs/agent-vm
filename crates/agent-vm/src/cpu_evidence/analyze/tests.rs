//! T19: raw-oracle and numeric-mechanics fixtures for the Phase 0 analyzer.
//!
//! The fixtures build the authoritative poll log by hand (never by running the analyzer) and
//! assert both verdicts and the intermediate counts the plan pins, including the negative
//! control where filtering lookup errors out of the log would turn a FAIL into a PASS.

use super::*;

const BASE_NS: u64 = 10_000_000_000;

fn bits(value: f32) -> u32 {
    value.to_bits()
}

fn qualified_idle() -> Vec<HostSample> {
    (0..HOST_IDLE_SAMPLES)
        .map(|index| HostSample {
            kind: "pretrial".to_string(),
            at_ns: index as u64 * 1_000_000_000,
            idle_hundredths: 9_950,
        })
        .collect()
}

fn qualified_deltas() -> Vec<ProcessDelta> {
    vec![ProcessDelta {
        sample_id: 0,
        pid: 1,
        command: "launchd".to_string(),
        cpu_ns: 20_000_000,
        wall_ns: 1_000_000_000,
        excluded: false,
    }]
}

fn qualified_workload(workers: u32, duty: u32) -> WorkloadReport {
    let mut checkpoints = Vec::new();
    for worker in 0..workers {
        for second in 0..=10u128 {
            checkpoints.push(WorkloadCheckpoint {
                worker,
                pid: 100 + worker,
                kind: if second == 10 { "end" } else { "checkpoint" }.to_string(),
                monotonic_ns: second * 1_000_000_000,
                process_time_ns: second * 1_000_000_000 * u128::from(duty) / 100,
                iterations: second as u64 * 1_000,
            });
        }
    }
    WorkloadReport {
        workers,
        duty_percent: duty,
        ready: true,
        checkpoints,
    }
}

/// One raw poll attempt; `None` timestamp is an absent row / lookup error line.
fn poll(trial: &str, poll_id: u64, timestamp_ns: Option<i128>, value: Option<f32>) -> PollRecord {
    PollRecord {
        poll_id,
        trial: trial.to_string(),
        config: "fixture".to_string(),
        scheduled_ns: BASE_NS + poll_id * 200_000_000,
        read_start_ns: BASE_NS + poll_id * 200_000_000 + 1_000,
        read_end_ns: BASE_NS + poll_id * 200_000_000 + 2_000,
        sdk_timestamp_ns: timestamp_ns,
        cpu_percent_bits: value.map(bits),
        vcpu_time_ns: Some(poll_id * 1_000_000),
        memory_limit_bytes: Some(1 << 30),
        memory_available_bytes: Some(512 << 20),
        residency_present: Some(true),
        lifecycle_valid: true,
        lifecycle_value: "running".to_string(),
        lifecycle_cache_age_ns: Some(1),
        probe_started_ns: None,
        probe_ended_ns: None,
        probe_result: None,
        probe_skipped: Some("cache hit".to_string()),
        runtime_identity: Some("runtime-fixture".to_string()),
        error: None,
    }
}

fn error_attempt(trial: &str, poll_id: u64) -> PollRecord {
    PollRecord {
        poll_id,
        trial: trial.to_string(),
        config: "fixture".to_string(),
        scheduled_ns: BASE_NS + poll_id * 200_000_000,
        read_start_ns: BASE_NS + poll_id * 200_000_000 + 1_000,
        read_end_ns: BASE_NS + poll_id * 200_000_000 + 2_000,
        error: Some("metrics lookup failed".to_string()),
        // The sandbox identity is known independently of the row: an absent row cannot make
        // the run's runtime identity change.
        runtime_identity: Some("runtime-fixture".to_string()),
        ..PollRecord::default()
    }
}

struct RawTable {
    attempts: Vec<PollRecord>,
}

impl RawTable {
    /// Five settling rows, then `counted` distinct rows, each attempted twice (the second
    /// attempt repeats the timestamp, so it is a pure duplicate).
    fn with_duplicates(trial: &str, settling: usize, counted: usize, rate: f32) -> Self {
        let mut attempts = Vec::new();
        let mut poll_id = 0;
        let mut stamp = 0i128;
        for _ in 0..settling + counted {
            attempts.push(poll(trial, poll_id, Some(stamp), Some(rate)));
            poll_id += 1;
            attempts.push(poll(trial, poll_id, Some(stamp), Some(rate)));
            poll_id += 1;
            stamp += 200_000_000;
        }
        Self { attempts }
    }
}

fn spec(trial: &str, cpus: u8, workers: u32, duty: u32, shape: TrialShape) -> TrialSpec {
    TrialSpec {
        trial: trial.to_string(),
        config: format!("C={cpus} workers={workers} duty={duty}%"),
        memory_mib: 1024,
        boot_cpus: 1,
        max_cpus: 4,
        cpus,
        workers,
        duty_percent: duty,
        phase_ms: 0,
        trial_index: 1,
        shape,
    }
}

/// The declared 1..=4 interval held at `cpus`; calibration never resizes.
fn commitment(cpus: u8) -> Commitment {
    Commitment {
        cpus,
        boot_cpus: 1,
        max_cpus: 4,
    }
}

fn analyze(spec: &TrialSpec, attempts: &[PollRecord], workload: &WorkloadReport) -> TrialAnalysis {
    analyze_trial(
        spec,
        attempts,
        &qualified_idle(),
        &qualified_deltas(),
        workload,
    )
}

#[test]
fn nearest_rank_uses_the_declared_indices() {
    let sixty: Vec<u128> = (1..=60).collect();
    assert_eq!(nearest_rank(&sixty, 50), Some(30));
    assert_eq!(nearest_rank(&sixty, 5), Some(3));
    assert_eq!(nearest_rank(&sixty, 95), Some(57));
    let twenty: Vec<u128> = (1..=20).collect();
    assert_eq!(nearest_rank(&twenty, 95), Some(19));
    let five: Vec<u128> = (1..=5).collect();
    assert_eq!(nearest_rank(&five, 50), Some(3));
    assert_eq!(nearest_rank::<u128>(&[], 50), None);
    assert_eq!(nearest_rank(&sixty, 0), None);
    assert_eq!(nearest_rank(&sixty, 101), None);
}

/// Independent exact oracle for the analyzer's numeric mechanics.
///
/// `f64` holds every `f32` exactly, `10 * f32` has at most a 28-bit significand so the product
/// is exact in `f64`, and `f32::total_cmp` orders positive finite values numerically. Nothing
/// here shares code with the analyzer's decoder or comparisons.
fn oracle_value(bits: u32) -> f64 {
    f64::from(f32::from_bits(bits))
}

fn oracle_order(low: u32, high: u32) -> Ordering {
    f32::from_bits(low).total_cmp(&f32::from_bits(high))
}

fn oracle_tenths(bits: u32) -> Option<(u32, u32)> {
    let value = oracle_value(bits);
    if !value.is_finite() || value <= 0.0 {
        return None;
    }
    let scaled = value * 10.0;
    let cap = MAX_RATE_TENTHS as f64;
    Some((
        scaled.floor().min(cap) as u32,
        scaled.ceil().min(cap) as u32,
    ))
}

fn decoded_rate(bits: u32) -> Rate {
    match decode_rate(bits) {
        Decoded::Positive(rate) => rate,
        other => panic!("{bits:#010x} decoded as {other:?}, not a positive rate"),
    }
}

#[test]
fn exact_limits_compare_without_rounding() {
    // 250_000_000 ns of one host core over 1 s is exactly 0.25 and passes `<= 0.25`.
    let equal = Ratio::new(250_000_000, 1_000_000_000);
    let p95_limit = Ratio::new(NON_OWNED_P95_MAX_NUM, NON_OWNED_P95_MAX_DEN);
    assert!(equal.cmp_ratio(&p95_limit) == Ordering::Equal);
    let above = Ratio::new(250_000_001, 1_000_000_000);
    assert!(above.cmp_ratio(&p95_limit) == Ordering::Greater);
    // Operands whose cross product cannot fit in a `u128` still compare exactly.
    let huge = Ratio::new(u128::MAX, u128::MAX - 1);
    assert!(huge.cmp_ratio(&Ratio::new(1, 1)) == Ordering::Greater);
    assert!(Ratio::new(1, u128::MAX).cmp_ratio(&Ratio::new(0, 1)) == Ordering::Greater);
    assert!(Ratio::new(u128::MAX, 2).cmp_ratio(&Ratio::new(u128::MAX - 1, 2)) == Ordering::Greater);
    // Percent thresholds keep their own exact comparison.
    let exactly_95 = Rate {
        significand: 95,
        exponent: 0,
    };
    assert!(exactly_95.at_or_above(95));
    assert!(!exactly_95.strictly_between(85, 95));
    assert!(!exactly_95.below(95));
    // One exact half step below 95 and above 85 is decided by the exponent, not a product.
    assert!(
        Rate {
            significand: 95,
            exponent: -1
        }
        .below(95)
    );
    assert!(
        Rate {
            significand: 171,
            exponent: -1
        }
        .at_or_above(85)
    );
    // 95 and one representable step below/above it.
    let exactly_95 = decode_rate(bits(95.0));
    assert!(matches!(exactly_95, Decoded::Positive(r) if r.at_or_above(95)));
    let below = decode_rate(bits(f32::from_bits(bits(95.0) - 1)));
    assert!(matches!(below, Decoded::Positive(r) if r.below(95)));
    let above_85 = decode_rate(bits(f32::from_bits(bits(85.0) + 1)));
    assert!(matches!(above_85, Decoded::Positive(r) if !r.at_or_below(85)));
}

#[test]
fn decode_rate_retains_the_binary_value() {
    assert_eq!(decode_rate(bits(0.0)), Decoded::Zero);
    assert_eq!(decode_rate(bits(-0.0)), Decoded::Invalid);
    assert_eq!(decode_rate(bits(f32::NAN)), Decoded::Invalid);
    assert_eq!(decode_rate(bits(f32::INFINITY)), Decoded::Invalid);
    assert_eq!(decode_rate(bits(-1.0)), Decoded::Invalid);
    // The smallest positive subnormal is `1 * 2^-149`, kept exactly.
    assert_eq!(
        decode_rate(1),
        Decoded::Positive(Rate {
            significand: 1,
            exponent: -149
        })
    );
    // 100.0f32 is `13_107_200 * 2^-17`, exactly 100.
    assert_eq!(
        decode_rate(bits(100.0)),
        Decoded::Positive(Rate {
            significand: 100 << 17,
            exponent: -17
        })
    );
    assert_eq!(decoded_rate(bits(100.0)).as_f64(), 100.0);
    // 202.1 is not exactly representable; the binary value keeps the actual float ratio.
    let carried = decoded_rate(bits(202.1));
    assert!(carried.at_or_above(202) && carried.below(203));
    assert_eq!(carried.as_f64(), oracle_value(bits(202.1)));
    // The largest finite value stays exact instead of being clamped for diagnostics.
    assert_eq!(
        decode_rate(bits(f32::MAX)),
        Decoded::Positive(Rate {
            significand: (1 << 24) - 1,
            exponent: 104
        })
    );
    // Tenths intervals floor the lower and ceil the upper endpoint.
    let (lo, hi) = tenths_bounds(decode_rate(bits(94.999))).expect("positive");
    assert!(lo <= 949 && hi >= 950, "lo={lo} hi={hi}");
}

#[test]
fn minimum_normal_and_adjacent_subnormals_decode_exactly() {
    // The old decoder shifted `1u128 << (150 - exponent)`, i.e. by 149 for a minimum normal:
    // a debug panic and a wrong release value. These are all finite, so all decode exactly.
    const MIN_SUBNORMAL: u32 = 0x0000_0001;
    const MAX_SUBNORMAL: u32 = 0x007f_ffff;
    const MIN_NORMAL: u32 = 0x0080_0000;
    assert_eq!(
        decoded_rate(MIN_NORMAL),
        Rate {
            significand: 1 << 23,
            exponent: -149
        }
    );
    assert_eq!(
        decoded_rate(MAX_SUBNORMAL),
        Rate {
            significand: (1 << 23) - 1,
            exponent: -149
        }
    );
    for (low, high) in [
        (MIN_SUBNORMAL, MIN_SUBNORMAL + 1),
        (MAX_SUBNORMAL - 1, MAX_SUBNORMAL),
        // Adjacent across the subnormal/normal boundary: same exponent, one step apart.
        (MAX_SUBNORMAL, MIN_NORMAL),
        (MIN_NORMAL, MIN_NORMAL + 1),
        (0x0000_0001, 0x0080_0000),
    ] {
        assert_eq!(
            oracle_order(low, high),
            Ordering::Less,
            "{low:#x} {high:#x}"
        );
        let low_rate = decoded_rate(low);
        let high_rate = decoded_rate(high);
        // Distinct values, not one shared bucket, and ordered exactly.
        assert_ne!(low_rate, high_rate, "{low:#x} and {high:#x} were bucketed");
        assert_eq!(low_rate.cmp_value(&high_rate), Ordering::Less);
        assert_eq!(high_rate.cmp_value(&low_rate), Ordering::Greater);
        assert_eq!(low_rate.cmp_value(&low_rate), Ordering::Equal);
        assert!(low_rate.as_f64() < high_rate.as_f64());
    }
    // A minimum normal is a usable observation just below one tenth of a percent.
    assert_eq!(tenths_bounds(decode_rate(MIN_NORMAL)), Some((0, 1)));
    assert_eq!(tenths_bounds(decode_rate(MIN_SUBNORMAL)), Some((0, 1)));
    // Every subnormal keeps the exact interval the oracle computes, at either end of the
    // subnormal range.
    for step in [1u32, 2, 0x0010_0000, MAX_SUBNORMAL - 1, MAX_SUBNORMAL] {
        assert_eq!(tenths_bounds(decode_rate(step)), oracle_tenths(step));
        assert_eq!(tenths_bounds(decode_rate(step)), Some((0, 1)));
    }
}

#[test]
fn largest_finite_rate_is_exact_and_saturates_only_the_policy_interval() {
    let max_finite = bits(f32::MAX);
    let rate = decoded_rate(max_finite);
    // 3.4028235e38 is retained as `(2^24 - 1) * 2^104`, not clamped to 100000.
    assert_eq!(rate.significand, (1 << 24) - 1);
    assert_eq!(rate.exponent, 104);
    assert!(rate.cmp_value(&decoded_rate(0x0000_0001)) == Ordering::Greater);
    assert!(rate.at_or_above(255));
    assert!(!rate.at_or_below(255));
    assert!(!rate.at_or_below(100_000));
    // Only the policy-facing interval saturates: 255 CPUs x 100% x 10 (plan §3.1).
    assert_eq!(
        tenths_bounds(decode_rate(max_finite)),
        Some((255_000, 255_000))
    );
    assert_eq!(
        tenths_bounds(decode_rate(max_finite)),
        oracle_tenths(max_finite)
    );
    for raw in [25500.0f32, 25500.1, 1e6, 3.0e38] {
        let bits = bits(raw);
        assert_eq!(tenths_bounds(decode_rate(bits)), Some((255_000, 255_000)));
        assert_eq!(tenths_bounds(decode_rate(bits)), oracle_tenths(bits));
    }
    // The cap is not applied below 25500%: ordinary percents stay exact intervals.
    for raw in [0.5f32, 85.0, 94.999, 95.0, 100.0, 25499.0] {
        let bits = bits(raw);
        assert_eq!(tenths_bounds(decode_rate(bits)), oracle_tenths(bits));
    }
    assert_eq!(tenths_bounds(decode_rate(bits(95.0))), Some((950, 950)));
}

#[test]
fn mixed_magnitude_rates_sort_and_quantile_exactly() {
    // Subnormals, a minimum normal, ordinary percentages and very large finite values.
    let mut cases: Vec<u32> = vec![
        0x0000_0001,
        0x0000_0002,
        0x0000_00ff,
        0x0040_0000,
        0x007f_ffff,
        0x0080_0000,
        0x0080_0001,
        bits(0.0001),
        bits(1.0),
        bits(85.0),
        bits(94.999),
        bits(95.0),
        bits(100.0),
        bits(202.1),
        bits(380.0),
        bits(400.0),
        bits(100_000.0),
        bits(1e9),
        bits(f32::MAX),
    ];
    // Sixty counted rows: the declared quantile volume, with the magnitudes interleaved.
    let base = cases.clone();
    while cases.len() < 60 {
        cases.extend(base.iter().copied());
    }
    cases.truncate(60);

    let mut rates: Vec<Rate> = cases.iter().copied().map(decoded_rate).collect();
    rates.sort_by(Rate::cmp_value);
    let mut want: Vec<f32> = cases.iter().map(|bits| f32::from_bits(*bits)).collect();
    want.sort_by(f32::total_cmp);
    let got: Vec<f64> = rates.iter().map(Rate::as_f64).collect();
    let expected: Vec<f64> = want.iter().map(|value| f64::from(*value)).collect();
    assert_eq!(got, expected, "exact order must match the f32 oracle");

    // Nearest-rank quantiles over the exact values: 5 -> item 3, 50 -> item 30, 95 -> item 57.
    for percentile in [5u32, 50, 95] {
        let rank = (60u128 * u128::from(percentile)).div_ceil(100).max(1);
        let oracle = f64::from(want[(rank - 1) as usize]);
        let measured = if percentile == 50 {
            median_rate(&rates)
        } else {
            quantile_rate(&rates, percentile)
        };
        assert_eq!(
            measured.map(|rate| rate.as_f64()),
            Some(oracle),
            "p{percentile}"
        );
        // Every reported rate is a genuine observation of this trace, not a synthesis.
        assert!(
            rates
                .iter()
                .any(|rate| *rate == measured.expect("non-empty"))
        );
    }

    // A full trial over the same mixed rows grades its diagnostics against the oracle.
    let mut attempts: Vec<PollRecord> = (0..5 + 60)
        .map(|index| poll("mixed", index, Some(i128::from(index) * 200_000_000), None))
        .collect();
    for (record, bits) in attempts.iter_mut().skip(5).zip(cases.iter()) {
        record.cpu_percent_bits = Some(*bits);
    }
    let trial = spec("mixed", 1, 1, 100, TrialShape::OneWorkerFull);
    let analysis = analyze(&trial, &attempts, &qualified_workload(1, 100));
    assert_eq!(analysis.counted_distinct, 60);
    assert_eq!(analysis.positive, 60);
    let mut oracle_rates: Vec<f32> = cases.iter().map(|bits| f32::from_bits(*bits)).collect();
    oracle_rates.sort_by(f32::total_cmp);
    assert_eq!(
        analysis.median.map(|rate| rate.as_f64()),
        Some(f64::from(oracle_rates[29]))
    );
    assert_eq!(
        analysis.p5.map(|rate| rate.as_f64()),
        Some(f64::from(oracle_rates[2]))
    );
    assert_eq!(
        analysis.p95.map(|rate| rate.as_f64()),
        Some(f64::from(oracle_rates[56]))
    );
}

#[test]
fn pure_duplicates_pass_growth_and_duplicate_reset_fails() {
    let table = RawTable::with_duplicates("dup", 5, 60, 100.0);
    let trial = spec("dup", 1, 1, 100, TrialShape::AllWorkersFull);
    let analysis = analyze(&trial, &table.attempts, &qualified_workload(1, 100));
    assert_eq!(analysis.distinct_total, 65);
    assert_eq!(analysis.counted_distinct, 60);
    assert_eq!(analysis.duplicates, 65);
    assert_eq!(analysis.longest_high, 10);
    assert_eq!(analysis.high_opportunities, 6);
    assert_eq!(analysis.high_blocks_complete, 6);
    assert!(analysis.passed(), "{:?}", analysis.failures);

    // Mutation: make every duplicate an unusable rate. Duplicates must reset the run, so the
    // same table can no longer assemble ten consecutive highs.
    let mut broken = table.attempts.clone();
    for record in broken.iter_mut().skip(1).step_by(2) {
        record.cpu_percent_bits = Some(bits(f32::NAN));
    }
    let mutated = analyze(&trial, &broken, &qualified_workload(1, 100));
    assert!(mutated.longest_high < 10, "{:?}", mutated);
    assert_eq!(mutated.high_opportunities, 0);
    assert!(!mutated.passed());
}

#[test]
fn errors_after_each_ninth_high_fail_growth_but_filtering_would_pass() {
    // Build 60 counted highs where each ten-row block's ninth high is followed by an
    // attempted lookup error before the next high.
    let mut attempts: Vec<PollRecord> = Vec::new();
    let mut poll_id = 0;
    let mut stamp = 0i128;
    for _ in 0..5 {
        attempts.push(poll("errors", poll_id, Some(stamp), Some(100.0)));
        poll_id += 1;
        stamp += 200_000_000;
    }
    let mut counted = 0;
    let mut high_in_block = 0;
    while counted < 60 {
        attempts.push(poll("errors", poll_id, Some(stamp), Some(100.0)));
        poll_id += 1;
        stamp += 200_000_000;
        counted += 1;
        high_in_block += 1;
        // The duplicate of the row is neutral and stays.
        attempts.push(poll(
            "errors",
            poll_id,
            Some(stamp - 200_000_000),
            Some(100.0),
        ));
        poll_id += 1;
        if high_in_block == 9 && counted < 60 {
            attempts.push(error_attempt("errors", poll_id));
            poll_id += 1;
            high_in_block = 0;
        }
        if high_in_block == 10 {
            high_in_block = 0;
        }
    }
    let trial = spec("errors", 1, 1, 100, TrialShape::AllWorkersFull);
    let failed = analyze(&trial, &attempts, &qualified_workload(1, 100));
    assert_eq!(failed.longest_high, 9, "{:?}", failed);
    assert_eq!(failed.high_opportunities, 0);
    assert_eq!(failed.high_blocks_complete, 0);
    assert_eq!(failed.verdict(), "FAIL");

    // Removing only the error attempts leaves duplicates neutral: six opportunities and six
    // successful blocks, i.e. the whole growth gate would falsely pass.
    let filtered: Vec<PollRecord> = attempts
        .iter()
        .filter(|record| record.error.is_none())
        .cloned()
        .enumerate()
        .map(|(index, mut record)| {
            record.poll_id = index as u64;
            record
        })
        .collect();
    // Re-index the duplicate rows: the filtered log still repeats each timestamp once.
    let passed = analyze(&trial, &filtered, &qualified_workload(1, 100));
    assert_eq!(passed.longest_high, 10, "{:?}", passed);
    assert_eq!(passed.high_opportunities, 6);
    assert_eq!(passed.high_blocks_complete, 6);
    assert_eq!(passed.verdict(), "PASS");
}

#[test]
fn settling_boundary_is_exactly_after_the_fifth_distinct_row() {
    let trial = spec("settle", 1, 1, 100, TrialShape::OneWorkerFull);

    // An error before the fifth settling row is settling evidence: it cannot shorten the
    // counted span, so six full ten-row runs still complete.
    let mut early = RawTable::with_duplicates("early", 5, 60, 100.0);
    early.attempts.insert(7, error_attempt("early", 998));
    let early_analysis = analyze(&trial, &early.attempts, &qualified_workload(1, 100));
    assert_eq!(early_analysis.counted_distinct, 60);
    assert_eq!(early_analysis.high_opportunities, 6);

    // An error after the fifth settling row is inside the counted span. It resets the run,
    // so only five of the six non-overlapping ten-row windows remain complete.
    let mut table = RawTable::with_duplicates("settle", 5, 60, 100.0);
    table.attempts.insert(12, error_attempt("settle", 999));
    let analysis = analyze(&trial, &table.attempts, &qualified_workload(1, 100));
    assert_eq!(analysis.counted_distinct, 60);
    assert_eq!(analysis.high_opportunities, 5);
    assert_eq!(analysis.high_blocks_complete, 5);
}

#[test]
fn replay_a100_b90_a100_is_not_recounted() {
    let mut clock = ObservationClock::default();
    assert_eq!(clock.observe(Some(100)), Clock::Distinct);
    assert_eq!(clock.observe(Some(90)), Clock::Regressed);
    assert_eq!(clock.observe(Some(100)), Clock::Duplicate);
}

#[test]
fn post_correction_readmission_counts_at_most_one_row_per_streak() {
    // A100 -> 100 regressed B90 polls -> identical A100: the correction re-anchors to 90, so
    // A100 is genuinely advancing and is re-admitted exactly once. A second identical A100
    // is then a duplicate, so one streak can never rebuild a ten-observation run.
    let mut clock = ObservationClock::default();
    assert_eq!(clock.observe(Some(100)), Clock::Distinct);
    for _ in 0..99 {
        assert_eq!(clock.observe(Some(90)), Clock::Regressed);
    }
    assert_eq!(clock.observe(Some(90)), Clock::Reanchor);
    assert_eq!(clock.observe(Some(100)), Clock::Distinct);
    assert_eq!(clock.observe(Some(100)), Clock::Duplicate);
    // Even five such cycles stay far below a complete run: each costs 100 regressed polls.
    let mut runs = Runs::default();
    for _ in 0..5 {
        runs.step(
            GrowthPolicy::CeilingInhibited,
            Clock::Distinct,
            true,
            Some(decode_rate(bits(100.0))),
            commitment(1),
        );
        runs.step(
            GrowthPolicy::CeilingInhibited,
            Clock::Duplicate,
            true,
            Some(decode_rate(bits(100.0))),
            commitment(1),
        );
    }
    // Five cycles cost five observations and five complete 100-poll streaks: no run completes.
    assert_eq!(runs.high, 5);
    assert_eq!(runs.high_opportunities, 0);
}

#[test]
fn duplicate_only_volume_never_reaches_the_counted_span() {
    // Two attempts per timestamp with no new reading: the second is neutral, so the counted
    // span grows by one row per pair and cannot reach sixty distinct rows in the budget.
    let mut table = RawTable::with_duplicates("dupes", 5, 60, 100.0);
    // Keep every row at one timestamp: only the first is Distinct.
    for row in table.attempts.iter_mut() {
        row.sdk_timestamp_ns = Some(1_000);
    }
    let analysis = analyze(
        &spec("dupes", 1, 1, 100, TrialShape::OneWorkerFull),
        &table.attempts,
        &qualified_workload(1, 100),
    );
    assert_ne!(
        analysis.verdict(),
        "pass",
        "sixty identical timestamps cannot supply sixty distinct observations"
    );
}

#[test]
fn sustained_regression_reanchors_only_on_the_hundredth_poll() {
    let mut clock = ObservationClock::default();
    assert_eq!(clock.observe(Some(1_000)), Clock::Distinct);
    for _ in 0..99 {
        assert_eq!(clock.observe(Some(900)), Clock::Regressed);
    }
    // Poll 100 re-anchors to its own timestamp and is discarded.
    assert_eq!(clock.observe(Some(900)), Clock::Reanchor);
    // A genuinely advancing row below the old maximum is now Distinct in the new epoch.
    assert_eq!(clock.observe(Some(901)), Clock::Distinct);
    // The re-admitted row alone cannot complete a run.
    let mut runs = Runs::default();
    runs.step(
        GrowthPolicy::CeilingInhibited,
        Clock::Distinct,
        true,
        Some(decode_rate(bits(100.0))),
        commitment(1),
    );
    assert_eq!(runs.high, 1);
    assert_eq!(runs.high_opportunities, 0);
}

#[test]
fn one_lucky_run_is_not_enough() {
    // Three complete blocks and three broken ones: 3/6 fails the majority-of-blocks rule.
    let mut attempts: Vec<PollRecord> = Vec::new();
    let mut poll_id = 0u64;
    let mut stamp = 0i128;
    for _ in 0..5 {
        attempts.push(poll("lucky", poll_id, Some(stamp), Some(100.0)));
        poll_id += 1;
        stamp += 200_000_000;
    }
    for block in 0..6 {
        for row in 0..10 {
            attempts.push(poll("lucky", poll_id, Some(stamp), Some(100.0)));
            poll_id += 1;
            stamp += 200_000_000;
            if block >= 3 && row == 4 {
                attempts.push(error_attempt("lucky", poll_id));
                poll_id += 1;
            }
        }
    }
    let trial = spec("lucky", 1, 1, 100, TrialShape::AllWorkersFull);
    let analysis = analyze(&trial, &attempts, &qualified_workload(1, 100));
    assert_eq!(analysis.high_blocks_complete, 3);
    assert_eq!(analysis.verdict(), "FAIL");
}

#[test]
fn sixty_row_cutoff_excludes_trailing_attempts() {
    let mut table = RawTable::with_duplicates("cut", 5, 61, 100.0);
    // Corrupt the 61st counted distinct row: it is outside the counted span.
    let last_distinct = table.attempts.len() - 2;
    table.attempts[last_distinct].cpu_percent_bits = Some(bits(f32::NAN));
    let trial = spec("cut", 1, 1, 100, TrialShape::OneWorkerFull);
    let analysis = analyze(&trial, &table.attempts, &qualified_workload(1, 100));
    assert_eq!(analysis.counted_distinct, 60);
    assert!(analysis.passed(), "{:?}", analysis.failures);
}

#[test]
fn zero_rates_never_shrink_and_never_grow() {
    let table = RawTable::with_duplicates("zero", 5, 60, 0.0);
    let trial = spec("zero", 2, 1, 100, TrialShape::OneWorkerFull);
    let analysis = analyze(&trial, &table.attempts, &qualified_workload(1, 100));
    assert!(analysis.zero >= 60);
    assert_eq!(analysis.low_opportunities, 0);
    assert_eq!(analysis.high_opportunities, 0);
    // A zero-only trace cannot satisfy the positive-rate row; it is the S-B gate, not a pass.
    assert!(!analysis.passed());
}

#[test]
fn a_wrong_live_memory_limit_makes_the_trial_inconclusive() {
    let table = RawTable::with_duplicates("mem", 5, 60, 100.0);
    let trial = spec("mem", 1, 1, 100, TrialShape::AllWorkersFull);
    // 2048 MiB rows against a 1024 MiB declaration: the page walk measured another size.
    let mut wrong = table.attempts.clone();
    for record in &mut wrong {
        record.memory_limit_bytes = Some(2048 << 20);
    }
    let analysis = analyze(&trial, &wrong, &qualified_workload(1, 100));
    assert_eq!(analysis.verdict(), "INCONCLUSIVE");
    assert!(
        analysis
            .inconclusive
            .iter()
            .any(|reason| reason.contains("declared 1024 MiB"))
    );
}

#[test]
fn suitemate_failure_is_not_pooled_away() {
    let good_table = RawTable::with_duplicates("good", 5, 60, 100.0);
    let bad_table = RawTable::with_duplicates("bad", 5, 30, 100.0);
    let good = spec("good", 1, 1, 100, TrialShape::OneWorkerFull);
    let bad = spec("bad", 1, 1, 100, TrialShape::OneWorkerFull);
    let analyses = vec![
        analyze(&good, &good_table.attempts, &qualified_workload(1, 100)),
        analyze(&bad, &bad_table.attempts, &qualified_workload(1, 100)),
    ];
    let verdict = analyze_suite(&analyses, &[good, bad]);
    assert_eq!(verdict.verdict(), "INCONCLUSIVE");
    assert!(
        verdict
            .inconclusive
            .iter()
            .any(|reason| reason.starts_with("bad:"))
    );
}

#[test]
fn slow_producers_progress_on_distinct_rows_at_declared_phases() {
    for period_ms in [400i128, 600] {
        for phase_ms in [0i128, 50, 100, 150] {
            // The reader polls every 200 ms; the producer publishes every `period_ms` from
            // `phase_ms`. Ten distinct highs must still complete the run.
            let mut attempts = Vec::new();
            let start = phase_ms;
            for (poll_id, step) in (0..200i128).enumerate() {
                let at = start + step * 200;
                let published = if at >= period_ms {
                    Some(((at - period_ms) / period_ms) * period_ms)
                } else {
                    None
                };
                attempts.push(poll("slow", poll_id as u64, published, Some(100.0)));
            }
            let mut clock = ObservationClock::default();
            let mut runs = Runs::default();
            for record in &attempts {
                let observation = clock.observe(record.sdk_timestamp_ns);
                runs.step(
                    GrowthPolicy::CeilingInhibited,
                    observation,
                    true,
                    record.cpu_percent_bits.map(decode_rate),
                    commitment(1),
                );
            }
            assert!(
                runs.longest_high >= 10,
                "period={period_ms} phase={phase_ms} longest={}",
                runs.longest_high
            );
        }
    }
}

#[test]
fn idle_and_non_owned_qualification_reject_marginal_samples() {
    let mut idle = qualified_idle();
    idle[3].idle_hundredths = 8_999;
    idle[7].idle_hundredths = 8_999;
    // Eight of ten still pass; nine are required.
    assert!(!qualify_idle(&idle).is_empty());

    // Two samples of exactly 0.25 core: mean 0.025 passes the 0.10 limit and nearest-rank
    // p95 (rank 19 of 20) is exactly the 0.25 limit, so the inclusive comparison passes.
    let at_limit: Vec<ProcessDelta> = (0..20)
        .map(|index| ProcessDelta {
            sample_id: index as u64,
            pid: 2 + index,
            command: "worker".to_string(),
            cpu_ns: if index < 2 { 250_000_000 } else { 0 },
            wall_ns: 1_000_000_000,
            excluded: false,
        })
        .collect();
    assert!(qualify_non_owned(&at_limit).is_empty());
    // One nanosecond above the exact limit fails.
    let mut above: Vec<ProcessDelta> = at_limit.clone();
    above[0].cpu_ns += 1;
    above[1].cpu_ns += 1;
    assert!(!qualify_non_owned(&above).is_empty());
    // Two processes at 0.06 core in the same interval aggregate to 0.12 host-core, above the
    // 0.10 mean limit, even though neither alone would trip it.
    let aggregate = vec![
        ProcessDelta {
            sample_id: 0,
            pid: 2,
            command: "one".to_string(),
            cpu_ns: 60_000_000,
            wall_ns: 1_000_000_000,
            excluded: false,
        },
        ProcessDelta {
            sample_id: 0,
            pid: 3,
            command: "two".to_string(),
            cpu_ns: 60_000_000,
            wall_ns: 1_000_000_000,
            excluded: false,
        },
    ];
    assert!(!qualify_non_owned(&aggregate).is_empty());
    // A single 0.25-core sample passes p95 but fails the mean limit.
    let busy = vec![ProcessDelta {
        sample_id: 0,
        pid: 2,
        command: "build".to_string(),
        cpu_ns: 250_000_000,
        wall_ns: 1_000_000_000,
        excluded: false,
    }];
    assert!(!qualify_non_owned(&busy).is_empty());
}

#[test]
fn workload_duty_outside_the_declared_band_is_inconclusive() {
    let slow = qualified_workload(1, 80);
    let mut report = slow.clone();
    for checkpoint in &mut report.checkpoints {
        checkpoint.process_time_ns = checkpoint.process_time_ns * 90 / 100;
    }
    assert!(!qualify_workload(&report).is_empty());
    assert!(qualify_workload(&slow).is_empty());
    let gap = WorkloadReport {
        checkpoints: {
            let mut points = slow.checkpoints.clone();
            points[5].monotonic_ns += 30_000_000_000;
            points
        },
        ..slow
    };
    assert!(!qualify_workload(&gap).is_empty());
}

#[test]
fn calibration_matrix_is_the_declared_thirty_six_trials() {
    let mut all = Vec::new();
    for memory in [1024u32, 8192] {
        all.extend(calibration_matrix(memory));
    }
    assert_eq!(all.len(), 36);
    let expected = [
        (1u8, 1u32, 80u32),
        (1, 1, 90),
        (1, 1, 100),
        (2, 1, 80),
        (2, 1, 90),
        (2, 1, 100),
        (2, 2, 100),
        (4, 1, 100),
        (4, 4, 100),
    ];
    for spec in &all {
        assert!(
            expected.contains(&(spec.cpus, spec.workers, spec.duty_percent)),
            "{spec:?}"
        );
        assert!(spec.phase_ms == 0 || spec.phase_ms == 100);
    }
}

#[test]
fn production_growth_policy_still_holds_at_the_ceiling() {
    // Full demand at the 4-CPU ceiling: the production-shaped shadow proposes nothing, while
    // the calibration threshold opportunity still completes its run (P0-D).
    let mut proposals = Runs::default();
    let mut threshold = Runs::default();
    for _ in 0..10 {
        proposals.step(
            GrowthPolicy::CeilingInhibited,
            Clock::Distinct,
            true,
            Some(decode_rate(bits(400.0))),
            commitment(4),
        );
        threshold.step(
            GrowthPolicy::FixedThreshold,
            Clock::Distinct,
            true,
            Some(decode_rate(bits(400.0))),
            commitment(4),
        );
    }
    assert_eq!(proposals.high, 0);
    assert_eq!(proposals.longest_high, 0);
    assert_eq!(proposals.high_opportunities, 0);
    assert_eq!(threshold.longest_high, 10);
    assert_eq!(threshold.high_opportunities, 1);

    // Below the ceiling both policies agree, so the separation changes only the C=4 row.
    let mut proposals = Runs::default();
    let mut threshold = Runs::default();
    for _ in 0..10 {
        for (runs, policy) in [
            (&mut proposals, GrowthPolicy::CeilingInhibited),
            (&mut threshold, GrowthPolicy::FixedThreshold),
        ] {
            runs.step(
                policy,
                Clock::Distinct,
                true,
                Some(decode_rate(bits(190.0))),
                commitment(2),
            );
        }
    }
    assert_eq!(proposals.high_opportunities, 1);
    assert_eq!(threshold.high_opportunities, 1);
}

#[test]
fn c4_all_workers_calibration_row_can_pass_at_the_ceiling() {
    // The declared C=4 all-workers row runs at the physical ceiling: four complete high runs
    // must still be visible, and the qualified 60-row 400% trace supplies six.
    let trial = calibration_matrix(1024)
        .into_iter()
        .find(|spec| spec.cpus == 4 && spec.workers == 4 && spec.trial_index == 1)
        .expect("the declared C=4 all-workers row");
    let table = RawTable::with_duplicates(&trial.trial, 5, 60, 400.0);
    let analysis = analyze(&trial, &table.attempts, &qualified_workload(4, 100));
    assert!(analysis.passed(), "{:?}", analysis.failures);
    assert_eq!(analysis.counted_distinct, 60);
    assert_eq!(analysis.positive, 60);
    assert_eq!(analysis.longest_high, 10);
    assert_eq!(analysis.high_opportunities, 6);
    assert_eq!(analysis.high_blocks_complete, 6);
    assert_eq!(analysis.median.map(|rate| rate.as_f64()), Some(400.0));
    // The ceiling is still modelled for the production policy: it would propose no growth.
    assert_eq!(analysis.proposal_high_opportunities, 0);
}

#[test]
fn c4_all_workers_trace_interrupted_in_three_blocks_fails() {
    // The same qualified C=4 trace with a lookup error inside the first three ten-row blocks.
    // The whole-span runs survive (five opportunities), but only three blocks complete, which
    // is below the declared four: the row must fail.
    let trial = calibration_matrix(1024)
        .into_iter()
        .find(|spec| spec.cpus == 4 && spec.workers == 4 && spec.trial_index == 1)
        .expect("the declared C=4 all-workers row");
    let mut attempts: Vec<PollRecord> = Vec::new();
    let mut poll_id = 0u64;
    let mut stamp = 0i128;
    for _ in 0..5 {
        attempts.push(poll(&trial.trial, poll_id, Some(stamp), Some(400.0)));
        poll_id += 1;
        stamp += 200_000_000;
    }
    for block in 0..6 {
        for row in 0..10 {
            attempts.push(poll(&trial.trial, poll_id, Some(stamp), Some(400.0)));
            poll_id += 1;
            stamp += 200_000_000;
            if block < 3 && row == 4 {
                attempts.push(error_attempt(&trial.trial, poll_id));
                poll_id += 1;
            }
        }
    }
    let analysis = analyze(&trial, &attempts, &qualified_workload(4, 100));
    assert_eq!(analysis.counted_distinct, 60);
    assert_eq!(analysis.high_opportunities, 5);
    assert_eq!(analysis.high_blocks_complete, 3);
    assert_eq!(analysis.verdict(), "FAIL");
    assert!(
        analysis
            .failures
            .iter()
            .any(|reason| reason.contains("3/6 ten-row blocks") && reason.contains("4 required")),
        "{:?}",
        analysis.failures
    );
}

#[test]
fn wide_products_are_exact_beyond_128_bits() {
    // Values that fit in one `u128` must reduce to the ordinary product...
    for (a, b) in [
        (1u128 << 64, (1u128 << 64) - 1),
        (u128::MAX / 3, 3),
        (0, u128::MAX),
    ] {
        assert_eq!(mul_wide(a, b), (0, a * b), "{a} * {b}");
    }
    // ...and larger ones keep both halves of the 256-bit product.
    assert_eq!(mul_wide(u128::MAX, u128::MAX), (u128::MAX - 1, 1));
    assert_eq!(mul_wide(1u128 << 127, 3), (1, 1u128 << 127));
    assert_eq!(
        mul_wide((1u128 << 64) + 12345, (1u128 << 64) + 6789),
        (1, 0x4abe_0000_0000_04fe_d79d)
    );
    // Cross multiplication therefore decides without a checked multiply.
    assert!(Ratio::new(u128::MAX, u128::MAX).cmp_ratio(&Ratio::new(1, 1)) == Ordering::Equal);
    assert!(Ratio::new(u128::MAX, u128::MAX - 1).cmp_ratio(&Ratio::new(1, 1)) == Ordering::Greater);
    assert!(Ratio::new(1, u128::MAX).cmp_ratio(&Ratio::new(1, u128::MAX - 1)) == Ordering::Less);
}

#[test]
fn cross_configuration_medians_compare_exactly() {
    // Matched one-worker medians of 100 / 105 / 98 %: C2/C1 = 1.05 and C4/C1 = 0.98 both sit
    // inside 0.85..=1.15 exactly, with no rounded intermediate.
    let mut specs = Vec::new();
    let mut analyses = Vec::new();
    for index in [1u8, 2] {
        for (cpus, rate) in [(1u8, 100.0f32), (2, 105.0), (4, 98.0)] {
            let mut trial = spec(
                &format!("cal-m1024-c{cpus}-w1-d100-t{index}"),
                cpus,
                1,
                100,
                TrialShape::OneWorkerFull,
            );
            trial.trial_index = index;
            let table = RawTable::with_duplicates(&trial.trial, 5, 60, rate);
            analyses.push(analyze(
                &trial,
                &table.attempts,
                &qualified_workload(1, 100),
            ));
            specs.push(trial);
        }
    }
    for analysis in &analyses {
        assert!(analysis.passed(), "{:?}", analysis.failures);
    }
    let verdict = analyze_suite(&analyses, &specs);
    assert!(verdict.failures.is_empty(), "{:?}", verdict.failures);
    assert_eq!(verdict.verdict(), "PASS", "{:?}", verdict.inconclusive);

    // A C=4 median of 120 % is outside the band on the cross-configuration row alone.
    let mut skewed = analyses.clone();
    for analysis in skewed
        .iter_mut()
        .filter(|analysis| analysis.trial.contains("-c4-"))
    {
        analysis.median = Some(decoded_rate(bits(120.0)));
    }
    let verdict = analyze_suite(&skewed, &specs);
    assert!(
        verdict
            .failures
            .iter()
            .any(|reason| reason.contains("C4/C1")),
        "{:?}",
        verdict.failures
    );
    assert!(
        !verdict
            .failures
            .iter()
            .any(|reason| reason.contains("C2/C1")),
        "{:?}",
        verdict.failures
    );
}
