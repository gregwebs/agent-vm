//! Sandbox resource sizing at launch ([ADR-0070] D1): the **resource ceiling** the
//! launch options set and the **boot commitment** every launch route boots at.
//!
//! [ADR-0070]: ../../../docs/adr/0070-dynamic-resource-commitment.md

use std::time::Duration;

use microsandbox::sandbox::SandboxBuilder;
use vstd::prelude::*;

verus! {

/// The boot commitment's memory when the ceiling allows it. It is also the floor
/// live resize can never go below, because virtio-mem only plugs above it.
const BOOT_MEMORY_MIB: u32 = 512;
/// The boot commitment's online vCPUs, and the floor the CPU controller keeps.
const BOOT_CPUS: u8 = 1;
/// `u64` so the product of any `u32` GiB value cannot overflow before it is compared.
const MIB_PER_GIB: u64 = 1024;

/// Why a launch's resource options cannot form a ceiling, in refusal precedence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
enum CeilingRefusal { ZeroMemory, MemoryOverflow, ZeroCpus }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Sizing { max_cpus: u8, max_memory_mib: u32, boot_cpus: u8, boot_memory_mib: u32 }

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

} // verus!

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
}
