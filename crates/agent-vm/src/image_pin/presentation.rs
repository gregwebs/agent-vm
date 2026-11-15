//! The two read-only projections of the pin authority (ADR-0068, #609).
//!
//! Neither adds state, policy or a write path: the listing renders approvals the
//! store already validated and the diagnostic row counts them. Both therefore
//! read one bounded snapshot without a lock, and both project knowledge through
//! [`active::knowledge`] rather than restating the role algebra — a listing that
//! disagreed with retirement would be a second, quieter policy engine.
//!
//! # Why the doctor row cannot leak what the listing prints
//!
//! The listing is a deliberate private-reference disclosure surface; the
//! diagnostic row is not. So the doctor facade returns counts and a path only,
//! and the reference-bearing snapshot type never leaves this module: `doctor`
//! cannot render a reference it was never handed.

use std::cmp::Ordering;
use std::path::PathBuf;

use anyhow::Result;

use crate::one_line::Line;
use crate::project::ProjectDir;

use super::active::{KnowledgeFacts, RoleKnowledge};
use super::store::Store;
use super::{ApprovedPin, HostLinuxPlatform, ProjectId};

/// One approval of the projecting project, with the knowledge of its roles in
/// its own project/platform scope.
///
/// Deliberately without `Debug`/`Display`: the record's reference and digest are
/// private disclosure, so no diagnostic, log line or error context can render
/// one by accident.
pub(super) struct ObservedPin {
    pub(super) pin: ApprovedPin,
    pub(super) knowledge: KnowledgeFacts,
}

/// Every approval of one project across platforms, from one store snapshot, plus
/// the store path the doctor row names. Also without `Debug`/`Display`, for the
/// same reason as [`ObservedPin`].
pub(super) struct ProjectPinsSnapshot {
    pub(super) path: PathBuf,
    pub(super) pins: Vec<ObservedPin>,
}

/// The pin-store path, the host platform's role presence and its unclaimed
/// count: everything the `active images:` row may say.
///
/// A separate type from [`ProjectPinsSnapshot`] on purpose — it holds no
/// reference, digest or revision, so the row's redaction is a property of its
/// input rather than of its formatter.
pub(crate) struct ActiveImages {
    pub(crate) path: PathBuf,
    pub(crate) boot_recorded: bool,
    pub(crate) output_recorded: bool,
    pub(crate) unclaimed: usize,
}

/// What `doctor` may report about this project's approvals.
pub(crate) enum ActiveImagesObservation {
    /// The store was located and read (or is genuinely absent).
    Available(ActiveImages),
    /// The project directory could not be captured, so no project's approvals
    /// were even looked for.
    ProjectUnknown,
    /// The store could not be located or read. `authority_located` separates an
    /// unlocatable `$HOME` from located damage: the existing convention is that
    /// only located damage fails the diagnostic.
    Unavailable {
        message: Line,
        authority_located: bool,
    },
}

/// The single listing command's report: the header plus one row per approval.
///
/// Whole-file validation happens before this projection, so damage is an error
/// with no partial output rather than a shortened listing.
pub(crate) fn pins_report(project: &ProjectDir) -> Result<String> {
    let store = Store::host()?;
    let snapshot = store.project_pins(&ProjectId::of(project))?;
    Ok(render_pins(&snapshot))
}

/// This project's approval summary for the diagnostic row.
pub(crate) fn observe_active_images(project: Option<&ProjectDir>) -> ActiveImagesObservation {
    observe_active_images_with(project, || load_active_images(project))
}

/// [`observe_active_images`] with the load supplied, so the ordering claim — an
/// uncapturable project reads nothing — is tested by a loader that never runs
/// instead of inferred from the returned value alone.
fn observe_active_images_with(
    project: Option<&ProjectDir>,
    load: impl FnOnce() -> std::result::Result<ActiveSnapshot, ActiveLoadError>,
) -> ActiveImagesObservation {
    if project.is_none() {
        return ActiveImagesObservation::ProjectUnknown;
    }
    match load() {
        Ok(active) => ActiveImagesObservation::Available(active),
        Err(error) => ActiveImagesObservation::Unavailable {
            message: error.message,
            authority_located: error.authority_located,
        },
    }
}

/// The doctor row's snapshot: counts and a path, never a reference or digest.
type ActiveSnapshot = ActiveImages;

/// A located-or-not failure, kept typed so the row's failure decision never
/// inspects a message. The [`Line`] has already escaped the text.
struct ActiveLoadError {
    message: Line,
    authority_located: bool,
}

impl ActiveLoadError {
    /// `$HOME` itself is unusable, so nothing was read: the authority could not
    /// be located. Reporting that as damage would diagnose a file that was never
    /// found.
    fn unlocated(error: anyhow::Error) -> Self {
        Self {
            message: crate::one_line::text(&error.to_string()),
            authority_located: false,
        }
    }

    /// The authority was located and the *store's own* safe message explains why
    /// it could not be read. `to_string` and not the cause chain: a cause may
    /// quote bytes of the damaged record.
    fn located(error: anyhow::Error) -> Self {
        Self {
            message: crate::one_line::text(&error.to_string()),
            authority_located: true,
        }
    }
}

fn load_active_images(
    project: Option<&ProjectDir>,
) -> std::result::Result<ActiveSnapshot, ActiveLoadError> {
    // Unreachable: `observe_active_images_with` never calls the loader for an
    // absent project. A fixed error keeps the no-panic rule without pretending a
    // project exists.
    let project = project.ok_or_else(|| ActiveLoadError {
        message: crate::one_line::text("the invoking project directory is unknown"),
        authority_located: false,
    })?;
    let store = Store::host().map_err(ActiveLoadError::unlocated)?;
    let snapshot = store
        .project_pins(&ProjectId::of(project))
        .map_err(ActiveLoadError::located)?;
    Ok(summarize_host(&snapshot, &HostLinuxPlatform::host()))
}

const HEADER: &str = "REFERENCE\tPLATFORM\tDIGEST\tREVISION\tROLES\tUNRESOLVED\n";

fn render_pins(snapshot: &ProjectPinsSnapshot) -> String {
    let mut rows: Vec<(String, String, &ObservedPin)> = snapshot
        .pins
        .iter()
        .map(|observed| {
            (
                observed.pin.key.reference.whole(),
                observed.pin.key.platform.render(),
                observed,
            )
        })
        .collect();
    rows.sort_by(|left, right| order((&left.0, &left.1), (&right.0, &right.1)));
    let mut report = String::from(HEADER);
    for (reference, platform, observed) in rows {
        report.push_str(&row(
            &reference,
            &platform,
            observed.pin.digest.as_str(),
            observed.pin.revision.0,
            observed.knowledge,
        ));
    }
    report
}

/// The documented collation: raw canonical reference bytes, then raw rendered
/// platform bytes. Both are compared *before* escaping, because the escape
/// policy is a display transform — sorting its output would order rows by an
/// artifact of the terminal policy.
fn order(left: (&str, &str), right: (&str, &str)) -> Ordering {
    left.0
        .as_bytes()
        .cmp(right.0.as_bytes())
        .then_with(|| left.1.as_bytes().cmp(right.1.as_bytes()))
}

/// One TSV row: exactly six TAB-separated fields and one trailing LF.
///
/// The two text columns take the reference/disclosure escape policy, so schema
/// variants may carry printable punctuation without breaking the field count;
/// the digest and revision are already validated ASCII, and the role labels are
/// fixed literals.
fn row(
    reference: &str,
    platform: &str,
    digest: &str,
    revision: u64,
    facts: KnowledgeFacts,
) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}\n",
        crate::config::escape_str(reference),
        crate::config::escape_str(platform),
        digest,
        revision,
        role_labels(facts),
        unresolved_slots(facts),
    )
}

/// The ROLES column: the roles this record holds. A held role is Present
/// knowledge, so the spelling follows the kernel and never `RoleMask::as_str`,
/// whose last arm renders the both-role spelling for the empty mask.
fn role_labels(facts: KnowledgeFacts) -> &'static str {
    labels(
        facts.boot == RoleKnowledge::Present,
        facts.output == RoleKnowledge::Present,
    )
}

/// The UNRESOLVED column: the scope's unresolved slots, which is Unknown
/// knowledge — including for a record that holds the *other* role.
fn unresolved_slots(facts: KnowledgeFacts) -> &'static str {
    labels(
        facts.boot == RoleKnowledge::Unknown,
        facts.output == RoleKnowledge::Unknown,
    )
}

/// The four column spellings, joined in boot-then-output order. `none` is a
/// literal, not an empty field: a blank cell cannot distinguish "no role" from a
/// truncated row.
fn labels(boot: bool, output: bool) -> &'static str {
    match (boot, output) {
        (true, true) => "boot+output",
        (true, false) => "boot",
        (false, true) => "output",
        (false, false) => "none",
    }
}

/// The host-platform half of a project's snapshot.
///
/// The full typed platform, variant included, is compared: a foreign platform's
/// approval is neither this host's recorded role nor this host's uncertainty.
fn summarize_host(snapshot: &ProjectPinsSnapshot, host: &HostLinuxPlatform) -> ActiveImages {
    let mut boot_recorded = false;
    let mut output_recorded = false;
    let mut unclaimed = 0;
    for observed in &snapshot.pins {
        if observed.pin.key.platform != *host {
            continue;
        }
        let facts = observed.knowledge;
        boot_recorded |= facts.boot == RoleKnowledge::Present;
        output_recorded |= facts.output == RoleKnowledge::Present;
        // The retained-domain definition: an approval holding neither role.
        // Unknown counts, and so does fully resolved Absent; retirement is the
        // narrower `active::may_retire`, which the listing never performs.
        if facts.boot != RoleKnowledge::Present && facts.output != RoleKnowledge::Present {
            unclaimed += 1;
        }
    }
    ActiveImages {
        path: snapshot.path.clone(),
        boot_recorded,
        output_recorded,
        unclaimed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_pin::ManifestDigest;
    use crate::image_pin::active::{self, HeldRoles, RoleMask};

    // --- the knowledge table ------------------------------------------------
    //
    // Every row is derived from `active::knowledge` and `active::may_retire`, so
    // this table cannot disagree with retirement; what it fixes is the *label*.

    fn facts(resolved: RoleMask, held: Option<RoleMask>) -> KnowledgeFacts {
        active::knowledge(resolved, held.and_then(HeldRoles::new))
    }

    #[test]
    fn role_labels_follow_knowledge_and_retirement() {
        let (boot, output, both, empty) = (
            RoleMask::BOOT,
            RoleMask::OUTPUT,
            RoleMask::BOOT_AND_OUTPUT,
            RoleMask::EMPTY,
        );
        let rows = [
            // (resolved, held, ROLES, UNRESOLVED, unclaimed, may_retire)
            (empty, None, "none", "boot+output", true, false),
            (boot, None, "none", "output", true, false),
            (output, None, "none", "boot", true, false),
            (boot, Some(boot), "boot", "output", false, false),
            (output, Some(output), "output", "boot", false, false),
            (both, Some(boot), "boot", "none", false, false),
            (both, Some(output), "output", "none", false, false),
            (both, Some(both), "boot+output", "none", false, false),
            (both, None, "none", "none", true, true),
            // The kernel is what decides a held role's label: holding both is
            // Present/Present even in a scope that resolved only Output. That
            // join is not a state a valid store can persist (a held role must be
            // resolved), and this table does not weaken that rule.
            (output, Some(both), "boot+output", "none", false, false),
        ];
        for (resolved, held, roles, unresolved, unclaimed, retire) in rows {
            let facts = facts(resolved, held);
            assert_eq!(role_labels(facts), roles, "{resolved:?}/{held:?}");
            assert_eq!(unresolved_slots(facts), unresolved, "{resolved:?}/{held:?}");
            assert_eq!(
                facts.boot != RoleKnowledge::Present && facts.output != RoleKnowledge::Present,
                unclaimed,
                "{resolved:?}/{held:?}"
            );
            assert_eq!(active::may_retire(facts), retire, "{resolved:?}/{held:?}");
            // Retirement is a strict subset of unclaimed, never the same
            // predicate: an uncertain record is not droppable.
            assert!(
                !active::may_retire(facts) || unclaimed,
                "{resolved:?}/{held:?}"
            );
        }
        // Internal EMPTY normalizes to the same "holds nothing" state as the
        // omitted field, so both project alike.
        assert_eq!(HeldRoles::new(empty), None);
    }

    // --- the row formatter and the collation --------------------------------

    /// Text a validated schema could never carry (canonical references and
    /// platforms admit no control bytes), used at the formatter seam: weakening
    /// the OCI parser to admit a hostile fixture would be the wrong trade.
    #[test]
    fn listing_escapes_columns_without_changing_sort_keys() {
        let hostile_reference = "reg.example/\"x\t\u{1b}[31m\u{7f}:1";
        let hostile_platform = "linux/arm64\\vary\n\u{e9}";
        let facts = facts(RoleMask::EMPTY, None);
        let digest = digest('a');
        let row = row(
            hostile_reference,
            hostile_platform,
            digest.as_str(),
            7,
            facts,
        );
        assert_eq!(row.matches('\n').count(), 1, "{row:?}");
        assert!(row.ends_with('\n'), "{row:?}");
        assert_eq!(row.split('\t').count(), 6, "six fields: {row:?}");
        assert!(!row.contains('\u{1b}') && !row.contains('\u{7f}'));
        assert!(row.contains("\\\""), "quote escaped: {row:?}");
        assert!(row.contains("\\\\"), "backslash doubled: {row:?}");
        assert!(row.contains("\\x09"), "TAB escaped: {row:?}");
        assert!(row.contains("\\x1b"), "ESC escaped: {row:?}");
        assert!(row.contains("\\x0a"), "LF escaped: {row:?}");
        assert!(
            row.contains("\\xc3\\xa9"),
            "non-ASCII byte-escaped: {row:?}"
        );

        // Raw byte order, not the escaped order: `"` (0x22) precedes `A` (0x41),
        // while their escaped spellings order the other way.
        assert_eq!(
            order(("\"x:1", "linux/arm64"), ("A:1", "linux/arm64")),
            Ordering::Less
        );
        // Then the rendered platform, so one reference keeps its platforms
        // adjacent and deterministic.
        assert_eq!(
            order(("a:1", "linux/amd64"), ("a:1", "linux/arm64")),
            Ordering::Less
        );
        assert_eq!(
            order(("a:1-variant", "linux/arm64/v8"), ("a:1", "linux/arm64")),
            Ordering::Greater
        );
    }

    // --- the snapshot projection -------------------------------------------

    fn digest(byte: char) -> ManifestDigest {
        ManifestDigest::parse(&format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn platform(architecture: &str, variant: Option<&str>) -> HostLinuxPlatform {
        let mut platform = HostLinuxPlatform::for_tests();
        platform.architecture = architecture.to_string();
        platform.variant = variant.map(str::to_owned);
        platform
    }

    fn observed(
        reference: &str,
        platform: &HostLinuxPlatform,
        byte: char,
        revision: u64,
        knowledge: KnowledgeFacts,
    ) -> ObservedPin {
        use crate::image_acquire::OciTarget;
        use crate::image_pin::{PinKey, PinRevision};

        let target = OciTarget::parse(reference).unwrap();
        let mut key = PinKey::new(&ProjectId::for_tests('a'), &target).unwrap();
        key.platform = platform.clone();
        ObservedPin {
            pin: ApprovedPin {
                key,
                digest: digest(byte),
                revision: PinRevision(revision),
            },
            knowledge,
        }
    }

    fn snapshot(pins: Vec<ObservedPin>) -> ProjectPinsSnapshot {
        ProjectPinsSnapshot {
            path: PathBuf::from("/home/u/.config/agent-vm/image-pins.json"),
            pins,
        }
    }

    #[test]
    fn rendered_rows_are_sorted_by_reference_then_platform() {
        let host = HostLinuxPlatform::for_tests();
        let facts = facts(RoleMask::BOOT_AND_OUTPUT, Some(RoleMask::BOOT_AND_OUTPUT));
        let report = render_pins(&snapshot(vec![
            observed("reg.example/b:2", &host, 'c', 3, facts),
            observed("reg.example/a:1", &host, 'b', 2, facts),
            observed("reg.example/a:1", &platform("zzz", None), 'd', 4, facts),
        ]));
        let references: Vec<&str> = report
            .lines()
            .skip(1)
            .map(|line| line.split('\t').next().unwrap())
            .collect();
        assert_eq!(
            references,
            ["reg.example/a:1", "reg.example/a:1", "reg.example/b:2"]
        );
        let platforms: Vec<&str> = report
            .lines()
            .skip(1)
            .map(|line| line.split('\t').nth(1).unwrap())
            .collect();
        assert_eq!(platforms[0], host.render(), "{}", platforms[0]);
        assert_eq!(
            report.matches('\n').count(),
            4,
            "header plus three rows: {report}"
        );
    }

    #[test]
    fn host_summary_counts_only_the_exact_platform() {
        let host = HostLinuxPlatform::for_tests();
        let other_arch = if host.architecture == "arm64" {
            "amd64"
        } else {
            "arm64"
        };
        let present = facts(RoleMask::BOOT, Some(RoleMask::BOOT));
        // The foreign holders own the *other* role, so "Output is not recorded"
        // below is a real observation rather than an untested consequence.
        let foreign_output = facts(RoleMask::OUTPUT, Some(RoleMask::OUTPUT));
        let unknown = facts(RoleMask::EMPTY, None);
        let active = summarize_host(
            &snapshot(vec![
                observed("reg.example/host:1", &host, 'a', 1, present),
                observed(
                    "reg.example/variant:1",
                    &platform(&host.architecture, Some("v8")),
                    'b',
                    2,
                    foreign_output,
                ),
                observed(
                    "reg.example/arch:1",
                    &platform(other_arch, None),
                    'c',
                    3,
                    foreign_output,
                ),
                observed(
                    "reg.example/variant-unclaimed:1",
                    &platform(&host.architecture, Some("v8")),
                    'd',
                    4,
                    unknown,
                ),
                observed(
                    "reg.example/arch-unclaimed:1",
                    &platform(other_arch, None),
                    'e',
                    5,
                    unknown,
                ),
            ]),
            &host,
        );
        assert!(active.boot_recorded);
        assert!(
            !active.output_recorded,
            "a foreign Output holder is not this host's"
        );
        assert_eq!(active.unclaimed, 0, "foreign uncertainty does not count");
        assert_eq!(
            active.path,
            PathBuf::from("/home/u/.config/agent-vm/image-pins.json")
        );
    }

    #[test]
    fn host_summary_counts_unknown_and_known_absent_as_unclaimed() {
        let host = HostLinuxPlatform::for_tests();
        let unknown = facts(RoleMask::EMPTY, None);
        let known_absent = facts(RoleMask::BOOT_AND_OUTPUT, None);
        let held = facts(RoleMask::OUTPUT, Some(RoleMask::OUTPUT));
        let active = summarize_host(
            &snapshot(vec![
                observed("reg.example/unknown:1", &host, 'a', 1, unknown),
                observed("reg.example/known-inactive:1", &host, 'b', 2, known_absent),
                observed("reg.example/held:1", &host, 'c', 3, held),
            ]),
            &host,
        );
        assert!(!active.boot_recorded);
        assert!(active.output_recorded);
        assert_eq!(active.unclaimed, 2);
    }

    // --- the loader seam ----------------------------------------------------

    #[test]
    fn unknown_project_does_not_read_the_store() {
        let calls = std::cell::Cell::new(0);
        let observation = observe_active_images_with(None, || {
            calls.set(calls.get() + 1);
            panic!("an uncapturable project must not read the store");
        });
        assert!(matches!(
            observation,
            ActiveImagesObservation::ProjectUnknown
        ));
        assert_eq!(calls.get(), 0);
    }

    /// The companion row: the seam actually invokes a supplied loader once, so
    /// the assertion above cannot pass vacuously.
    #[test]
    fn known_project_invokes_loader_once() {
        let calls = std::cell::Cell::new(0);
        let directory =
            crate::project::ProjectDir::from_path_for_tests(&std::env::temp_dir()).unwrap();
        let observation = observe_active_images_with(Some(&directory), || {
            calls.set(calls.get() + 1);
            Ok(ActiveImages {
                path: PathBuf::from("/p"),
                boot_recorded: true,
                output_recorded: false,
                unclaimed: 2,
            })
        });
        assert_eq!(calls.get(), 1);
        match observation {
            ActiveImagesObservation::Available(active) => {
                assert!(active.boot_recorded && !active.output_recorded);
                assert_eq!(active.unclaimed, 2);
            }
            _ => panic!("a supplied loader's value must be reported"),
        }
    }
}
