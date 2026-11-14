//! Which roles an approval holds, and which slots a project/platform scope has
//! actually resolved (ADR-0068).
//!
//! # Why three facts, not one
//!
//! An approval's `roles` say which single-holder slots it currently fills. They
//! say nothing about a slot nobody has claimed: a pin with no held role is
//! *unclaimed*, not proof that no earlier operation needed it. Only the scope's
//! `resolved` set can turn "no held role" into "known absent". Retirement is
//! therefore **iff both** roles are known-absent for one record, and a single
//! claim resolves exactly one slot for every record in the scope.
//!
//! # Why the algebra lives here
//!
//! Held roles, resolution and retirement are one small kernel that the store's
//! trusted adapters (decode, scope join, record walk) must not restate. Keeping
//! the kernel apart from I/O lets its truth tables and Verus contracts state the
//! rules once.

use serde::Deserialize as _;

use vstd::prelude::*;

use super::{HostLinuxPlatform, PinKey, ProjectId};

/// What one successful claim asks the store to record. Selection, refresh and
/// publication differ only in this value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RoleClaim {
    /// Approval content changed; membership is untouched (refresh, adoption).
    Keep,
    /// This approval is the successful result of the named role.
    Claim(Role),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Change {
    Unchanged,
    Changed,
}

/// One project on one measured platform: the unit whose roles are resolved
/// together. Never a whole project across platforms: this host's successful
/// acquisition cannot justify deleting a foreign platform's approval.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct ScopeKey {
    project: ProjectId,
    platform: HostLinuxPlatform,
}

impl ScopeKey {
    pub(super) fn of(project: ProjectId, platform: HostLinuxPlatform) -> Self {
        Self { project, platform }
    }

    pub(super) fn project(&self) -> &ProjectId {
        &self.project
    }

    pub(super) fn platform(&self) -> &HostLinuxPlatform {
        &self.platform
    }
}

impl std::fmt::Debug for ScopeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ScopeKey(<redacted>)")
    }
}

/// A record's held roles: a nonempty mask. `None` (no `roles` field) is the
/// separate "holds nothing" state, never "both known absent".
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct HeldRoles(RoleMask);

impl HeldRoles {
    pub(super) fn new(mask: RoleMask) -> Option<Self> {
        (!mask.is_empty()).then_some(Self(mask))
    }

    pub(super) fn mask(self) -> RoleMask {
        self.0
    }

    pub(super) fn contains(self, role: Role) -> bool {
        self.0.contains(role)
    }
}

impl std::fmt::Debug for HeldRoles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.as_str())
    }
}

/// A scope's resolved slots: a nonempty mask. A missing scope record is the
/// separate "both unknown" state.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct ResolvedRoles(RoleMask);

impl ResolvedRoles {
    pub(super) fn new(mask: RoleMask) -> Option<Self> {
        (!mask.is_empty()).then_some(Self(mask))
    }

    pub(super) fn mask(self) -> RoleMask {
        self.0
    }
}

impl std::fmt::Debug for ResolvedRoles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.as_str())
    }
}

/// One record's two roles against its scope's resolution: a held role is
/// Present, a resolved-but-unheld role is Absent, and an unresolved role is
/// Unknown regardless of what the record holds.
pub(super) fn knowledge(resolved: RoleMask, held: Option<HeldRoles>) -> KnowledgeFacts {
    let role = |role: Role| match held {
        Some(held) if held.contains(role) => RoleKnowledge::Present,
        _ if resolved.contains(role) => RoleKnowledge::Absent,
        _ => RoleKnowledge::Unknown,
    };
    KnowledgeFacts {
        boot: role(Role::Boot),
        output: role(Role::Output),
    }
}

/// The held roles a knowledge transition produces, mapped back from the kernel's
/// Present/Absent answer. Only the claimed role can move; the other role is
/// preserved, so an unresolved other role stays exactly as it was. `None` is the
/// same "holds nothing" state as the stored omitted field.
pub(super) fn after_role(
    after: KnowledgeFacts,
    held: Option<HeldRoles>,
    claimed: Role,
) -> Option<HeldRoles> {
    let base = held.map(HeldRoles::mask).unwrap_or(RoleMask::EMPTY);
    let knowledge = match claimed {
        Role::Boot => after.boot,
        Role::Output => after.output,
    };
    let mask = if knowledge == RoleKnowledge::Present {
        base.with(claimed)
    } else {
        base.without(claimed)
    };
    HeldRoles::new(mask)
}

/// A nonempty set of roles, spelled `boot`, `output` or `boot-and-output`.
///
/// Parsing is the only way to obtain one from stored text, so an empty mask,
/// an unknown spelling or a non-string cannot be represented.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct RoleMask(u8);

impl RoleMask {
    pub(super) const BOOT: Self = Self(1);
    pub(super) const OUTPUT: Self = Self(2);
    pub(super) const BOOT_AND_OUTPUT: Self = Self(3);
    /// No roles held: the empty mask the transition walk starts from. Not a
    /// value a record or a scope may store (they omit the field instead).
    pub(super) const EMPTY: Self = Self(0);

    pub(super) fn parse(stored: &str) -> Result<Self, ()> {
        match stored {
            "boot" => Ok(Self::BOOT),
            "output" => Ok(Self::OUTPUT),
            "boot-and-output" => Ok(Self::BOOT_AND_OUTPUT),
            _ => Err(()),
        }
    }

    pub(super) fn as_str(self) -> &'static str {
        match self.0 {
            1 => "boot",
            2 => "output",
            _ => "boot-and-output",
        }
    }

    pub(super) fn contains(self, role: Role) -> bool {
        self.0 & role.bit() != 0
    }

    pub(super) fn with(self, role: Role) -> Self {
        Self(self.0 | role.bit())
    }

    pub(super) fn without(self, role: Role) -> Self {
        Self(self.0 & !role.bit())
    }

    pub(super) fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Whether this mask names every role `other` names: the relational check
    /// that no held role is unresolved.
    pub(super) fn covers(self, other: Self) -> bool {
        other.0 & !self.0 == 0
    }
}

impl std::fmt::Debug for RoleMask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl serde::Serialize for RoleMask {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for RoleMask {
    /// `null`, `""`, an unknown spelling and a non-string are all damage; the
    /// optional field's own deserializer is what turns a present value into
    /// `Some`, so a pin can never silently lose its held roles.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let stored = String::deserialize(deserializer)?;
        Self::parse(&stored)
            .map_err(|()| serde::de::Error::custom("an image role mask must name a role"))
    }
}

/// A present `roles`/`resolved` value: missing is handled by serde's `default`,
/// and an explicit `null` must not become `None`.
pub(super) fn present_mask<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<RoleMask>, D::Error> {
    RoleMask::deserialize(deserializer).map(Some)
}

/// A present, positive write sequence: `null`, `0` and a non-number are damage.
pub(super) fn present_sequence<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u64>, D::Error> {
    let value = u64::deserialize(deserializer)?;
    if value == 0 {
        return Err(serde::de::Error::custom(
            "the write sequence must be positive",
        ));
    }
    Ok(Some(value))
}

/// The typed claim one save applies after the target approval exists. Built only
/// from a validated under-lock snapshot; the store never re-uses a preflight plan.
pub(super) struct ClaimPlan {
    scope: ScopeKey,
    role: Role,
    target: PinKey,
    /// The scope's resolution before this claim: what a record's knowledge was
    /// decided against.
    prior: RoleMask,
    /// The scope's resolution once this claim is applied.
    resolved: RoleMask,
}

impl ClaimPlan {
    pub(super) fn of(
        scope: ScopeKey,
        target: PinKey,
        role: Role,
        prior: RoleMask,
        resolved: RoleMask,
    ) -> Self {
        Self {
            scope,
            target,
            role,
            prior,
            resolved,
        }
    }

    pub(super) fn prior(&self) -> RoleMask {
        self.prior
    }

    pub(super) fn scope(&self) -> &ScopeKey {
        &self.scope
    }

    pub(super) fn target(&self) -> &PinKey {
        &self.target
    }

    pub(super) fn role(&self) -> Role {
        self.role
    }

    pub(super) fn resolved(&self) -> RoleMask {
        self.resolved
    }
}

verus! {

#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub(super) enum Role {
    Boot,
    Output,
}

impl Role {
    pub(super) fn bit(self) -> (bit: u8)
        ensures bit == (match self { Role::Boot => 1u8, Role::Output => 2u8 }),
    {
        match self {
            Role::Boot => 1u8,
            Role::Output => 2u8,
        }
    }
}

/// The three-valued knowledge of one role for one record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub(super) enum RoleKnowledge {
    Unknown,
    Present,
    Absent,
}

/// The knowledge of both slots for one record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub(super) struct KnowledgeFacts {
    pub(super) boot: RoleKnowledge,
    pub(super) output: RoleKnowledge,
}

/// Retirement is affirmative evidence about **both** slots: held means Present,
/// resolved-without-holding means Absent, and a missing resolution bit stays
/// Unknown and protects the record.
pub(super) fn may_retire(facts: KnowledgeFacts) -> (retire: bool)
    ensures retire == (facts.boot == RoleKnowledge::Absent && facts.output == RoleKnowledge::Absent),
{
    facts.boot == RoleKnowledge::Absent && facts.output == RoleKnowledge::Absent
}

/// One claim's input: both slots' prior knowledge, which role was claimed, and
/// whether this record is the claim's target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub(super) struct ClaimFacts {
    pub(super) boot: RoleKnowledge,
    pub(super) output: RoleKnowledge,
    pub(super) claimed: Role,
    pub(super) target: bool,
}

/// Claiming a slot makes it Present on the target and Absent on every other
/// record of the scope; the other slot's knowledge, including Unknown, is
/// untouched.
pub(super) fn claim_knowledge(facts: ClaimFacts) -> (after: KnowledgeFacts)
    ensures
        after.boot == if facts.claimed == Role::Boot {
            if facts.target { RoleKnowledge::Present } else { RoleKnowledge::Absent }
        } else {
            facts.boot
        },
        after.output == if facts.claimed == Role::Output {
            if facts.target { RoleKnowledge::Present } else { RoleKnowledge::Absent }
        } else {
            facts.output
        },
{
    let boot = if facts.claimed == Role::Boot {
        if facts.target { RoleKnowledge::Present } else { RoleKnowledge::Absent }
    } else {
        facts.boot
    };
    let output = if facts.claimed == Role::Output {
        if facts.target { RoleKnowledge::Present } else { RoleKnowledge::Absent }
    } else {
        facts.output
    };
    KnowledgeFacts { boot, output }
}

/// The global write sequence's one arithmetic step. Exhaustion is a distinct
/// outcome (no reservation) rather than wrapping, saturating or resetting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub(super) struct SequenceReservation {
    pub(super) next: u64,
    pub(super) reserved: bool,
}

pub(super) fn checked_next_sequence(current: u64) -> (reservation: SequenceReservation)
    ensures
        reservation.reserved == (current < u64::MAX),
        reservation.reserved ==> reservation.next == current + 1,
        reservation.reserved ==> reservation.next > current,
{
    if current == u64::MAX {
        SequenceReservation {
            next: 0,
            reserved: false,
        }
    } else {
        SequenceReservation {
            next: current + 1,
            reserved: true,
        }
    }
}

}

#[cfg(test)]
mod tests {
    use super::*;

    const K: [RoleKnowledge; 3] = [
        RoleKnowledge::Unknown,
        RoleKnowledge::Present,
        RoleKnowledge::Absent,
    ];

    /// Retirement is affirmative evidence about **both** slots: all nine
    /// knowledge pairs, including the impossible adapter states, so a
    /// one-slot rule cannot pass.
    #[test]
    fn retirement_requires_both_known_absent() {
        for boot in K {
            for output in K {
                assert_eq!(
                    may_retire(KnowledgeFacts { boot, output }),
                    boot == RoleKnowledge::Absent && output == RoleKnowledge::Absent,
                    "{boot:?}/{output:?}"
                );
            }
        }
    }

    /// The exhaustive 9 x 2 x 2 table: claiming a slot makes it Present on the
    /// target and Absent on every other record, and leaves the other slot's
    /// knowledge — including Unknown — exactly as it was.
    #[test]
    fn knowledge_transition_matches_36_literal_rows() {
        let rows = [
            (
                RoleKnowledge::Unknown,
                RoleKnowledge::Unknown,
                Role::Boot,
                false,
                RoleKnowledge::Absent,
                RoleKnowledge::Unknown,
            ),
            (
                RoleKnowledge::Unknown,
                RoleKnowledge::Unknown,
                Role::Boot,
                true,
                RoleKnowledge::Present,
                RoleKnowledge::Unknown,
            ),
            (
                RoleKnowledge::Unknown,
                RoleKnowledge::Unknown,
                Role::Output,
                false,
                RoleKnowledge::Unknown,
                RoleKnowledge::Absent,
            ),
            (
                RoleKnowledge::Unknown,
                RoleKnowledge::Unknown,
                Role::Output,
                true,
                RoleKnowledge::Unknown,
                RoleKnowledge::Present,
            ),
            (
                RoleKnowledge::Unknown,
                RoleKnowledge::Present,
                Role::Boot,
                false,
                RoleKnowledge::Absent,
                RoleKnowledge::Present,
            ),
            (
                RoleKnowledge::Unknown,
                RoleKnowledge::Present,
                Role::Boot,
                true,
                RoleKnowledge::Present,
                RoleKnowledge::Present,
            ),
            (
                RoleKnowledge::Unknown,
                RoleKnowledge::Present,
                Role::Output,
                false,
                RoleKnowledge::Unknown,
                RoleKnowledge::Absent,
            ),
            (
                RoleKnowledge::Unknown,
                RoleKnowledge::Present,
                Role::Output,
                true,
                RoleKnowledge::Unknown,
                RoleKnowledge::Present,
            ),
            (
                RoleKnowledge::Unknown,
                RoleKnowledge::Absent,
                Role::Boot,
                false,
                RoleKnowledge::Absent,
                RoleKnowledge::Absent,
            ),
            (
                RoleKnowledge::Unknown,
                RoleKnowledge::Absent,
                Role::Boot,
                true,
                RoleKnowledge::Present,
                RoleKnowledge::Absent,
            ),
            (
                RoleKnowledge::Unknown,
                RoleKnowledge::Absent,
                Role::Output,
                false,
                RoleKnowledge::Unknown,
                RoleKnowledge::Absent,
            ),
            (
                RoleKnowledge::Unknown,
                RoleKnowledge::Absent,
                Role::Output,
                true,
                RoleKnowledge::Unknown,
                RoleKnowledge::Present,
            ),
            (
                RoleKnowledge::Present,
                RoleKnowledge::Unknown,
                Role::Boot,
                false,
                RoleKnowledge::Absent,
                RoleKnowledge::Unknown,
            ),
            (
                RoleKnowledge::Present,
                RoleKnowledge::Unknown,
                Role::Boot,
                true,
                RoleKnowledge::Present,
                RoleKnowledge::Unknown,
            ),
            (
                RoleKnowledge::Present,
                RoleKnowledge::Unknown,
                Role::Output,
                false,
                RoleKnowledge::Present,
                RoleKnowledge::Absent,
            ),
            (
                RoleKnowledge::Present,
                RoleKnowledge::Unknown,
                Role::Output,
                true,
                RoleKnowledge::Present,
                RoleKnowledge::Present,
            ),
            (
                RoleKnowledge::Present,
                RoleKnowledge::Present,
                Role::Boot,
                false,
                RoleKnowledge::Absent,
                RoleKnowledge::Present,
            ),
            (
                RoleKnowledge::Present,
                RoleKnowledge::Present,
                Role::Boot,
                true,
                RoleKnowledge::Present,
                RoleKnowledge::Present,
            ),
            (
                RoleKnowledge::Present,
                RoleKnowledge::Present,
                Role::Output,
                false,
                RoleKnowledge::Present,
                RoleKnowledge::Absent,
            ),
            (
                RoleKnowledge::Present,
                RoleKnowledge::Present,
                Role::Output,
                true,
                RoleKnowledge::Present,
                RoleKnowledge::Present,
            ),
            (
                RoleKnowledge::Present,
                RoleKnowledge::Absent,
                Role::Boot,
                false,
                RoleKnowledge::Absent,
                RoleKnowledge::Absent,
            ),
            (
                RoleKnowledge::Present,
                RoleKnowledge::Absent,
                Role::Boot,
                true,
                RoleKnowledge::Present,
                RoleKnowledge::Absent,
            ),
            (
                RoleKnowledge::Present,
                RoleKnowledge::Absent,
                Role::Output,
                false,
                RoleKnowledge::Present,
                RoleKnowledge::Absent,
            ),
            (
                RoleKnowledge::Present,
                RoleKnowledge::Absent,
                Role::Output,
                true,
                RoleKnowledge::Present,
                RoleKnowledge::Present,
            ),
            (
                RoleKnowledge::Absent,
                RoleKnowledge::Unknown,
                Role::Boot,
                false,
                RoleKnowledge::Absent,
                RoleKnowledge::Unknown,
            ),
            (
                RoleKnowledge::Absent,
                RoleKnowledge::Unknown,
                Role::Boot,
                true,
                RoleKnowledge::Present,
                RoleKnowledge::Unknown,
            ),
            (
                RoleKnowledge::Absent,
                RoleKnowledge::Unknown,
                Role::Output,
                false,
                RoleKnowledge::Absent,
                RoleKnowledge::Absent,
            ),
            (
                RoleKnowledge::Absent,
                RoleKnowledge::Unknown,
                Role::Output,
                true,
                RoleKnowledge::Absent,
                RoleKnowledge::Present,
            ),
            (
                RoleKnowledge::Absent,
                RoleKnowledge::Present,
                Role::Boot,
                false,
                RoleKnowledge::Absent,
                RoleKnowledge::Present,
            ),
            (
                RoleKnowledge::Absent,
                RoleKnowledge::Present,
                Role::Boot,
                true,
                RoleKnowledge::Present,
                RoleKnowledge::Present,
            ),
            (
                RoleKnowledge::Absent,
                RoleKnowledge::Present,
                Role::Output,
                false,
                RoleKnowledge::Absent,
                RoleKnowledge::Absent,
            ),
            (
                RoleKnowledge::Absent,
                RoleKnowledge::Present,
                Role::Output,
                true,
                RoleKnowledge::Absent,
                RoleKnowledge::Present,
            ),
            (
                RoleKnowledge::Absent,
                RoleKnowledge::Absent,
                Role::Boot,
                false,
                RoleKnowledge::Absent,
                RoleKnowledge::Absent,
            ),
            (
                RoleKnowledge::Absent,
                RoleKnowledge::Absent,
                Role::Boot,
                true,
                RoleKnowledge::Present,
                RoleKnowledge::Absent,
            ),
            (
                RoleKnowledge::Absent,
                RoleKnowledge::Absent,
                Role::Output,
                false,
                RoleKnowledge::Absent,
                RoleKnowledge::Absent,
            ),
            (
                RoleKnowledge::Absent,
                RoleKnowledge::Absent,
                Role::Output,
                true,
                RoleKnowledge::Absent,
                RoleKnowledge::Present,
            ),
        ];
        assert_eq!(rows.len(), 36);
        for (boot, output, claimed, target, after_boot, after_output) in rows {
            assert_eq!(
                claim_knowledge(ClaimFacts {
                    boot,
                    output,
                    claimed,
                    target
                }),
                KnowledgeFacts {
                    boot: after_boot,
                    output: after_output
                },
                "{boot:?}/{output:?} claimed {claimed:?} target {target}"
            );
        }
    }

    /// Only the three spellings parse, so an empty or invented mask cannot be
    /// represented.
    #[test]
    fn role_masks_parse_only_the_three_spellings() {
        for (stored, mask) in [
            ("boot", RoleMask::BOOT),
            ("output", RoleMask::OUTPUT),
            ("boot-and-output", RoleMask::BOOT_AND_OUTPUT),
        ] {
            assert_eq!(RoleMask::parse(stored), Ok(mask));
            assert_eq!(mask.as_str(), stored);
            assert!(!mask.is_empty());
        }
        for damage in ["", "Boot", "boot+output", "both", "boot,output"] {
            assert!(RoleMask::parse(damage).is_err(), "{damage:?}");
        }
        assert!(RoleMask::EMPTY.is_empty());
        assert!(HeldRoles::new(RoleMask::EMPTY).is_none());
        assert!(ResolvedRoles::new(RoleMask::EMPTY).is_none());
    }

    /// Exhaustion is a distinct outcome: no wrap, no saturation, no reset.
    #[test]
    fn checked_next_sequence_exhausts_without_wrapping() {
        for current in [0, 1, 41, u64::MAX - 1] {
            let r = checked_next_sequence(current);
            assert!(r.reserved);
            assert_eq!(r.next, current + 1);
            assert!(r.next > current);
        }
        let r = checked_next_sequence(u64::MAX);
        assert!(!r.reserved);
        assert_eq!(r.next, 0);
    }
}
