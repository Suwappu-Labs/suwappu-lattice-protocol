"""Committee roster formation from eligible writers (Spec C3a §5)."""

from __future__ import annotations

from .types import CommitteeMember, CommitteeRole, CommitteeRoster
from .policy import CommitteePolicy
from .standby import score_member
from ..writer import IdentityTier, WriterRecord, TRANSACTABLE_STATES
from ..writer_registry import WriterRegistry

__all__ = ["CommitteeFormation"]


class CommitteeFormation:
    """Stateless builder — produces a CommitteeRoster from registry state + policy."""

    def __init__(self, registry: WriterRegistry) -> None:
        self._registry = registry

    def build_roster(
        self,
        policy: CommitteePolicy,
        epoch: int,
        round_num: int,
        timestamp: int,
    ) -> CommitteeRoster:
        """Build a complete roster for a new epoch."""
        # 1. Gather all transactable writers
        candidates = self._registry.active_writers()

        # 2. Split into normal-eligible and force-included
        eligible: list[WriterRecord] = []
        force_included: list[WriterRecord] = []

        for record in candidates:
            fp = record.identity.fingerprint
            if record.state not in TRANSACTABLE_STATES:
                continue
            if fp in policy.force_include:
                force_included.append(record)
                continue
            if fp in policy.force_exclude:
                continue
            if not self._passes_filters(record, policy):
                continue
            eligible.append(record)

        # 3. Force-include: must still be transactable (already checked above)
        all_eligible = eligible + force_included

        # 4. Convert to CommitteeMember and score
        members = [self._to_member(r, epoch) for r in all_eligible]
        members.sort(key=score_member, reverse=True)

        # 5. Split into active and standby
        cap = policy.max_committee_size
        if cap > 0:
            active = members[:cap]
            standby_pool = members[cap:]
        else:
            active = members
            standby_pool = []

        # 6. Cap standby
        if policy.max_standby_size > 0:
            standby_pool = standby_pool[:policy.max_standby_size]

        # 7. Set roles
        active_members = [
            CommitteeMember(
                writer_fp=m.writer_fp, bls_pk=m.bls_pk, tier=m.tier,
                joined_epoch=m.joined_epoch, role=CommitteeRole.ACTIVE,
            )
            for m in active
        ]
        standby_members = [
            CommitteeMember(
                writer_fp=m.writer_fp, bls_pk=m.bls_pk, tier=m.tier,
                joined_epoch=m.joined_epoch, role=CommitteeRole.STANDBY,
            )
            for m in standby_pool
        ]

        return CommitteeRoster(
            vm_tag=policy.vm_tag,
            epoch=epoch,
            active_members=active_members,
            standby_members=standby_members,
            formed_at=timestamp,
            formation_round=round_num,
        )

    def _passes_filters(self, record: WriterRecord, policy: CommitteePolicy) -> bool:
        """Apply eligibility filters (BLS key, tier, tenure)."""
        tier = record.identity.tier
        if policy.require_bls_key and tier not in (IdentityTier.BLS, IdentityTier.COMPOSITE):
            return False
        if policy.required_tiers is not None and tier not in policy.required_tiers:
            return False
        if policy.min_epochs_active > 0:
            active_transitions = sum(
                1 for e in record.transition_log if e.to_state.value == "active"
            )
            if active_transitions < policy.min_epochs_active:
                return False
        return True

    def _to_member(self, record: WriterRecord, epoch: int) -> CommitteeMember:
        """Convert a WriterRecord to a CommitteeMember."""
        return CommitteeMember(
            writer_fp=record.identity.fingerprint,
            bls_pk=record.identity.bls_pk or b"",
            tier=record.identity.tier,
            joined_epoch=epoch,
            role=CommitteeRole.ACTIVE,  # placeholder, set properly in build_roster
        )
