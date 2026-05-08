"""Standby member selection strategies (Spec C3a §8)."""

from __future__ import annotations

from typing import Optional

from .types import CommitteeMember, CommitteeRoster
from .policy import CommitteePolicy, StandbyStrategy
from ..writer import IdentityTier

__all__ = ["StandbySelector", "score_member"]

_TIER_WEIGHT: dict[IdentityTier, int] = {
    IdentityTier.MLDSA:     1,
    IdentityTier.BLS:       2,
    IdentityTier.COMPOSITE: 3,
}


def score_member(member: CommitteeMember) -> tuple[int, int]:
    """Deterministic scoring: (tier_weight, -joined_epoch).

    Higher tuple = higher priority. Earlier joined_epoch is better
    (negated so lower epoch yields higher score).
    """
    return (_TIER_WEIGHT.get(member.tier, 0), -member.joined_epoch)


class StandbySelector:
    """Selects which standby member fills a vacancy."""

    def __init__(self, policy: CommitteePolicy) -> None:
        self._policy = policy

    def next(self, roster: CommitteeRoster) -> Optional[CommitteeMember]:
        """Return the next standby to promote, or None if standby is empty."""
        if not roster.standby_members:
            return None

        strategy = self._policy.standby_strategy

        if strategy is StandbyStrategy.PRIORITY_QUEUE:
            ranked = self.rank(roster.standby_members)
            return ranked[0] if ranked else None

        if strategy is StandbyStrategy.FIFO:
            return roster.standby_members[0]

        if strategy is StandbyStrategy.ADMIN_DESIGNATED:
            standby_fps = {m.writer_fp: m for m in roster.standby_members}
            for fp in self._policy.admin_standby_list:
                if fp in standby_fps:
                    return standby_fps[fp]
            return None

        return None

    def rank(self, candidates: list[CommitteeMember]) -> list[CommitteeMember]:
        """Order candidates by score descending."""
        return sorted(candidates, key=score_member, reverse=True)
