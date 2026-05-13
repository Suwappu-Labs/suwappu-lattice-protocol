"""Validator identity mapping and eviction tracking (Spec D1b §2)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..execution.committee.types import CommitteeRoster


@dataclass(frozen=True)
class ValidatorInfo:
    """Identity record for a single validator."""

    writer_fp: bytes
    bls_pk: bytes
    validator_index: int


class ValidatorSet:
    """Maps committee roster identities to engine indices.

    Fixed at epoch creation. Evictions mark validators inactive but never
    change index assignments or quorum threshold.
    """

    def __init__(self, epoch: int, members: list[ValidatorInfo]) -> None:
        self._epoch = epoch
        self._members = list(members)
        n = len(members)
        f = (n - 1) // 3 if n > 0 else 0
        self._quorum_threshold = 2 * f + 1
        self._evicted: set[bytes] = set()
        self._fp_to_index: dict[bytes, int] = {
            m.writer_fp: m.validator_index for m in members
        }
        self._index_to_fp: dict[int, bytes] = {
            m.validator_index: m.writer_fp for m in members
        }
        self._index_to_bls: dict[int, bytes] = {
            m.validator_index: m.bls_pk for m in members
        }

    @classmethod
    def from_roster(cls, roster: CommitteeRoster) -> ValidatorSet:
        """Build a ValidatorSet from a CommitteeRoster."""
        members = [
            ValidatorInfo(
                writer_fp=m.writer_fp,
                bls_pk=m.bls_pk,
                validator_index=i,
            )
            for i, m in enumerate(roster.active_members)
        ]
        return cls(epoch=roster.epoch, members=members)

    @property
    def epoch(self) -> int:
        return self._epoch

    @property
    def members(self) -> list[ValidatorInfo]:
        return list(self._members)

    @property
    def quorum_threshold(self) -> int:
        return self._quorum_threshold

    @property
    def size(self) -> int:
        return len(self._members)

    def index_for(self, writer_fp: bytes) -> int:
        if writer_fp not in self._fp_to_index:
            raise KeyError(f"Unknown writer_fp: {writer_fp!r}")
        return self._fp_to_index[writer_fp]

    def fp_for(self, index: int) -> bytes:
        if index not in self._index_to_fp:
            raise KeyError(f"Unknown index: {index}")
        return self._index_to_fp[index]

    def bls_pk_for(self, index: int) -> bytes:
        if index not in self._index_to_bls:
            raise KeyError(f"Unknown index: {index}")
        return self._index_to_bls[index]

    def evict(self, writer_fp: bytes) -> None:
        if writer_fp not in self._fp_to_index:
            raise KeyError(f"Unknown writer_fp: {writer_fp!r}")
        self._evicted.add(writer_fp)

    def is_active(self, writer_fp: bytes) -> bool:
        return writer_fp in self._fp_to_index and writer_fp not in self._evicted

    def is_evicted(self, writer_fp: bytes) -> bool:
        return writer_fp in self._evicted

    def active_count(self) -> int:
        return len(self._members) - len(self._evicted)

    def evicted_indices(self) -> set[int]:
        return {self._fp_to_index[fp] for fp in self._evicted}
