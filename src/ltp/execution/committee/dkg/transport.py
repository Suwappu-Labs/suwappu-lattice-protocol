"""DKG transport protocol (Spec C3b §6)."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .types import DKGCommitment, DKGComplaint, DKGShare

__all__ = ["DKGTransport", "FakeDKGTransport"]


@runtime_checkable
class DKGTransport(Protocol):
    """Abstract transport for DKG ceremony messages."""

    def broadcast_commitment(self, commitment: DKGCommitment) -> None: ...
    def broadcast_complaint(self, complaint: DKGComplaint) -> None: ...
    def send_share(self, recipient_fp: bytes, share: DKGShare) -> None: ...
    def receive_commitments(self) -> list[DKGCommitment]: ...
    def receive_shares(self, my_fp: bytes) -> list[DKGShare]: ...
    def receive_complaints(self) -> list[DKGComplaint]: ...


class FakeDKGTransport:
    """In-memory DKG transport for testing. All participants share one instance."""

    def __init__(self) -> None:
        self._commitments: list[DKGCommitment] = []
        self._complaints: list[DKGComplaint] = []
        self._shares: dict[bytes, list[DKGShare]] = {}

    def broadcast_commitment(self, commitment: DKGCommitment) -> None:
        self._commitments.append(commitment)

    def broadcast_complaint(self, complaint: DKGComplaint) -> None:
        self._complaints.append(complaint)

    def send_share(self, recipient_fp: bytes, share: DKGShare) -> None:
        self._shares.setdefault(recipient_fp, []).append(share)

    def receive_commitments(self) -> list[DKGCommitment]:
        return list(self._commitments)

    def receive_shares(self, my_fp: bytes) -> list[DKGShare]:
        return list(self._shares.get(my_fp, []))

    def receive_complaints(self) -> list[DKGComplaint]:
        return list(self._complaints)
