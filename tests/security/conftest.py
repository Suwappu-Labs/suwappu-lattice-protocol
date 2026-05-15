"""Shared fixtures for the offensive security suite.

Mirrors the canonical 4-validator DKG fixture pattern from
tests/test_consensus_adapter.py and tests/test_threshold_signing_integration.py
so the security tests exercise the same code paths the rest of the suite
does, not test-only shims.
"""

from __future__ import annotations

import pytest

from src.ltp.execution.committee.dkg.session import DKGSession
from src.ltp.execution.committee.dkg.types import DKGSessionConfig
from src.ltp.execution.committee.types import (
    CommitteeMember,
    CommitteeRole,
    CommitteeRoster,
)
from src.ltp.execution.writer import IdentityTier


@pytest.fixture(scope="session")
def four_validator_roster() -> CommitteeRoster:
    members = [
        CommitteeMember(
            writer_fp=f"validator-{i}".encode(),
            bls_pk=bytes([i + 1]) * 48,
            tier=IdentityTier.COMPOSITE,
            joined_epoch=0,
            role=CommitteeRole.ACTIVE,
        )
        for i in range(4)
    ]
    return CommitteeRoster(
        vm_tag=1,
        epoch=1,
        active_members=members,
        standby_members=[],
        formed_at=0,
        formation_round=0,
    )


@pytest.fixture(scope="session")
def dkg_4_of_3():
    """Run a clean 4-node, threshold-3 DKG ceremony once per session.

    Returns ``(signing_keys, group_pk)`` matching the contract used by
    ``CommitteeManager.sign_as_committee``.
    """
    n, threshold, epoch = 4, 3, 1
    participants = [f"validator-{i}".encode() for i in range(n)]
    cfg = DKGSessionConfig(
        vm_tag=1,
        epoch=epoch,
        threshold=threshold,
        participants=participants,
        timeout_rounds=10,
        start_round=0,
    )
    sessions = [DKGSession(cfg, fp, idx + 1) for idx, fp in enumerate(participants)]

    commitments, all_shares = [], []
    for s in sessions:
        c, shares = s.begin()
        commitments.append(c)
        all_shares.append(shares)

    for s in sessions:
        for c in commitments:
            if c.dealer_fp != s.my_fp:
                s.receive_commitment(c)
        s.end_commitment_phase()

    for i, s in enumerate(sessions):
        fp = participants[i]
        for shares in all_shares:
            if fp in shares:
                s.receive_share(shares[fp])
        s.end_sharing_phase()

    signing_keys, group_pk = [], None
    for s in sessions:
        result, key = s.finalize()
        signing_keys.append(key)
        if group_pk is None:
            group_pk = result.group_pk

    return signing_keys, group_pk
