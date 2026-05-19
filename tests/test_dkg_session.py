"""Tests for DKG session state machine (Spec C3b §5)."""

from __future__ import annotations

import pytest

from src.ltp.execution.committee.dkg.types import (
    DKGPhase,
    DKGSessionConfig,
    DKGState,
)
from src.ltp.zk.ec_backend import bls12_381_available

pytestmark = pytest.mark.skipif(not bls12_381_available(), reason="py_ecc not installed")

from src.ltp.execution.committee.dkg.session import DKGSession  # noqa: E402
from src.ltp.execution.committee.dkg.vss import PedersenVSS  # noqa: E402

FP_1 = b"\x01" * 32
FP_2 = b"\x02" * 32
FP_3 = b"\x03" * 32
PARTICIPANTS = [FP_1, FP_2, FP_3]


def _make_config(threshold: int = 2, start_round: int = 0) -> DKGSessionConfig:
    return DKGSessionConfig(
        vm_tag=0x01,
        epoch=1,
        threshold=threshold,
        participants=list(PARTICIPANTS),
        timeout_rounds=10,
        start_round=start_round,
    )


class TestDKGSessionInit:
    def test_initial_state_is_idle(self):
        cfg = _make_config()
        s = DKGSession(cfg, FP_1, 1)
        assert s.state is DKGState.IDLE


class TestDKGSessionBegin:
    def test_transitions_to_committing(self):
        s = DKGSession(_make_config(), FP_1, 1)
        commitment, shares = s.begin()
        assert s.state is DKGState.COMMITTING
        assert commitment.dealer_fp == FP_1
        assert len(commitment.feldman_commitments) == 2  # threshold=2, degree=1
        assert len(commitment.pedersen_commitments) == 2
        assert FP_2 in shares
        assert FP_3 in shares
        assert FP_1 not in shares

    def test_begin_twice_raises(self):
        s = DKGSession(_make_config(), FP_1, 1)
        s.begin()
        with pytest.raises(ValueError, match="not IDLE"):
            s.begin()


class TestDKGSessionCommitmentPhase:
    def test_receive_and_end_commitment(self):
        cfg = _make_config()
        s1 = DKGSession(cfg, FP_1, 1)
        s2 = DKGSession(cfg, FP_2, 2)
        c1, _ = s1.begin()
        c2, _ = s2.begin()
        s1.receive_commitment(c2)
        s1.end_commitment_phase()
        assert s1.state is DKGState.SHARING


class TestDKGSessionSharingPhase:
    def test_receive_shares_and_verify(self):
        cfg = _make_config()
        s1 = DKGSession(cfg, FP_1, 1)
        s2 = DKGSession(cfg, FP_2, 2)
        s3 = DKGSession(cfg, FP_3, 3)

        c1, shares_1 = s1.begin()
        c2, shares_2 = s2.begin()
        c3, shares_3 = s3.begin()

        s1.receive_commitment(c2)
        s1.receive_commitment(c3)
        s1.end_commitment_phase()

        s1.receive_share(shares_2[FP_1])
        s1.receive_share(shares_3[FP_1])
        complaints = s1.end_sharing_phase()
        assert complaints == []
        assert s1.state is DKGState.COMPLAINING


class TestDKGSessionFinalize:
    def test_happy_path_finalize(self):
        """3 participants, threshold=2, no complaints -> COMPLETED."""
        cfg = _make_config()
        sessions = [
            DKGSession(cfg, FP_1, 1),
            DKGSession(cfg, FP_2, 2),
            DKGSession(cfg, FP_3, 3),
        ]

        commitments = []
        all_shares = []
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
            for j, shares in enumerate(all_shares):
                fp = PARTICIPANTS[i]
                if fp in shares:
                    s.receive_share(shares[fp])
            complaints = s.end_sharing_phase()
            assert complaints == []

        results = []
        for s in sessions:
            result, signing_key = s.finalize()
            results.append(result)
            assert s.state is DKGState.COMPLETED
            assert signing_key.secret_share > 0
            assert signing_key.participant_fp == s.my_fp

        # All participants agree on the group public key
        assert results[0].group_pk == results[1].group_pk == results[2].group_pk
        assert len(results[0].group_pk) == 96
        assert results[0].threshold == 2
        assert len(results[0].qual_set) == 3


class TestDKGSessionAbort:
    def test_abort_from_any_state(self):
        s = DKGSession(_make_config(), FP_1, 1)
        s.abort("test reason")
        assert s.state is DKGState.FAILED

    def test_abort_during_committing(self):
        s = DKGSession(_make_config(), FP_1, 1)
        s.begin()
        s.abort("network failure")
        assert s.state is DKGState.FAILED


class TestDKGSessionTimeout:
    def test_timeout_triggers_failure(self):
        cfg = _make_config(start_round=100)
        s = DKGSession(cfg, FP_1, 1)
        s.begin()
        assert s.check_timeout(105) is False
        assert s.check_timeout(110) is True
        assert s.state is DKGState.FAILED

    def test_no_timeout_before_deadline(self):
        cfg = _make_config(start_round=0)
        s = DKGSession(cfg, FP_1, 1)
        s.begin()
        assert s.check_timeout(9) is False
        assert s.state is DKGState.COMMITTING
