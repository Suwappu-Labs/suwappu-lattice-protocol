"""End-to-end DKG ceremony tests (Spec C3b)."""

from __future__ import annotations

import pytest

from src.ltp.zk.ec_backend import bls12_381_available
from src.ltp.execution.committee.dkg.types import (
    DKGPhase,
    DKGSessionConfig,
    DKGState,
)

pytestmark = pytest.mark.skipif(
    not bls12_381_available(), reason="py_ecc not installed"
)

from src.ltp.execution.committee.dkg.session import DKGSession  # noqa: E402
from src.ltp.execution.committee.dkg.transport import FakeDKGTransport  # noqa: E402
from src.ltp.execution.committee.dkg.registry import DKGKeyRegistry  # noqa: E402


PARTICIPANTS = [bytes([i]) * 32 for i in range(1, 6)]  # 5 participants


def _run_ceremony(
    participants: list[bytes],
    threshold: int,
    tamper_dealer: bytes | None = None,
) -> list:
    """Run a complete DKG ceremony and return results from all participants.

    If tamper_dealer is set, that dealer's shares are corrupted.
    """
    n = len(participants)
    cfg = DKGSessionConfig(
        vm_tag=0x01, epoch=1, threshold=threshold,
        participants=list(participants), timeout_rounds=20, start_round=0,
    )
    sessions = [
        DKGSession(cfg, fp, idx + 1)
        for idx, fp in enumerate(participants)
    ]
    transport = FakeDKGTransport()

    # Phase 1: begin
    all_shares = {}
    for s in sessions:
        commitment, shares = s.begin()
        transport.broadcast_commitment(commitment)
        for recipient_fp, share in shares.items():
            if tamper_dealer == s.my_fp:
                # Corrupt the share
                from src.ltp.execution.committee.dkg.types import DKGShare
                share = DKGShare(
                    dealer_fp=share.dealer_fp,
                    recipient_fp=share.recipient_fp,
                    share=share.share + 1,  # tamper
                    blinding_share=share.blinding_share,
                )
            transport.send_share(recipient_fp, share)

    # Phase 2: distribute commitments
    commitments = transport.receive_commitments()
    for s in sessions:
        for c in commitments:
            if c.dealer_fp != s.my_fp:
                s.receive_commitment(c)
        s.end_commitment_phase()

    # Phase 3: distribute shares and verify
    all_complaints = []
    for s in sessions:
        my_shares = transport.receive_shares(s.my_fp)
        for share in my_shares:
            s.receive_share(share)
        complaints = s.end_sharing_phase()
        for c in complaints:
            transport.broadcast_complaint(c)
        all_complaints.extend(complaints)

    # Phase 4: distribute complaints and finalize
    all_received_complaints = transport.receive_complaints()
    results = []
    for s in sessions:
        for c in all_received_complaints:
            if c.complainant_fp != s.my_fp:
                s.receive_complaint(c)
        result = s.finalize()
        results.append(result)

    return results


class TestHappyPathCeremony:

    def test_3_of_3(self):
        results = _run_ceremony(PARTICIPANTS[:3], threshold=3)
        group_pks = {r.group_pk for r in results}
        assert len(group_pks) == 1  # all agree
        assert results[0].threshold == 3
        assert len(results[0].qual_set) == 3

    def test_2_of_5(self):
        results = _run_ceremony(PARTICIPANTS, threshold=2)
        group_pks = {r.group_pk for r in results}
        assert len(group_pks) == 1
        assert results[0].threshold == 2
        assert len(results[0].qual_set) == 5

    def test_3_of_5(self):
        results = _run_ceremony(PARTICIPANTS, threshold=3)
        group_pks = {r.group_pk for r in results}
        assert len(group_pks) == 1


class TestComplaintResolution:

    def test_dishonest_dealer_excluded_from_qual(self):
        """One dealer sends bad shares -> excluded from QUAL, ceremony succeeds."""
        tamper_fp = PARTICIPANTS[0]
        results = _run_ceremony(PARTICIPANTS[:4], threshold=2, tamper_dealer=tamper_fp)
        for r in results:
            assert tamper_fp not in r.qual_set
            assert len(r.qual_set) == 3

    def test_too_many_dishonest_dealers_fails(self):
        """If too many dealers are excluded, QUAL < threshold -> ceremony fails."""
        with pytest.raises(ValueError, match="QUAL set too small"):
            _run_ceremony(PARTICIPANTS[:2], threshold=2, tamper_dealer=PARTICIPANTS[0])


class TestRegistryIntegration:

    def test_store_ceremony_result(self):
        results = _run_ceremony(PARTICIPANTS[:3], threshold=2)
        reg = DKGKeyRegistry(0x01)
        reg.store(results[0])
        assert reg.has_epoch(1)
        assert reg.group_pk(1) == results[0].group_pk

    def test_multiple_epochs(self):
        reg = DKGKeyRegistry(0x01)
        for epoch in range(1, 4):
            cfg = DKGSessionConfig(
                vm_tag=0x01, epoch=epoch, threshold=2,
                participants=list(PARTICIPANTS[:3]),
                timeout_rounds=20, start_round=0,
            )
            sessions = [
                DKGSession(cfg, fp, idx + 1)
                for idx, fp in enumerate(PARTICIPANTS[:3])
            ]
            # Quick ceremony
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
                fp = PARTICIPANTS[i]
                for j, shares in enumerate(all_shares):
                    if fp in shares:
                        s.receive_share(shares[fp])
                s.end_sharing_phase()
            result = sessions[0].finalize()
            reg.store(result)

        assert reg.epoch_count() == 3
        assert reg.current().epoch == 3
