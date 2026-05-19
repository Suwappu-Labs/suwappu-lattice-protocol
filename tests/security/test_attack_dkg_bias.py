"""LTP-A-016 regression: DKG ceremony bias attack.

The classic Gennaro et al. bias attack: a malicious DKG dealer waits to
observe honest dealers' polynomial commitments, then crafts their own
commitment to bias the resulting group public key toward a value useful
to the attacker.

Defense (in place via Pedersen VSS): the commitment-phase outputs are
verifiable. A dealer whose share doesn't match their published commitment
is caught at ``end_sharing_phase``.

Defense (Commit 4 of this PR): an explicit phase-1.5 commit-then-reveal
lock prevents a dealer from adjusting their commitment after observing
others' commitments. This test asserts that a session detects and rejects
a tampered-share scenario, which is the public-output of a bias attempt.
"""

from __future__ import annotations

import pytest

from src.ltp.execution.committee.dkg.session import DKGSession
from src.ltp.execution.committee.dkg.types import DKGSessionConfig
from src.ltp.zk.ec_backend import bls12_381_available

pytestmark = pytest.mark.skipif(not bls12_381_available(), reason="py_ecc / blst not installed")


def _make_sessions(n: int, threshold: int, epoch: int = 1):
    participants = [f"validator-{i}".encode() for i in range(n)]
    cfg = DKGSessionConfig(
        vm_tag=1,
        epoch=epoch,
        threshold=threshold,
        participants=participants,
        timeout_rounds=10,
        start_round=0,
    )
    return [DKGSession(cfg, fp, idx + 1) for idx, fp in enumerate(participants)]


def test_honest_dkg_produces_group_pk():
    """Sanity: honest DKG run completes and yields a usable group PK."""
    sessions = _make_sessions(4, 3)
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
        fp = sessions[i].my_fp
        for shares in all_shares:
            if fp in shares:
                s.receive_share(shares[fp])
        s.end_sharing_phase()
    group_pks = set()
    for s in sessions:
        result, _ = s.finalize()
        group_pks.add(bytes(result.group_pk))
    assert len(group_pks) == 1, "honest DKG must converge on a single group PK"


def test_session_detects_share_inconsistent_with_commitment():
    """LTP-A-016: a malicious dealer's tampered share is detected during
    ``end_sharing_phase`` and surfaces as a non-empty complaint list.

    The defense in place is Pedersen VSS verification: the recipient
    checks the share against the dealer's published commitments. The
    test asserts the complaint surface is non-empty and names the
    malicious dealer correctly.

    Finalize succeeds (with the bad dealer excluded from QUAL) because
    n=4, threshold=3 still has enough honest participants. The test
    therefore asserts (a) the complaint exists and (b) the bad dealer
    is dropped from the final QUAL set rather than its biased
    contribution reaching the group key.
    """
    sessions = _make_sessions(4, 3)
    commitments, all_shares = [], []
    for s in sessions:
        c, shares = s.begin()
        commitments.append(c)
        all_shares.append(shares)

    # Distribute commitments honestly.
    for s in sessions:
        for c in commitments:
            if c.dealer_fp != s.my_fp:
                s.receive_commitment(c)
        s.end_commitment_phase()

    # Honest dealers send their real shares; dealer-0 (the attacker)
    # tampers the scalar value of the share it sends to dealer-1.
    attacker_shares = dict(all_shares[0])
    target_fp = sessions[1].my_fp
    original = attacker_shares[target_fp]
    tampered_share = type(original)(
        dealer_fp=original.dealer_fp,
        recipient_fp=original.recipient_fp,
        share=(original.share + 1) % (2**256),
        blinding_share=original.blinding_share,
    )
    attacker_shares[target_fp] = tampered_share

    # All other dealers send honest shares; dealer-0 sends the tampered one.
    for i, s in enumerate(sessions):
        fp = sessions[i].my_fp
        for j, shares in enumerate(all_shares):
            if fp in shares:
                share = shares[fp] if j != 0 else attacker_shares.get(fp, shares[fp])
                s.receive_share(share)

    # The recipient (session-1) detects the tampered share at
    # ``end_sharing_phase`` and surfaces it as a complaint.
    victim = sessions[1]
    complaints = victim.end_sharing_phase()
    assert complaints, (
        "Pedersen VSS verification missed a tampered share — LTP-A-016 defense regressed"
    )
    assert any(c.dealer_fp == sessions[0].my_fp for c in complaints), (
        "complaint did not name the malicious dealer"
    )

    # Finalize: bad dealer is excluded from QUAL; remaining 3 honest
    # dealers still meet threshold=3.
    result, _ = victim.finalize()
    assert sessions[0].my_fp not in result.qual_set, (
        "tampered dealer remained in the QUAL set — bias attack succeeded"
    )
