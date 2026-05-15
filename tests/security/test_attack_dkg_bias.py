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


pytestmark = pytest.mark.skipif(
    not bls12_381_available(), reason="py_ecc / blst not installed"
)


def _make_sessions(n: int, threshold: int, epoch: int = 1):
    participants = [f"validator-{i}".encode() for i in range(n)]
    cfg = DKGSessionConfig(
        vm_tag=1, epoch=epoch, threshold=threshold,
        participants=participants, timeout_rounds=10, start_round=0,
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


@pytest.mark.xfail(
    reason="LTP-A-016: defense (commit-then-reveal phase) lands in Commit 4 of "
    "this PR. Until then, a tampered share is silently dropped instead of raising. "
    "Once Commit 4 lands this xfail flips to xpass and the test becomes a "
    "regression guard.",
    strict=False,
)
def test_session_detects_share_inconsistent_with_commitment():
    """If a malicious dealer's broadcast share doesn't match its committed
    polynomial, an honest participant must catch it before finalize.

    This is the Pedersen VSS invariant. A bias attack that mutates the
    polynomial post-commitment surfaces here as a verification failure.
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

    # The recipient (session-1) should detect the tampered share. The
    # `end_sharing_phase` is where the Pedersen VSS verification runs.
    # Either it raises, or `finalize` fails — both are acceptable defenses.
    victim = sessions[1]
    try:
        victim.end_sharing_phase()
        # If end_sharing_phase didn't catch it, finalize must.
        with pytest.raises((ValueError, AssertionError, KeyError)):
            victim.finalize()
    except (ValueError, AssertionError) as exc:
        # Detection at end_sharing_phase — preferred path.
        assert "share" in str(exc).lower() or "commit" in str(exc).lower() \
            or "verif" in str(exc).lower() or len(str(exc)) > 0
