"""End-to-end threshold signing tests: DKG -> sign -> verify (Spec C3c)."""

from __future__ import annotations

import pytest

from src.ltp.execution.committee.dkg.types import DKGSessionConfig
from src.ltp.zk.ec_backend import bls12_381_available

pytestmark = pytest.mark.skipif(not bls12_381_available(), reason="py_ecc not installed")

from src.ltp.execution.committee.dkg.session import DKGSession  # noqa: E402
from src.ltp.execution.committee.dkg.threshold_signing import (  # noqa: E402
    DOMAIN_ATTESTATION,
    DOMAIN_STATE_ROOT,
    ThresholdSigningKey,
    combine_partial_signatures,
    partial_sign,
    threshold_verify,
)

PARTICIPANTS = [bytes([i]) * 32 for i in range(1, 6)]


def _full_ceremony(
    participants: list[bytes],
    threshold: int,
    epoch: int = 1,
) -> tuple[bytes, list[ThresholdSigningKey]]:
    """Run full DKG and return (group_pk, signing_keys)."""
    cfg = DKGSessionConfig(
        vm_tag=0x01,
        epoch=epoch,
        threshold=threshold,
        participants=list(participants),
        timeout_rounds=20,
        start_round=0,
    )
    sessions = [DKGSession(cfg, fp, idx + 1) for idx, fp in enumerate(participants)]

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
        fp = participants[i]
        for shares in all_shares:
            if fp in shares:
                s.receive_share(shares[fp])
        s.end_sharing_phase()

    signing_keys = []
    group_pk = None
    for s in sessions:
        result, key = s.finalize()
        signing_keys.append(key)
        if group_pk is None:
            group_pk = result.group_pk

    return group_pk, signing_keys


class TestFullCeremonyToSignature:
    def test_2_of_3_sign_and_verify(self):
        group_pk, keys = _full_ceremony(PARTICIPANTS[:3], threshold=2)
        msg = b"attestation payload"
        partials = [partial_sign(k, msg, DOMAIN_ATTESTATION) for k in keys[:2]]
        sig = combine_partial_signatures(partials, threshold=2)
        assert threshold_verify(group_pk, msg, sig, DOMAIN_ATTESTATION)

    def test_3_of_5_sign_and_verify(self):
        group_pk, keys = _full_ceremony(PARTICIPANTS, threshold=3)
        msg = b"state root hash"
        partials = [partial_sign(k, msg, DOMAIN_STATE_ROOT) for k in keys[:3]]
        sig = combine_partial_signatures(partials, threshold=3)
        assert threshold_verify(group_pk, msg, sig, DOMAIN_STATE_ROOT)

    def test_5_of_5_sign_and_verify(self):
        group_pk, keys = _full_ceremony(PARTICIPANTS, threshold=5)
        msg = b"unanimous"
        partials = [partial_sign(k, msg, DOMAIN_ATTESTATION) for k in keys]
        sig = combine_partial_signatures(partials, threshold=5)
        assert threshold_verify(group_pk, msg, sig, DOMAIN_ATTESTATION)


class TestSubsetIndependence:
    def test_any_2_of_4_produces_same_signature(self):
        """All t-subsets produce the same combined signature."""
        group_pk, keys = _full_ceremony(PARTICIPANTS[:4], threshold=2)
        msg = b"subset test"
        from itertools import combinations

        sigs = set()
        for subset in combinations(range(4), 2):
            partials = [partial_sign(keys[i], msg, DOMAIN_ATTESTATION) for i in subset]
            sig = combine_partial_signatures(partials, threshold=2)
            sigs.add(sig)
        # All subsets produce the same combined signature
        assert len(sigs) == 1

    def test_any_3_of_5_produces_same_signature(self):
        group_pk, keys = _full_ceremony(PARTICIPANTS, threshold=3)
        msg = b"larger subset test"
        from itertools import combinations

        sigs = set()
        for subset in combinations(range(5), 3):
            partials = [partial_sign(keys[i], msg, DOMAIN_ATTESTATION) for i in subset]
            sig = combine_partial_signatures(partials, threshold=3)
            sigs.add(sig)
        assert len(sigs) == 1


class TestSecurityProperties:
    def test_t_minus_1_partials_fail(self):
        """t-1 partials cannot produce a valid signature."""
        group_pk, keys = _full_ceremony(PARTICIPANTS[:3], threshold=2)
        msg = b"should fail"
        # Only 1 partial for threshold=2
        partials = [partial_sign(keys[0], msg, DOMAIN_ATTESTATION)]
        with pytest.raises(ValueError, match="Need at least 2"):
            combine_partial_signatures(partials, threshold=2)

    def test_wrong_group_rejects(self):
        """Signature from group A doesn't verify against group B's key."""
        group_pk_a, keys_a = _full_ceremony(PARTICIPANTS[:3], threshold=2)
        group_pk_b, keys_b = _full_ceremony(PARTICIPANTS[:3], threshold=2)
        msg = b"cross-group"
        partials = [partial_sign(k, msg, DOMAIN_ATTESTATION) for k in keys_a[:2]]
        sig = combine_partial_signatures(partials, threshold=2)
        # Verify against group B's key — should fail (different random polys)
        assert group_pk_a != group_pk_b  # overwhelmingly likely
        assert not threshold_verify(group_pk_b, msg, sig, DOMAIN_ATTESTATION)


class TestMultipleEpochs:
    def test_different_epochs_different_keys_both_verify(self):
        group_pk_1, keys_1 = _full_ceremony(PARTICIPANTS[:3], threshold=2, epoch=1)
        group_pk_2, keys_2 = _full_ceremony(PARTICIPANTS[:3], threshold=2, epoch=2)
        msg = b"epoch test"
        # Sign with epoch 1 keys
        partials_1 = [partial_sign(k, msg, DOMAIN_ATTESTATION) for k in keys_1[:2]]
        sig_1 = combine_partial_signatures(partials_1, threshold=2)
        # Sign with epoch 2 keys
        partials_2 = [partial_sign(k, msg, DOMAIN_ATTESTATION) for k in keys_2[:2]]
        sig_2 = combine_partial_signatures(partials_2, threshold=2)
        # Each verifies against its own group key
        assert threshold_verify(group_pk_1, msg, sig_1, DOMAIN_ATTESTATION)
        assert threshold_verify(group_pk_2, msg, sig_2, DOMAIN_ATTESTATION)
        # Cross-epoch fails
        assert not threshold_verify(group_pk_1, msg, sig_2, DOMAIN_ATTESTATION)
        assert not threshold_verify(group_pk_2, msg, sig_1, DOMAIN_ATTESTATION)
