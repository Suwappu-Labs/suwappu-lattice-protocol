"""Tests for threshold BLS signing types and protocol (Spec C3c)."""

from __future__ import annotations

import pytest

from src.ltp.zk.ec_backend import bls12_381_available
from src.ltp.execution.committee.dkg.types import DKGPhase, DKGResult


class TestDKGResultSecretShare:

    def test_default_secret_share_is_none(self):
        r = DKGResult(
            vm_tag=0x01,
            epoch=1,
            group_pk=b"\xaa" * 48,
            participant_vks={b"\x01" * 32: b"\xbb" * 48},
            threshold=2,
            qual_set=frozenset([b"\x01" * 32]),
            phase=DKGPhase.EAGER,
        )
        assert r.my_secret_share is None

    def test_secret_share_can_be_set(self):
        r = DKGResult(
            vm_tag=0x01,
            epoch=1,
            group_pk=b"\xaa" * 48,
            participant_vks={b"\x01" * 32: b"\xbb" * 48},
            threshold=2,
            qual_set=frozenset([b"\x01" * 32]),
            phase=DKGPhase.EAGER,
            my_secret_share=12345,
        )
        assert r.my_secret_share == 12345

    def test_secret_share_frozen(self):
        r = DKGResult(
            vm_tag=0x01,
            epoch=1,
            group_pk=b"\xaa" * 48,
            participant_vks={},
            threshold=2,
            qual_set=frozenset(),
            phase=DKGPhase.EAGER,
            my_secret_share=42,
        )
        with pytest.raises(AttributeError):
            r.my_secret_share = 99


pytestmark_g2 = pytest.mark.skipif(
    not bls12_381_available(), reason="py_ecc not installed"
)


@pytestmark_g2
class TestThresholdSigningKeyType:

    def test_frozen(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            ThresholdSigningKey,
        )
        key = ThresholdSigningKey(
            participant_fp=b"\x01" * 32,
            participant_index=1,
            secret_share=42,
            group_pk=b"\xaa" * 96,
            threshold=2,
            epoch=1,
            vm_tag=0x01,
        )
        with pytest.raises(AttributeError):
            key.secret_share = 99

    def test_fields(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            ThresholdSigningKey,
        )
        key = ThresholdSigningKey(
            participant_fp=b"\x01" * 32,
            participant_index=3,
            secret_share=777,
            group_pk=b"\xbb" * 96,
            threshold=2,
            epoch=5,
            vm_tag=0x02,
        )
        assert key.participant_fp == b"\x01" * 32
        assert key.participant_index == 3
        assert key.secret_share == 777
        assert len(key.group_pk) == 96
        assert key.threshold == 2
        assert key.epoch == 5
        assert key.vm_tag == 0x02


@pytestmark_g2
class TestPartialSignatureType:

    def test_frozen(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            PartialSignature,
        )
        sig = PartialSignature(
            signer_fp=b"\x01" * 32,
            signer_index=1,
            signature=b"\xcc" * 96,
            epoch=1,
        )
        with pytest.raises(AttributeError):
            sig.epoch = 99

    def test_fields(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            PartialSignature,
        )
        sig = PartialSignature(
            signer_fp=b"\x02" * 32,
            signer_index=2,
            signature=b"\xdd" * 96,
            epoch=3,
        )
        assert sig.signer_fp == b"\x02" * 32
        assert sig.signer_index == 2
        assert len(sig.signature) == 96
        assert sig.epoch == 3


# ---------------------------------------------------------------------------
# Signing protocol tests (require a real DKG ceremony for keys)
# ---------------------------------------------------------------------------


def _run_dkg_and_get_keys(
    n: int = 3, threshold: int = 2,
) -> tuple:
    """Run a DKG ceremony and return (group_pk, list[ThresholdSigningKey])."""
    from src.ltp.execution.committee.dkg.session import DKGSession
    from src.ltp.execution.committee.dkg.types import DKGSessionConfig
    from src.ltp.execution.committee.dkg.threshold_signing import (
        ThresholdSigningKey,
    )

    participants = [bytes([i]) * 32 for i in range(1, n + 1)]
    cfg = DKGSessionConfig(
        vm_tag=0x01, epoch=1, threshold=threshold,
        participants=participants, timeout_rounds=20, start_round=0,
    )
    sessions = [DKGSession(cfg, fp, idx + 1) for idx, fp in enumerate(participants)]

    # Phase 1: begin
    commitments = []
    all_shares = []
    for s in sessions:
        c, shares = s.begin()
        commitments.append(c)
        all_shares.append(shares)

    # Phase 2: commitments
    for s in sessions:
        for c in commitments:
            if c.dealer_fp != s.my_fp:
                s.receive_commitment(c)
        s.end_commitment_phase()

    # Phase 3: shares
    for i, s in enumerate(sessions):
        fp = participants[i]
        for shares in all_shares:
            if fp in shares:
                s.receive_share(shares[fp])
        s.end_sharing_phase()

    # Phase 4: finalize — get results and signing keys
    signing_keys = []
    group_pk = None
    for s in sessions:
        result, key = s.finalize()
        signing_keys.append(key)
        if group_pk is None:
            group_pk = result.group_pk

    return group_pk, signing_keys


@pytestmark_g2
class TestPartialSign:

    def test_produces_96_byte_signature(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            partial_sign, DOMAIN_ATTESTATION,
        )
        _, keys = _run_dkg_and_get_keys()
        sig = partial_sign(keys[0], b"hello", DOMAIN_ATTESTATION)
        assert len(sig.signature) == 96

    def test_deterministic(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            partial_sign, DOMAIN_ATTESTATION,
        )
        _, keys = _run_dkg_and_get_keys()
        sig1 = partial_sign(keys[0], b"hello", DOMAIN_ATTESTATION)
        sig2 = partial_sign(keys[0], b"hello", DOMAIN_ATTESTATION)
        assert sig1.signature == sig2.signature

    def test_different_message_different_sig(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            partial_sign, DOMAIN_ATTESTATION,
        )
        _, keys = _run_dkg_and_get_keys()
        sig1 = partial_sign(keys[0], b"hello", DOMAIN_ATTESTATION)
        sig2 = partial_sign(keys[0], b"world", DOMAIN_ATTESTATION)
        assert sig1.signature != sig2.signature

    def test_different_domain_different_sig(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            partial_sign, DOMAIN_ATTESTATION, DOMAIN_STATE_ROOT,
        )
        _, keys = _run_dkg_and_get_keys()
        sig1 = partial_sign(keys[0], b"hello", DOMAIN_ATTESTATION)
        sig2 = partial_sign(keys[0], b"hello", DOMAIN_STATE_ROOT)
        assert sig1.signature != sig2.signature

    def test_signer_metadata(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            partial_sign, DOMAIN_ATTESTATION,
        )
        _, keys = _run_dkg_and_get_keys()
        sig = partial_sign(keys[0], b"hello", DOMAIN_ATTESTATION)
        assert sig.signer_fp == keys[0].participant_fp
        assert sig.signer_index == keys[0].participant_index
        assert sig.epoch == keys[0].epoch


@pytestmark_g2
class TestCombineAndVerify:

    def test_combine_with_threshold_partials(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            partial_sign, combine_partial_signatures, threshold_verify,
            DOMAIN_ATTESTATION,
        )
        group_pk, keys = _run_dkg_and_get_keys(n=3, threshold=2)
        msg = b"test attestation"
        partials = [partial_sign(k, msg, DOMAIN_ATTESTATION) for k in keys[:2]]
        combined = combine_partial_signatures(partials, threshold=2)
        assert len(combined) == 96
        assert threshold_verify(group_pk, msg, combined, DOMAIN_ATTESTATION)

    def test_combine_with_all_partials(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            partial_sign, combine_partial_signatures, threshold_verify,
            DOMAIN_ATTESTATION,
        )
        group_pk, keys = _run_dkg_and_get_keys(n=3, threshold=2)
        msg = b"test attestation"
        partials = [partial_sign(k, msg, DOMAIN_ATTESTATION) for k in keys]
        combined = combine_partial_signatures(partials, threshold=2)
        assert threshold_verify(group_pk, msg, combined, DOMAIN_ATTESTATION)

    def test_insufficient_partials_raises(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            partial_sign, combine_partial_signatures, DOMAIN_ATTESTATION,
        )
        _, keys = _run_dkg_and_get_keys(n=3, threshold=2)
        partials = [partial_sign(keys[0], b"msg", DOMAIN_ATTESTATION)]
        with pytest.raises(ValueError, match="Need at least 2"):
            combine_partial_signatures(partials, threshold=2)

    def test_rejects_tampered_message(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            partial_sign, combine_partial_signatures, threshold_verify,
            DOMAIN_ATTESTATION,
        )
        group_pk, keys = _run_dkg_and_get_keys(n=3, threshold=2)
        partials = [partial_sign(k, b"real msg", DOMAIN_ATTESTATION) for k in keys[:2]]
        combined = combine_partial_signatures(partials, threshold=2)
        assert not threshold_verify(group_pk, b"fake msg", combined, DOMAIN_ATTESTATION)

    def test_rejects_wrong_domain(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            partial_sign, combine_partial_signatures, threshold_verify,
            DOMAIN_ATTESTATION, DOMAIN_STATE_ROOT,
        )
        group_pk, keys = _run_dkg_and_get_keys(n=3, threshold=2)
        partials = [partial_sign(k, b"msg", DOMAIN_ATTESTATION) for k in keys[:2]]
        combined = combine_partial_signatures(partials, threshold=2)
        assert not threshold_verify(group_pk, b"msg", combined, DOMAIN_STATE_ROOT)

    def test_different_subsets_produce_same_signature(self):
        """Key property: any t-subset gives the same combined sig."""
        from src.ltp.execution.committee.dkg.threshold_signing import (
            partial_sign, combine_partial_signatures, DOMAIN_ATTESTATION,
        )
        _, keys = _run_dkg_and_get_keys(n=4, threshold=2)
        msg = b"deterministic"
        # Subset {0, 1}
        p_01 = [partial_sign(keys[0], msg, DOMAIN_ATTESTATION),
                partial_sign(keys[1], msg, DOMAIN_ATTESTATION)]
        sig_01 = combine_partial_signatures(p_01, threshold=2)
        # Subset {2, 3}
        p_23 = [partial_sign(keys[2], msg, DOMAIN_ATTESTATION),
                partial_sign(keys[3], msg, DOMAIN_ATTESTATION)]
        sig_23 = combine_partial_signatures(p_23, threshold=2)
        assert sig_01 == sig_23
