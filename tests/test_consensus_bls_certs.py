"""Tests for BLS certificate signing and verification (Spec D1b §3)."""

import pytest

from src.ltp.consensus.bls_certificates import (
    DOMAIN_CONSENSUS_ACK,
    BLSCertificateManager,
    SignedCertificate,
)
from src.ltp.consensus.types import Block, Certificate
from src.ltp.consensus.validator_set import ValidatorInfo, ValidatorSet
from src.ltp.execution.committee.dkg.session import DKGSession
from src.ltp.execution.committee.dkg.threshold_signing import (
    DOMAIN_ATTESTATION,
    combine_partial_signatures,
)
from src.ltp.execution.committee.dkg.types import DKGSessionConfig


def _run_dkg(n: int, threshold: int, epoch: int = 1):
    """Run a mini DKG ceremony. Returns (signing_keys, group_pk)."""
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


@pytest.fixture(scope="module")
def dkg_keys_4():
    """4-validator DKG with threshold 3 (module-scoped for speed)."""
    return _run_dkg(4, 3, epoch=1)


@pytest.fixture(scope="module")
def validator_set_4(dkg_keys_4):
    """ValidatorSet with 4 members matching DKG keys."""
    keys, _ = dkg_keys_4
    members = [
        ValidatorInfo(
            writer_fp=k.participant_fp,
            bls_pk=k.group_pk,
            validator_index=i,
        )
        for i, k in enumerate(keys)
    ]
    return ValidatorSet(epoch=1, members=members)


@pytest.fixture(scope="module")
def sample_block():
    """A sample Block for signing tests."""
    return Block(
        author=0,
        round=5,
        payload=(b"tx1", b"tx2"),
        parents=frozenset(),
        timestamp_ms=1000,
    )


class TestSignAck:
    """BLSCertificateManager.sign_ack tests."""

    def test_sign_ack_produces_partial_signature(self, dkg_keys_4, sample_block):
        keys, _ = dkg_keys_4
        mgr = BLSCertificateManager()
        partial = mgr.sign_ack(keys[0], sample_block.digest)
        assert partial.signature is not None
        assert len(partial.signature) == 96
        assert partial.signer_index == keys[0].participant_index

    def test_sign_ack_is_deterministic(self, dkg_keys_4, sample_block):
        keys, _ = dkg_keys_4
        mgr = BLSCertificateManager()
        p1 = mgr.sign_ack(keys[0], sample_block.digest)
        p2 = mgr.sign_ack(keys[0], sample_block.digest)
        assert p1.signature == p2.signature

    def test_different_keys_produce_different_signatures(self, dkg_keys_4, sample_block):
        keys, _ = dkg_keys_4
        mgr = BLSCertificateManager()
        p0 = mgr.sign_ack(keys[0], sample_block.digest)
        p1 = mgr.sign_ack(keys[1], sample_block.digest)
        assert p0.signature != p1.signature


class TestAggregateAndVerify:
    """BLS aggregation and certificate verification tests."""

    def test_aggregate_ack_signatures_combines_partials(
        self,
        dkg_keys_4,
        validator_set_4,
        sample_block,
    ):
        keys, group_pk = dkg_keys_4
        mgr = BLSCertificateManager(group_pk=group_pk)
        partials = [mgr.sign_ack(k, sample_block.digest) for k in keys[:3]]
        agg = mgr.aggregate_ack_signatures(partials, sample_block.digest, validator_set_4)
        assert len(agg) == 96

    def test_aggregated_signature_verifies(
        self,
        dkg_keys_4,
        validator_set_4,
        sample_block,
    ):
        keys, group_pk = dkg_keys_4
        mgr = BLSCertificateManager(group_pk=group_pk)
        partials = [mgr.sign_ack(k, sample_block.digest) for k in keys[:3]]
        agg = mgr.aggregate_ack_signatures(partials, sample_block.digest, validator_set_4)

        cert = Certificate(
            block=sample_block,
            signers=frozenset(k.participant_index for k in keys[:3]),
        )
        signed = SignedCertificate(
            certificate=cert,
            aggregated_signature=agg,
            signer_keys=frozenset(),
        )
        assert mgr.verify_certificate_signature(signed) is True

    def test_verify_fails_with_wrong_group_key(
        self,
        dkg_keys_4,
        validator_set_4,
        sample_block,
    ):
        keys, group_pk = dkg_keys_4
        mgr = BLSCertificateManager(group_pk=group_pk)
        partials = [mgr.sign_ack(k, sample_block.digest) for k in keys[:3]]
        agg = mgr.aggregate_ack_signatures(partials, sample_block.digest, validator_set_4)

        cert = Certificate(
            block=sample_block,
            signers=frozenset(k.participant_index for k in keys[:3]),
        )
        signed = SignedCertificate(
            certificate=cert,
            aggregated_signature=agg,
            signer_keys=frozenset(),
        )
        mgr_bad = BLSCertificateManager(group_pk=b"\xff" * 96)
        assert mgr_bad.verify_certificate_signature(signed) is False

    def test_verify_fails_with_tampered_digest(
        self,
        dkg_keys_4,
        validator_set_4,
        sample_block,
    ):
        keys, group_pk = dkg_keys_4
        mgr = BLSCertificateManager(group_pk=group_pk)
        partials = [mgr.sign_ack(k, sample_block.digest) for k in keys[:3]]
        agg = mgr.aggregate_ack_signatures(partials, sample_block.digest, validator_set_4)

        tampered_block = Block(
            author=0,
            round=5,
            payload=(b"TAMPERED",),
            parents=frozenset(),
            timestamp_ms=1000,
        )
        cert = Certificate(
            block=tampered_block,
            signers=frozenset(k.participant_index for k in keys[:3]),
        )
        signed = SignedCertificate(
            certificate=cert,
            aggregated_signature=agg,
            signer_keys=frozenset(),
        )
        assert mgr.verify_certificate_signature(signed) is False

    def test_insufficient_partials_raises(
        self,
        dkg_keys_4,
        validator_set_4,
        sample_block,
    ):
        keys, group_pk = dkg_keys_4
        mgr = BLSCertificateManager(group_pk=group_pk)
        partials = [mgr.sign_ack(keys[0], sample_block.digest)]
        with pytest.raises(ValueError, match="Need at least"):
            mgr.aggregate_ack_signatures(partials, sample_block.digest, validator_set_4)

    def test_empty_partials_raises(
        self,
        dkg_keys_4,
        validator_set_4,
        sample_block,
    ):
        keys, group_pk = dkg_keys_4
        mgr = BLSCertificateManager(group_pk=group_pk)
        with pytest.raises(ValueError, match="Need at least"):
            mgr.aggregate_ack_signatures([], sample_block.digest, validator_set_4)


class TestSignedCertificate:
    """SignedCertificate dataclass tests."""

    def test_wraps_certificate_correctly(self, sample_block):
        cert = Certificate(block=sample_block, signers=frozenset({0, 1, 2}))
        signed = SignedCertificate(
            certificate=cert,
            aggregated_signature=b"\xaa" * 96,
            signer_keys=frozenset({b"k0", b"k1", b"k2"}),
        )
        assert signed.certificate is cert
        assert len(signed.aggregated_signature) == 96
        assert len(signed.signer_keys) == 3

    def test_frozen(self, sample_block):
        cert = Certificate(block=sample_block, signers=frozenset({0}))
        signed = SignedCertificate(
            certificate=cert,
            aggregated_signature=b"\x00" * 96,
            signer_keys=frozenset(),
        )
        with pytest.raises(AttributeError):
            signed.aggregated_signature = b"\xff" * 96  # type: ignore[misc]


class TestBatchAttestation:
    """Batch signing and attestation verification tests."""

    def test_sign_committed_batch_round_trip(self, dkg_keys_4):
        keys, group_pk = dkg_keys_4
        mgr = BLSCertificateManager(group_pk=group_pk)
        batch_bytes = b"batch-round-5-epoch-1"
        partials = [mgr.sign_committed_batch(k, batch_bytes) for k in keys[:3]]
        combined = combine_partial_signatures(partials, 3)
        assert mgr.verify_batch_attestation(combined, batch_bytes, group_pk) is True

    def test_verify_batch_attestation_rejects_wrong_message(self, dkg_keys_4):
        keys, group_pk = dkg_keys_4
        mgr = BLSCertificateManager(group_pk=group_pk)
        batch_bytes = b"correct-batch"
        partials = [mgr.sign_committed_batch(k, batch_bytes) for k in keys[:3]]
        combined = combine_partial_signatures(partials, 3)
        assert mgr.verify_batch_attestation(combined, b"wrong-batch", group_pk) is False

    def test_different_domain_produces_different_signature(self, dkg_keys_4):
        keys, _ = dkg_keys_4
        mgr = BLSCertificateManager()
        msg = b"same-message"
        p_att = mgr.sign_committed_batch(keys[0], msg, domain=DOMAIN_ATTESTATION)
        p_ack = mgr.sign_ack(keys[0], msg)
        assert p_att.signature != p_ack.signature

    def test_verify_with_no_group_pk_returns_false(self, sample_block):
        mgr = BLSCertificateManager()
        cert = Certificate(block=sample_block, signers=frozenset({0}))
        signed = SignedCertificate(
            certificate=cert,
            aggregated_signature=b"\x00" * 96,
            signer_keys=frozenset(),
        )
        assert mgr.verify_certificate_signature(signed) is False
