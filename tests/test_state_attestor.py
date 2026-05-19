"""Tests for StateAttestor — dual-mode attestation (Spec D1c §4)."""

import pytest

from src.ltp.execution.execution_config import ExecutionConfig
from src.ltp.execution.state_attestor import AttestationResult, StateAttestor
from src.ltp.execution.state_root import MultiVMStateRoot
from src.ltp.execution.types import BatchResult, TxResult


@pytest.fixture(scope="module")
def operator_kp():
    from src.ltp import KeyPair

    return KeyPair.generate("test-attestor")


@pytest.fixture(scope="module")
def attestation_engine(operator_kp):
    from src.ltp.execution.attestation import AttestationEngine

    return AttestationEngine(operator_keypair=operator_kp, chain_id=103115120)


def _result_with_state_root(round_num: int = 0) -> BatchResult:
    root = MultiVMStateRoot(vm_roots={0x01: b"\xaa" * 32}, batch_round=round_num)
    return BatchResult(
        round=round_num,
        tx_results=[TxResult.accepted(gas_used=100)],
        state_root=root,
    )


def _result_no_state_root(round_num: int = 0) -> BatchResult:
    return BatchResult(round=round_num, tx_results=[], state_root=None)


class TestStateAttestorMLDSA:
    def test_mldsa_only_mode(self, attestation_engine):
        attestor = StateAttestor(
            attestation_engine=attestation_engine,
            committee_manager=None,
            config=ExecutionConfig(),
        )
        result = attestor.attest(_result_with_state_root(), epoch=1)
        assert isinstance(result, AttestationResult)
        assert result.mldsa_attestation is not None
        assert result.bls_signature is None
        assert result.mode == "mldsa_only"

    def test_state_root_populated(self, attestation_engine):
        attestor = StateAttestor(
            attestation_engine=attestation_engine,
            committee_manager=None,
            config=ExecutionConfig(),
        )
        result = attestor.attest(_result_with_state_root(round_num=5), epoch=1)
        assert len(result.state_root) == 32
        assert result.round == 5
        assert result.epoch == 1

    def test_mldsa_attestation_verifiable(self, attestation_engine, operator_kp):
        attestor = StateAttestor(
            attestation_engine=attestation_engine,
            committee_manager=None,
            config=ExecutionConfig(),
        )
        result = attestor.attest(_result_with_state_root(), epoch=1)
        assert result.mldsa_attestation.verify_mldsa(operator_kp.vk) is True

    def test_multiple_vms_produce_attestation(self, attestation_engine):
        root = MultiVMStateRoot(
            vm_roots={0x01: b"\xaa" * 32, 0x10: b"\xbb" * 32},
            batch_round=0,
        )
        br = BatchResult(round=0, tx_results=[TxResult.accepted()], state_root=root)
        attestor = StateAttestor(
            attestation_engine=attestation_engine,
            committee_manager=None,
            config=ExecutionConfig(),
        )
        result = attestor.attest(br, epoch=1)
        assert result.mode == "mldsa_only"
        assert len(result.state_root) == 32


class TestStateAttestorNoEngine:
    def test_no_engine_no_manager_returns_none_mode(self):
        attestor = StateAttestor(
            attestation_engine=None,
            committee_manager=None,
            config=ExecutionConfig(),
        )
        result = attestor.attest(_result_with_state_root(), epoch=1)
        assert result.mode == "none"
        assert result.mldsa_attestation is None
        assert result.bls_signature is None

    def test_catastrophic_batch_returns_none_mode(self, attestation_engine):
        attestor = StateAttestor(
            attestation_engine=attestation_engine,
            committee_manager=None,
            config=ExecutionConfig(),
        )
        result = attestor.attest(_result_no_state_root(), epoch=1)
        assert result.mode == "none"
        assert result.state_root is None


class TestStateAttestorDualMode:
    def test_dual_mode_with_bls_keys(self, attestation_engine):
        from src.ltp.execution.committee.dkg.session import DKGSession
        from src.ltp.execution.committee.dkg.threshold_signing import DOMAIN_STATE_ROOT
        from src.ltp.execution.committee.dkg.types import DKGSessionConfig

        participants = [f"v-{i}".encode() for i in range(4)]
        cfg = DKGSessionConfig(
            vm_tag=1,
            epoch=1,
            threshold=3,
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

        class FakeCM:
            def __init__(self):
                self._epoch = 1

            @property
            def epoch(self):
                return self._epoch

            def has_dkg_result(self, epoch):
                return epoch == 1

            def sign_as_committee(self, message, domain):
                from src.ltp.execution.committee.dkg.threshold_signing import (
                    combine_partial_signatures,
                    partial_sign,
                )

                partials = [partial_sign(k, message, domain) for k in signing_keys[:3]]
                return combine_partial_signatures(partials, 3)

        attestor = StateAttestor(
            attestation_engine=attestation_engine,
            committee_manager=FakeCM(),
            config=ExecutionConfig(),
        )
        result = attestor.attest(_result_with_state_root(), epoch=1)
        assert result.mode == "dual"
        assert result.mldsa_attestation is not None
        assert result.bls_signature is not None
        assert len(result.bls_signature) == 96

    def test_attestation_mode_reflects_availability(self, attestation_engine):
        attestor = StateAttestor(
            attestation_engine=attestation_engine,
            committee_manager=None,
            config=ExecutionConfig(),
        )
        assert attestor.attestation_mode() == "mldsa_only"

    def test_attestation_mode_no_engine(self):
        attestor = StateAttestor(
            attestation_engine=None,
            committee_manager=None,
            config=ExecutionConfig(),
        )
        assert attestor.attestation_mode() == "none"

    def test_deterministic_for_same_input(self, attestation_engine):
        attestor = StateAttestor(
            attestation_engine=attestation_engine,
            committee_manager=None,
            config=ExecutionConfig(),
        )
        r1 = attestor.attest(_result_with_state_root(), epoch=1)
        r2 = attestor.attest(_result_with_state_root(), epoch=1)
        assert r1.state_root == r2.state_root

    def test_empty_vm_roots_handled(self, attestation_engine):
        root = MultiVMStateRoot(vm_roots={}, batch_round=0)
        br = BatchResult(round=0, tx_results=[], state_root=root)
        attestor = StateAttestor(
            attestation_engine=attestation_engine,
            committee_manager=None,
            config=ExecutionConfig(),
        )
        result = attestor.attest(br, epoch=1)
        assert result.mode == "mldsa_only"
        assert len(result.state_root) == 32
