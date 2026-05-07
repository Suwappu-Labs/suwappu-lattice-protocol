"""End-to-end BLS attestation integration test (Spec C1 §7.3).

Full flow: fake consensus -> router -> state root -> N operators sign BLS
-> aggregate -> verify.
"""

import pytest
from src.ltp.bls import BLS
from src.ltp.bls_keys import BLSKeyPair
from src.ltp.keypair import KeyPair
from src.ltp.execution.attestation import AttestationEngine, AttestationAggregator
from src.ltp.execution.state_root import MultiVMStateRoot
from src.ltp.execution.registry import VMRegistry
from src.ltp.execution.router import TransactionRouter
from src.ltp.execution.consensus import FakeConsensusAdapter
from src.ltp.execution.types import OrderedBatch, TxResult
from src.ltp.domain import DOMAIN_BLS_ATTEST, bls_domain_sign, bls_aggregate_verify


class FakeEVM:
    """Minimal VM executor for E2E test."""
    vm_tag = 0x01
    vm_name = "fake-evm"
    family = "account"

    def execute(self, tx_bytes: bytes) -> TxResult:
        return TxResult.accepted(gas_used=21000)

    def state_root(self) -> bytes:
        from src.ltp.primitives import canonical_hash_bytes
        return canonical_hash_bytes(b"evm-state-e2e")

    def validate_tx(self, tx_bytes: bytes) -> bool:
        return True

    def query_state(self, query):
        from src.ltp.execution.types import StateResult
        return StateResult.not_found()

    def health_check(self) -> bool:
        return True


class TestBLSE2E:
    """Full end-to-end flow: consensus -> execute -> state root -> BLS attest -> aggregate -> verify."""

    def test_multi_operator_bls_attestation(self):
        # 1. Set up VM registry with a single EVM executor
        registry = VMRegistry()
        evm = FakeEVM()
        registry.register(evm)

        # 2. Create a multi-VM state root from the executor
        vm_roots = {}
        for executor in registry.all_executors():
            vm_roots[executor.vm_tag] = executor.state_root()
        state_root = MultiVMStateRoot(vm_roots=vm_roots, batch_round=1)

        # 3. Create 5 operators with BLS keys
        operators = []
        for i in range(5):
            kp = KeyPair.generate(f"e2e-op-{i}", with_bls=True)
            bls_id = kp.to_bls_identity()
            operators.append((kp, bls_id))

        # 4. Each operator signs the state root with BLS
        lead_kp, lead_bls = operators[0]
        engine = AttestationEngine(lead_kp, chain_id=103115120, bls_identity=lead_bls)
        att = engine.sign(state_root, consensus_round=1, epoch=0, active_vm_tags=[0x01])
        digest = att.digest

        # 5. All operators produce individual BLS signatures
        aggregator = AttestationAggregator()
        for kp, bls_id in operators:
            sig = bls_domain_sign(DOMAIN_BLS_ATTEST, bls_id.sk_accessor(), digest)
            aggregator.add_signature(bls_id.pk, sig)

        # 6. Aggregate into a single 96-byte signature
        agg_sig = aggregator.finalize()
        assert len(agg_sig) == 96
        assert aggregator.signer_count() == 5

        # 7. Verify the aggregate signature against all committee public keys
        committee_pks = aggregator.signer_pks()
        assert bls_aggregate_verify(DOMAIN_BLS_ATTEST, committee_pks, digest, agg_sig) is True

        # 8. Verify that a missing signer invalidates the aggregate
        partial_pks = committee_pks[:4]  # only 4 of 5
        assert bls_aggregate_verify(DOMAIN_BLS_ATTEST, partial_pks, digest, agg_sig) is False

    def test_dual_signed_attestation_e2e(self):
        """Single operator dual-signs: ML-DSA for PQ insurance + BLS for aggregation."""
        kp = KeyPair.generate("dual-e2e", with_bls=True)
        bls_id = kp.to_bls_identity()
        engine = AttestationEngine(kp, chain_id=103115120, bls_identity=bls_id)

        state_root = MultiVMStateRoot(
            vm_roots={0x01: b"\xcc" * 32},
            batch_round=99,
        )

        att = engine.sign_dual(state_root, consensus_round=99, epoch=5, active_vm_tags=[0x01])

        # Both signatures present and valid
        assert att.verify_mldsa(kp.vk) is True
        assert att.verify_bls([bls_id.pk]) is True
        assert att.verify(vk=kp.vk, bls_pks=[bls_id.pk]) is True

    def test_three_key_modes_all_sign_same_digest(self):
        """All three key modes produce signatures that verify against the same digest."""
        state_root = MultiVMStateRoot(vm_roots={0x01: b"\xdd" * 32}, batch_round=1)
        dummy_kp = KeyPair.generate("mode-test")
        engine = AttestationEngine(dummy_kp, chain_id=1)
        att = engine.sign(state_root, consensus_round=1, epoch=0, active_vm_tags=[0x01])
        digest = att.digest

        # Mode 1: Composite
        comp_kp = KeyPair.generate("comp", with_bls=True)
        comp_id = comp_kp.to_bls_identity()

        # Mode 2: Standalone
        standalone = BLSKeyPair.generate("standalone").to_identity()

        # Mode 3: Derived
        mldsa_kp = KeyPair.generate("derive-source")
        derived = BLSKeyPair.derive_from(mldsa_kp.sk, label="derived").to_identity()

        for identity in [comp_id, standalone, derived]:
            sig = bls_domain_sign(DOMAIN_BLS_ATTEST, identity.sk_accessor(), digest)
            assert bls_aggregate_verify(DOMAIN_BLS_ATTEST, [identity.pk], digest, sig) is True
