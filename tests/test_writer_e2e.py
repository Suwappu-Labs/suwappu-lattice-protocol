"""
End-to-end integration tests for the writer lifecycle (Spec C2 §12).

Exercises the full writer subsystem end-to-end across all layers:
  - WriterIdentity / WriterRegistry / WriterGate / TransactionRouter
  - Sponsor-path enrollment, admin-path approval, expiration/renewal
  - Multi-tier enrollment (MLDSA, COMPOSITE, BLS)
  - Emergency freeze and recovery
"""

from __future__ import annotations

import pytest

from src.ltp.execution.writer import WriterIdentity, WriterState, IdentityTier
from src.ltp.execution.writer_config import RegistryConfig
from src.ltp.execution.writer_registry import WriterRegistry
from src.ltp.execution.writer_policy import VMWriterPolicy
from src.ltp.execution.writer_recovery import EmergencyState
from src.ltp.execution.writer_epoch import EpochTracker, promote_due_probations
from src.ltp.execution.writer_gate import WriterGate
from src.ltp.execution.router import TransactionRouter
from src.ltp.execution.registry import VMRegistry
from src.ltp.execution.types import OrderedBatch, TxResult, StateResult
from src.ltp.keypair import KeyPair
from src.ltp.bls_keys import BLSKeyPair


# ---------------------------------------------------------------------------
# FakeEVM helper
# ---------------------------------------------------------------------------

class FakeEVM:
    """Minimal VM executor for E2E test."""
    vm_tag = 0x01
    vm_name = "fake-evm"
    family = "account"

    def execute(self, tx_bytes):
        return TxResult.accepted(gas_used=21000)

    def state_root(self):
        return b"\xcc" * 32

    def validate_tx(self, tx_bytes):
        return True

    def query_state(self, query):
        return StateResult.not_found()


# ---------------------------------------------------------------------------
# TestWriterLifecycleE2E
# ---------------------------------------------------------------------------

class TestWriterLifecycleE2E:
    """End-to-end integration tests exercising the full writer lifecycle."""

    def test_full_lifecycle(self):
        """Full flow: enroll → sponsor (2x) → PROBATION → promote → ACTIVE
        → transact → expire → renew → transact again.

        Verifies the audit trail accumulates at least 4 entries.
        """
        # --- Setup registry with sponsor_threshold=2, probation_epochs=5 ---
        config = RegistryConfig(sponsor_threshold=2, probation_epochs=5)
        registry = WriterRegistry(config=config)

        # Enroll a writer (PENDING)
        kp = KeyPair.generate("e2e-full")
        identity = WriterIdentity.from_keypair(kp)
        record = registry.enroll(identity, timestamp=1000)
        assert record.state == WriterState.PENDING

        fp = identity.fingerprint

        # First sponsor — still PENDING (threshold not yet met)
        registry.sponsor(fp, sponsor_fp=b"\xaa" * 32, timestamp=2000)
        assert registry.lookup(fp).state == WriterState.PENDING

        # Second sponsor — threshold met, auto-transitions to PROBATION
        registry.sponsor(fp, sponsor_fp=b"\xbb" * 32, timestamp=2000)
        assert registry.lookup(fp).state == WriterState.PROBATION

        # probation_until = 2000 + 5 = 2005
        # promote_due_probations at epoch >= 2005
        promoted = promote_due_probations(registry, current_epoch=2005, timestamp=5000)
        assert fp in promoted
        assert registry.lookup(fp).state == WriterState.ACTIVE

        # --- Setup gate + router ---
        vm_registry = VMRegistry()
        vm_registry.register(FakeEVM())
        emergency = EmergencyState()
        epoch_tracker = EpochTracker()
        gate = WriterGate(registry=registry, emergency=emergency, epoch_tracker=epoch_tracker)
        gate.set_policy(0x01, VMWriterPolicy(vm_tag=0x01))
        router = TransactionRouter(vm_registry, writer_gate=gate)

        # --- Transact while ACTIVE ---
        tx = fp + b"\x01" + b"hello"
        batch = OrderedBatch(
            round=1,
            epoch=0,
            transactions=[tx],
            leader_authority=0,
            timestamp_ms=1000,
            consensus_type="bft",
        )
        result = router.execute_batch(batch)
        assert result.tx_results[0].success, result.tx_results[0].error

        # --- Expire the writer ---
        record = registry.lookup(fp)
        record.expires_at = 15
        registry.check_expirations(current_epoch=15)
        assert registry.lookup(fp).state == WriterState.EXPIRED

        # Transaction should now fail (writer not in transactable state)
        result2 = router.execute_batch(OrderedBatch(
            round=2,
            epoch=0,
            transactions=[tx],
            leader_authority=0,
            timestamp_ms=2000,
            consensus_type="bft",
        ))
        assert not result2.tx_results[0].success

        # --- Renew the writer ---
        registry.renew(fp, actor_fp=b"\x01" * 32, timestamp=8000)
        assert registry.lookup(fp).state == WriterState.ACTIVE

        # --- Transact again after renewal ---
        result3 = router.execute_batch(OrderedBatch(
            round=3,
            epoch=0,
            transactions=[tx],
            leader_authority=0,
            timestamp_ms=3000,
            consensus_type="bft",
        ))
        assert result3.tx_results[0].success, result3.tx_results[0].error

        # --- Audit trail: at least 4 entries ---
        log = registry.lookup(fp).transition_log
        assert len(log) >= 4, (
            f"Expected at least 4 audit entries, got {len(log)}: "
            + str([(e.from_state, e.to_state) for e in log])
        )

    def test_three_identity_tiers_all_enroll(self):
        """All three identity tiers (MLDSA, COMPOSITE, BLS) can enroll
        and reach ACTIVE state via the admin approval path.

        Verifies active_writers() returns 3 entries.
        """
        registry = WriterRegistry()

        # --- MLDSA tier ---
        kp_mldsa = KeyPair.generate("mldsa-e2e")
        identity_mldsa = WriterIdentity.from_keypair(kp_mldsa)
        assert identity_mldsa.tier == IdentityTier.MLDSA
        registry.enroll(identity_mldsa, timestamp=1000)
        registry.approve(identity_mldsa.fingerprint, admin_fp=b"\x01" * 32, timestamp=2000)

        # --- COMPOSITE tier ---
        kp_comp = KeyPair.generate("comp-e2e", with_bls=True)
        identity_comp = WriterIdentity.from_keypair(kp_comp)
        assert identity_comp.tier == IdentityTier.COMPOSITE
        registry.enroll(identity_comp, timestamp=1001)
        registry.approve(identity_comp.fingerprint, admin_fp=b"\x01" * 32, timestamp=2000)

        # --- BLS tier ---
        bls_kp = BLSKeyPair.generate("bls-e2e")
        identity_bls = WriterIdentity.from_bls_identity(bls_kp.to_identity())
        assert identity_bls.tier == IdentityTier.BLS
        registry.enroll(identity_bls, timestamp=1002)
        registry.approve(identity_bls.fingerprint, admin_fp=b"\x01" * 32, timestamp=2000)

        # All three fingerprints are distinct
        fps = {identity_mldsa.fingerprint, identity_comp.fingerprint, identity_bls.fingerprint}
        assert len(fps) == 3, "Expected 3 distinct fingerprints"

        # All three are active
        active = registry.active_writers()
        assert len(active) == 3, f"Expected 3 active writers, got {len(active)}"
        active_fps = {r.identity.fingerprint for r in active}
        for fp in fps:
            assert fp in active_fps, f"Fingerprint {fp.hex()[:8]}… not in active set"

    def test_emergency_freeze_and_recovery(self):
        """Registry freeze blocks all transactions; unfreeze restores service.

        Scenario:
          1. Enroll + approve an ACTIVE writer
          2. Verify tx succeeds normally
          3. freeze_registry → tx fails
          4. unfreeze_registry → tx succeeds again
        """
        # --- Setup ---
        registry = WriterRegistry()
        emergency = EmergencyState()

        writer_fp = b"\xaa" * 32
        identity = WriterIdentity(
            tier=IdentityTier.MLDSA,
            fingerprint=writer_fp,
            mldsa_vk=b"\x01" * 32,
        )
        registry.enroll(identity, timestamp=1000)
        registry.approve(writer_fp, admin_fp=b"\x01" * 32, timestamp=2000)
        assert registry.lookup(writer_fp).state == WriterState.ACTIVE

        vm_registry = VMRegistry()
        vm_registry.register(FakeEVM())
        epoch_tracker = EpochTracker()
        gate = WriterGate(
            registry=registry,
            emergency=emergency,
            epoch_tracker=epoch_tracker,
        )
        gate.set_policy(0x01, VMWriterPolicy(vm_tag=0x01))
        router = TransactionRouter(vm_registry, writer_gate=gate)

        tx = writer_fp + b"\x01" + b"payload"

        def _run_batch(round_num: int) -> TxResult:
            batch = OrderedBatch(
                round=round_num,
                epoch=0,
                transactions=[tx],
                leader_authority=0,
                timestamp_ms=round_num * 1000,
                consensus_type="bft",
            )
            return router.execute_batch(batch).tx_results[0]

        # 1. Normal operation — should succeed
        r1 = _run_batch(1)
        assert r1.success, f"Expected success before freeze, got: {r1.error}"

        # 2. Freeze registry — subsequent tx must fail
        emergency.freeze_registry(
            actor_fp=b"\x01" * 32,
            reason="incident",
            timestamp=3000,
        )
        assert emergency.is_registry_frozen
        r2 = _run_batch(2)
        assert not r2.success, "Expected rejection while registry is frozen"
        assert "frozen" in r2.error

        # 3. Unfreeze registry — tx should succeed again
        emergency.unfreeze_registry(
            actor_fp=b"\x01" * 32,
            timestamp=4000,
        )
        assert not emergency.is_registry_frozen
        r3 = _run_batch(3)
        assert r3.success, f"Expected success after unfreeze, got: {r3.error}"
