"""
Key rotation lifecycle + cloud abstraction tests.

Tests the formal PENDING -> ACTIVE -> RETIRING -> RETIRED key lifecycle,
KMS backend abstraction, scheduled task runner, and DST-validated rotation.

All tests are deterministic — no threads, no sleeps.
"""

from __future__ import annotations

import threading
import time

import pytest

from src.ltp.cloud.kms import InMemoryKMSBackend
from src.ltp.cloud.scheduler import InMemoryScheduler
from src.ltp.keypair import (
    InvalidKeyStateTransition,
    KeyPair,
    KeyRotationEvent,
    KeyRotationManager,
    KeyState,
    _validate_key_transition,
)
from src.ltp.primitives import MLDSA, canonical_hash

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def alice() -> KeyPair:
    return KeyPair.generate("alice-5a")


# ---------------------------------------------------------------------------
# KeyState Enum
# ---------------------------------------------------------------------------


class TestKeyStateEnum:
    def test_all_states_exist(self):
        assert KeyState.PENDING.value == "pending"
        assert KeyState.ACTIVE.value == "active"
        assert KeyState.RETIRING.value == "retiring"
        assert KeyState.RETIRED.value == "retired"

    def test_states_are_strings(self):
        for state in KeyState:
            assert isinstance(state.value, str)

    def test_four_states_total(self):
        assert len(KeyState) == 4


# ---------------------------------------------------------------------------
# Key State Transitions
# ---------------------------------------------------------------------------


class TestKeyStateTransitions:
    def test_pending_to_active(self):
        _validate_key_transition(KeyState.PENDING, KeyState.ACTIVE)

    def test_active_to_retiring(self):
        _validate_key_transition(KeyState.ACTIVE, KeyState.RETIRING)

    def test_retiring_to_retired(self):
        _validate_key_transition(KeyState.RETIRING, KeyState.RETIRED)

    def test_retired_to_active_rejected(self):
        with pytest.raises(InvalidKeyStateTransition):
            _validate_key_transition(KeyState.RETIRED, KeyState.ACTIVE)

    def test_pending_to_retiring_rejected(self):
        with pytest.raises(InvalidKeyStateTransition):
            _validate_key_transition(KeyState.PENDING, KeyState.RETIRING)

    def test_active_to_pending_rejected(self):
        with pytest.raises(InvalidKeyStateTransition):
            _validate_key_transition(KeyState.ACTIVE, KeyState.PENDING)

    def test_retired_to_pending_rejected(self):
        with pytest.raises(InvalidKeyStateTransition):
            _validate_key_transition(KeyState.RETIRED, KeyState.PENDING)

    def test_retiring_to_active_rejected(self):
        with pytest.raises(InvalidKeyStateTransition):
            _validate_key_transition(KeyState.RETIRING, KeyState.ACTIVE)


# ---------------------------------------------------------------------------
# Full Key Lifecycle (GATE REQUIREMENT)
# ---------------------------------------------------------------------------


class TestKeyLifecycleFull:
    def test_full_pending_active_retiring_retired_cycle(self):
        """Gate test: full PENDING -> ACTIVE -> RETIRING -> RETIRED lifecycle."""
        mgr = KeyRotationManager()

        # Generate PENDING
        kp = mgr.generate_pending("lifecycle-test")
        assert kp.state == KeyState.PENDING

        # Activate
        mgr.activate(kp)
        assert kp.state == KeyState.ACTIVE

        # Begin retirement
        mgr.begin_retirement(kp, grace_period_seconds=100.0)
        assert kp.state == KeyState.RETIRING
        assert kp.expires_at > 0

        # Complete retirement
        mgr.complete_retirement(kp)
        assert kp.state == KeyState.RETIRED
        assert kp.dk == b"\x00" * len(kp.dk)

    def test_chain_verified_throughout_lifecycle(self):
        """Chain integrity maintained through full lifecycle."""
        mgr = KeyRotationManager()

        kp1 = mgr.generate_pending("chain-test")
        mgr.activate(kp1)
        assert mgr.verify_chain("chain-test")

        # Rotate (creates kp2, retires kp1)
        kp2 = mgr.rotate(kp1, grace_period_seconds=100.0)
        assert mgr.verify_chain("chain-test")
        assert kp2.predecessor_vk_hash == canonical_hash(kp1.vk)

    def test_rotate_preserves_backward_compat(self):
        """Existing rotate() API still works identically."""
        mgr = KeyRotationManager()
        kp1 = KeyPair.generate("compat-test")
        mgr.register(kp1)

        kp2 = mgr.rotate(kp1, grace_period_seconds=60.0)

        assert kp2.version == kp1.version + 1
        assert kp2.predecessor_vk_hash == canonical_hash(kp1.vk)
        assert kp1.state == KeyState.RETIRING
        assert kp2.state == KeyState.ACTIVE

    def test_generate_pending_creates_pending_state(self):
        mgr = KeyRotationManager()
        kp = mgr.generate_pending("pending-test")
        assert kp.state == KeyState.PENDING
        assert kp.label == "pending-test"

    def test_activate_moves_to_active(self):
        mgr = KeyRotationManager()
        kp = mgr.generate_pending("activate-test")
        mgr.activate(kp)
        assert kp.state == KeyState.ACTIVE

    def test_begin_retirement_sets_expires_at(self):
        mgr = KeyRotationManager()
        kp = KeyPair.generate("retire-test")
        mgr.register(kp)
        mgr.begin_retirement(kp, grace_period_seconds=3600.0)
        assert kp.state == KeyState.RETIRING
        assert kp.expires_at > time.time() - 1

    def test_complete_retirement_zeroizes(self):
        mgr = KeyRotationManager()
        kp = KeyPair.generate("zero-test")
        mgr.register(kp)
        mgr.begin_retirement(kp, grace_period_seconds=1.0)
        mgr.complete_retirement(kp)
        assert kp.state == KeyState.RETIRED
        assert all(b == 0 for b in kp.dk)
        assert all(b == 0 for b in kp.sk)

    def test_default_keypair_state_is_active(self):
        """KeyPair.generate() defaults to ACTIVE for backward compat."""
        kp = KeyPair.generate("default-state")
        assert kp.state == KeyState.ACTIVE


# ---------------------------------------------------------------------------
# KeyRotationEvent
# ---------------------------------------------------------------------------


class TestKeyRotationEvent:
    def test_event_is_frozen(self):
        event = KeyRotationEvent(
            old_vk_hash="abc",
            new_vk_hash="def",
            old_version=1,
            new_version=2,
            rotation_signature=b"sig",
            timestamp=1.0,
            label="test",
        )
        with pytest.raises(AttributeError):
            event.label = "changed"

    def test_rotation_event_chain_links(self):
        mgr = KeyRotationManager()
        kp = KeyPair.generate("event-test")
        mgr.register(kp)
        event = mgr.rotate_with_dst_validation(kp)

        assert event.old_vk_hash == canonical_hash(kp.vk)
        assert event.old_version == kp.version
        assert event.new_version == kp.version + 1
        assert event.label == "event-test"
        assert len(event.rotation_signature) > 0


# ---------------------------------------------------------------------------
# DST Validation
# ---------------------------------------------------------------------------


class TestDSTValidation:
    def test_rotate_with_dst_produces_event(self):
        mgr = KeyRotationManager()
        kp = KeyPair.generate("dst-test")
        mgr.register(kp)
        event = mgr.rotate_with_dst_validation(kp)
        assert isinstance(event, KeyRotationEvent)

    def test_dst_rotation_verifies_chain(self):
        mgr = KeyRotationManager()
        kp = KeyPair.generate("dst-chain")
        mgr.register(kp)
        mgr.rotate_with_dst_validation(kp)
        assert mgr.verify_chain("dst-chain")


# ---------------------------------------------------------------------------
# InMemoryKMSBackend
# ---------------------------------------------------------------------------


class TestInMemoryKMSBackend:
    def test_create_key(self):
        kms = InMemoryKMSBackend()
        vk = kms.create_key("test-key-1")
        assert len(vk) > 0

    def test_get_public_key(self):
        kms = InMemoryKMSBackend()
        vk = kms.create_key("test-key-2")
        assert kms.get_public_key("test-key-2") == vk

    def test_sign_and_verify(self):
        kms = InMemoryKMSBackend()
        kms.create_key("sign-key")
        vk = kms.get_public_key("sign-key")
        msg = b"test message"
        sig = kms.sign("sign-key", msg)
        assert MLDSA.verify(vk, msg, sig)

    def test_destroy_key(self):
        kms = InMemoryKMSBackend()
        kms.create_key("destroy-key")
        assert kms.destroy_key("destroy-key") is True
        with pytest.raises(KeyError):
            kms.get_public_key("destroy-key")

    def test_destroy_nonexistent_returns_false(self):
        kms = InMemoryKMSBackend()
        assert kms.destroy_key("no-such-key") is False

    def test_list_keys(self):
        kms = InMemoryKMSBackend()
        kms.create_key("a-key")
        kms.create_key("b-key")
        keys = kms.list_keys()
        assert "a-key" in keys
        assert "b-key" in keys

    def test_list_keys_with_prefix(self):
        kms = InMemoryKMSBackend()
        kms.create_key("node-1")
        kms.create_key("node-2")
        kms.create_key("other")
        assert len(kms.list_keys("node-")) == 2

    def test_get_key_metadata(self):
        kms = InMemoryKMSBackend()
        kms.create_key("meta-key")
        meta = kms.get_key_metadata("meta-key")
        assert meta["algorithm"] == "ML-DSA-65"
        assert meta["state"] == "active"
        assert "created_at" in meta

    def test_rotate_key(self):
        kms = InMemoryKMSBackend()
        kms.create_key("rot-key")
        old_vk = kms.get_public_key("rot-key")
        new_id = kms.rotate_key("rot-key")
        assert "v2" in new_id
        new_vk = kms.get_public_key("rot-key")
        assert new_vk != old_vk

    def test_thread_safety(self):
        kms = InMemoryKMSBackend()
        errors = []

        def create(i):
            try:
                kms.create_key(f"thread-key-{i}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=create, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(kms.list_keys()) == 10


# ---------------------------------------------------------------------------
# InMemoryScheduler
# ---------------------------------------------------------------------------


class TestInMemoryScheduler:
    def test_schedule_and_tick(self):
        sched = InMemoryScheduler()
        fired = []
        sched.schedule("task-1", lambda: fired.append(1), interval_seconds=10.0)
        sched.tick(0.0)  # Fires immediately (next_at starts at 0)
        assert len(fired) == 1

    def test_tick_before_interval_does_not_fire(self):
        sched = InMemoryScheduler()
        fired = []
        sched.schedule("task-2", lambda: fired.append(1), interval_seconds=100.0)
        sched.tick(0.0)  # First fire
        sched.tick(50.0)  # Before next interval
        assert len(fired) == 1

    def test_cancel_prevents_execution(self):
        sched = InMemoryScheduler()
        fired = []
        sched.schedule("task-3", lambda: fired.append(1), interval_seconds=10.0)
        sched.cancel("task-3")
        sched.tick(100.0)
        assert len(fired) == 0

    def test_trigger_now(self):
        sched = InMemoryScheduler()
        fired = []
        sched.schedule("task-4", lambda: fired.append(1), interval_seconds=1000.0)
        sched.trigger_now("task-4")
        assert len(fired) == 1

    def test_list_tasks(self):
        sched = InMemoryScheduler()
        sched.schedule("a", lambda: None, 10.0)
        sched.schedule("b", lambda: None, 20.0)
        tasks = sched.list_tasks()
        ids = [t["task_id"] for t in tasks]
        assert "a" in ids and "b" in ids

    def test_periodic_firing(self):
        sched = InMemoryScheduler()
        fired = []
        sched.schedule("periodic", lambda: fired.append(1), interval_seconds=10.0)
        sched.tick(0.0)  # Fire 1
        sched.tick(10.0)  # Fire 2
        sched.tick(20.0)  # Fire 3
        assert len(fired) == 3

    def test_deterministic_ordering(self):
        sched = InMemoryScheduler()
        order = []
        sched.schedule("first", lambda: order.append("A"), interval_seconds=10.0)
        sched.schedule("second", lambda: order.append("B"), interval_seconds=10.0)
        sched.tick(0.0)
        assert len(order) == 2


# ---------------------------------------------------------------------------
# Key Rotation with KMS
# ---------------------------------------------------------------------------


class TestKeyRotationWithKMS:
    def test_complete_retirement_delegates_to_kms(self):
        kms = InMemoryKMSBackend()
        kms.create_key("kms-retire-v1")
        mgr = KeyRotationManager(kms=kms)
        kp = KeyPair.generate("kms-retire")
        kp.version = 1
        mgr.register(kp)
        mgr.begin_retirement(kp)
        mgr.complete_retirement(kp)
        assert kp.state == KeyState.RETIRED
        # KMS key should be destroyed
        assert kms.destroy_key("kms-retire-v1") is False  # Already destroyed

    def test_rotation_without_kms_still_works(self):
        mgr = KeyRotationManager()  # No KMS
        kp = KeyPair.generate("no-kms")
        mgr.register(kp)
        kp2 = mgr.rotate(kp)
        assert kp2.version == 2
        assert kp.state == KeyState.RETIRING


# ---------------------------------------------------------------------------
# Key Rotation with Scheduler
# ---------------------------------------------------------------------------


class TestKeyRotationWithScheduler:
    def test_scheduled_rotation_triggers_on_tick(self):
        sched = InMemoryScheduler()
        mgr = KeyRotationManager(scheduler=sched)
        kp = KeyPair.generate("sched-test")
        mgr.register(kp)

        rotated = []

        def do_rotation():
            new = mgr.rotate(kp)
            rotated.append(new)

        sched.schedule("key-rotation", do_rotation, interval_seconds=100.0)
        sched.tick(0.0)
        assert len(rotated) == 1
        assert rotated[0].version == 2

    def test_cancel_stops_rotation(self):
        sched = InMemoryScheduler()
        rotated = []
        sched.schedule("cancel-test", lambda: rotated.append(1), interval_seconds=10.0)
        sched.tick(0.0)
        assert len(rotated) == 1
        sched.cancel("cancel-test")
        sched.tick(100.0)
        assert len(rotated) == 1  # No more fires
