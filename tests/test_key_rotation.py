"""
Key Rotation Protocol Tests.

Verifies the KeyRotationManager: rotation, grace periods, chain integrity,
and secure retirement of private key material.

Reference: WireGuard §5 (rekey intervals), NIST SP 800-57 (key lifecycle).
"""

import time

import pytest

from src.ltp import KeyPair, reset_poc_state
from src.ltp.keypair import KeyRotationManager
from src.ltp.primitives import canonical_hash


class TestKeyRotation:
    """Key rotation protocol tests."""

    @classmethod
    def setup_class(cls):
        reset_poc_state()

    def test_rotate_creates_new_version(self):
        """Rotation increments version number."""
        mgr = KeyRotationManager()
        kp1 = KeyPair.generate("alice")
        assert kp1.version == 1

        kp2 = mgr.rotate(kp1)
        assert kp2.version == 2
        assert kp2.label == "alice"

    def test_rotate_links_predecessor(self):
        """New key's predecessor_vk_hash matches H(old.vk)."""
        mgr = KeyRotationManager()
        kp1 = KeyPair.generate("alice")
        kp2 = mgr.rotate(kp1)

        assert kp2.predecessor_vk_hash == canonical_hash(kp1.vk)

    def test_rotate_sets_expiry_on_old(self):
        """Old key gets expires_at = now + grace_period."""
        mgr = KeyRotationManager()
        kp1 = KeyPair.generate("alice")
        assert kp1.expires_at == 0.0  # Never expires initially

        kp2 = mgr.rotate(kp1, grace_period_seconds=3600)
        assert kp1.expires_at > 0.0
        assert kp1.expires_at > time.time()  # Hasn't expired yet

    def test_grace_period_both_keys_active(self):
        """During grace period, both old and new keys are active."""
        mgr = KeyRotationManager()
        kp1 = KeyPair.generate("alice")
        mgr.register(kp1)
        kp2 = mgr.rotate(kp1, grace_period_seconds=3600)

        active = mgr.active_keys("alice")
        assert len(active) == 2
        assert kp1 in active
        assert kp2 in active

    def test_expired_key_not_active(self):
        """After grace period, old key is not in active list."""
        mgr = KeyRotationManager()
        kp1 = KeyPair.generate("alice")
        mgr.register(kp1)
        kp2 = mgr.rotate(kp1, grace_period_seconds=0.001)

        # Simulate time passing
        time.sleep(0.01)
        active = mgr.active_keys("alice")
        assert len(active) == 1
        assert active[0] == kp2

    def test_current_key_is_newest(self):
        """current_key() returns the highest-version key."""
        mgr = KeyRotationManager()
        kp1 = KeyPair.generate("alice")
        mgr.register(kp1)
        kp2 = mgr.rotate(kp1)
        kp3 = mgr.rotate(kp2)

        current = mgr.current_key("alice")
        assert current == kp3
        assert current.version == 3

    def test_chain_integrity(self):
        """verify_chain() confirms all predecessor links are valid."""
        mgr = KeyRotationManager()
        kp1 = KeyPair.generate("alice")
        mgr.register(kp1)
        kp2 = mgr.rotate(kp1)
        kp3 = mgr.rotate(kp2)

        assert mgr.verify_chain("alice") is True

    def test_broken_chain_detected(self):
        """verify_chain() detects tampered predecessor hash."""
        mgr = KeyRotationManager()
        kp1 = KeyPair.generate("alice")
        mgr.register(kp1)
        kp2 = mgr.rotate(kp1)

        # Tamper with chain
        kp2.predecessor_vk_hash = "tampered-hash"
        assert mgr.verify_chain("alice") is False

    def test_retire_zeroizes_private_keys(self):
        """retire() overwrites dk and sk with zeros."""
        mgr = KeyRotationManager()
        kp = KeyPair.generate("alice")
        assert kp.dk != b"\x00" * len(kp.dk)

        mgr.retire(kp)
        assert kp.dk == b"\x00" * len(kp.dk)
        assert kp.sk == b"\x00" * len(kp.sk)

    def test_is_expired_never_expires(self):
        """Key with expires_at=0 never expires."""
        mgr = KeyRotationManager()
        kp = KeyPair.generate("alice")
        assert mgr.is_expired(kp) is False

    def test_is_expired_future(self):
        """Key with future expiry is not expired."""
        mgr = KeyRotationManager()
        kp = KeyPair.generate("alice")
        kp.expires_at = time.time() + 3600
        assert mgr.is_expired(kp) is False

    def test_created_at_set(self):
        """KeyPair.generate() sets created_at to current time."""
        before = time.time()
        kp = KeyPair.generate("alice")
        after = time.time()
        assert before <= kp.created_at <= after

    def test_new_key_has_different_ek(self):
        """Rotated key has different encapsulation key."""
        mgr = KeyRotationManager()
        kp1 = KeyPair.generate("alice")
        kp2 = mgr.rotate(kp1)
        assert kp1.ek != kp2.ek
        assert kp1.vk != kp2.vk
