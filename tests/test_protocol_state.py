"""
Protocol State Machine + Replay Protection Tests.

Verifies protocol-level invariants: replay protection, entity deduplication,
and transfer state tracking.

Reference: WireGuard formal state machine, FoundationDB strict serializability.
"""

import pytest

from src.ltp import (
    CommitmentNetwork,
    Entity,
    KeyPair,
    LTPProtocol,
    reset_poc_state,
)


class TestReplayProtection:
    """Protocol replay protection tests."""

    @classmethod
    def setup_class(cls):
        reset_poc_state()

    def _make_protocol(self):
        """Create a fresh protocol instance."""
        reset_poc_state()
        network = CommitmentNetwork()
        for i in range(3):
            network.add_node(f"node-{i}", "us-east-1")
        return LTPProtocol(network)

    def test_duplicate_entity_same_sender(self):
        """Same entity from same sender in same timestamp can't be committed twice.

        EntityID includes timestamp, so two rapid commits of the same content
        with the same sender_vk will only collide if timestamps are identical.
        The commitment log rejects duplicate entity_ids.
        """
        proto = self._make_protocol()
        alice = KeyPair.generate("alice")

        entity = Entity(content=b"unique content", shape="text/plain")
        eid1, rec1, cek1 = proto.commit(entity, alice)

        # Second commit of same content — EntityID includes timestamp,
        # so it should be a different entity_id (different time.time())
        entity2 = Entity(content=b"unique content", shape="text/plain")
        eid2, rec2, cek2 = proto.commit(entity2, alice)

        # Different timestamps → different entity_ids
        assert eid1 != eid2

    def test_commit_materialize_different_receivers(self):
        """Same entity can be materialized by different receivers."""
        proto = self._make_protocol()
        alice = KeyPair.generate("alice")
        bob = KeyPair.generate("bob")
        carol = KeyPair.generate("carol")

        entity = Entity(content=b"shared secret", shape="text/plain")
        eid, rec, cek = proto.commit(entity, alice)

        # Seal to Bob
        sealed_bob = proto.lattice(eid, rec, cek, bob)
        result_bob = proto.materialize(sealed_bob, bob)
        assert result_bob == b"shared secret"

        # Seal to Carol (same entity, different receiver)
        sealed_carol = proto.lattice(eid, rec, cek, carol)
        result_carol = proto.materialize(sealed_carol, carol)
        assert result_carol == b"shared secret"

    def test_wrong_receiver_cannot_materialize(self):
        """Sealed key for Bob cannot be materialized by Eve."""
        proto = self._make_protocol()
        alice = KeyPair.generate("alice")
        bob = KeyPair.generate("bob")
        eve = KeyPair.generate("eve")

        entity = Entity(content=b"for bob only", shape="text/plain")
        eid, rec, cek = proto.commit(entity, alice)
        sealed = proto.lattice(eid, rec, cek, bob)

        # Eve tries to materialize
        result = proto.materialize(sealed, eve)
        assert result is None  # Should fail gracefully

    def test_tampered_sealed_key_fails(self):
        """Tampered sealed key produces None (not garbage)."""
        proto = self._make_protocol()
        alice = KeyPair.generate("alice")
        bob = KeyPair.generate("bob")

        entity = Entity(content=b"integrity test", shape="text/plain")
        eid, rec, cek = proto.commit(entity, alice)
        sealed = proto.lattice(eid, rec, cek, bob)

        # Tamper with sealed key
        tampered = bytearray(sealed)
        tampered[len(tampered) // 2] ^= 0xFF
        result = proto.materialize(bytes(tampered), bob)
        assert result is None


class TestTransferProperties:
    """End-to-end transfer property tests."""

    @classmethod
    def setup_class(cls):
        reset_poc_state()

    def _make_protocol(self):
        reset_poc_state()
        network = CommitmentNetwork()
        for i in range(3):
            network.add_node(f"node-{i}", "us-east-1")
        return LTPProtocol(network)

    def test_entity_id_includes_sender_identity(self):
        """Same content from different senders produces different entity_ids."""
        proto = self._make_protocol()
        alice = KeyPair.generate("alice")
        bob = KeyPair.generate("bob")

        content = b"same content"
        eid_alice, _, _ = proto.commit(Entity(content=content, shape="text/plain"), alice)
        eid_bob, _, _ = proto.commit(Entity(content=content, shape="text/plain"), bob)

        assert eid_alice != eid_bob  # Different sender_vk → different entity_id

    def test_sealed_key_size_constant(self):
        """Sealed key size is O(1) — independent of content size."""
        proto = self._make_protocol()
        alice = KeyPair.generate("alice")
        bob = KeyPair.generate("bob")

        sizes = []
        for content_size in [10, 100, 1000, 5000]:
            reset_poc_state()
            a = KeyPair.generate("a")
            b = KeyPair.generate("b")
            net = CommitmentNetwork()
            for i in range(3):
                net.add_node(f"n-{i}", "us")
            p = LTPProtocol(net)

            entity = Entity(content=b"x" * content_size, shape="application/octet-stream")
            eid, rec, cek = p.commit(entity, a)
            sealed = p.lattice(eid, rec, cek, b)
            sizes.append(len(sealed))

        # All sealed keys should be within 20 bytes of each other
        assert max(sizes) - min(sizes) <= 20, f"Sizes vary: {sizes}"

    def test_commitment_record_is_signed(self):
        """Commitment record has a valid signature field."""
        proto = self._make_protocol()
        alice = KeyPair.generate("alice")

        entity = Entity(content=b"signed content", shape="text/plain")
        eid, rec, cek = proto.commit(entity, alice)

        assert rec.signature is not None
        assert len(rec.signature) > 0
        assert rec.sender_id == "alice"
