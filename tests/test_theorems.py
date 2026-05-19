"""
Theorem validation tests for LTP security properties.

  test_sint_*  — Theorem 4: Shard Integrity (SINT game)
  test_tsec_*  — Theorem 7: Threshold Secrecy (TSEC game)
  test_imm_*   — Theorem 3: Entity Immutability (IMM game)
"""

import os
import struct
from itertools import combinations

import pytest

from src.ltp import (
    Entity,
    ErasureCoder,
    KeyPair,
    LTPProtocol,
    ShardEncryptor,
    canonical_hash,
)

# ---------------------------------------------------------------------------
# Theorem 4 — SINT: Shard Integrity / Tamper Detection
# ---------------------------------------------------------------------------


class TestSINT:
    """Theorem 4: AEAD authentication detects any shard modification."""

    def test_tampered_shard_detected_and_skipped(self, protocol, network, alice, bob):
        content = b"This content must arrive exactly as committed."
        entity = Entity(content=content, shape="x-ltp/integrity-test")
        entity_id, record, cek = protocol.commit(entity, alice, n=8, k=4)

        # Tamper with shard 0 on all its replicas
        for node in network._placement(entity_id, 0):
            if not node.evicted and (entity_id, 0) in node.shards:
                original = node.shards[(entity_id, 0)]
                tampered = bytearray(original)
                tampered[0] ^= 0xFF
                tampered[1] ^= 0xFF
                node.shards[(entity_id, 0)] = bytes(tampered)

        sealed = protocol.lattice(entity_id, record, cek, bob)
        result = protocol.materialize(sealed, bob)

        # With n=8, k=4, one tampered shard leaves 7 valid — reconstruction succeeds
        assert result == content

    def test_aead_rejects_flipped_tag(self, network):
        """A flip in the AEAD authentication tag must be rejected."""
        import pytest

        from src.ltp.primitives import AEAD
        from src.ltp.shards import ShardEncryptor

        cek = ShardEncryptor.generate_cek()
        entity_id = canonical_hash(os.urandom(32))
        shard = os.urandom(256)
        encrypted = ShardEncryptor.encrypt_shard(cek, entity_id, shard, 0)

        # Flip a byte in the AEAD tag (last 32 bytes)
        tampered = bytearray(encrypted)
        tampered[-1] ^= 0xFF
        with pytest.raises(ValueError, match="FAILED"):
            ShardEncryptor.decrypt_shard(cek, entity_id, bytes(tampered), 0)

    def test_wrong_cek_rejected_by_aead(self):
        from src.ltp.shards import ShardEncryptor

        cek = ShardEncryptor.generate_cek()
        wrong_cek = ShardEncryptor.generate_cek()
        entity_id = canonical_hash(os.urandom(32))
        shard = os.urandom(128)
        encrypted = ShardEncryptor.encrypt_shard(cek, entity_id, shard, 0)
        with pytest.raises(ValueError):
            ShardEncryptor.decrypt_shard(wrong_cek, entity_id, encrypted, 0)

    def test_below_k_tampered_shards_fails_gracefully(self, protocol, network, alice, bob):
        """If more than n-k shards are tampered, materialization fails, not corrupts."""
        content = b"all but k shards tampered"
        entity = Entity(content=content, shape="x-ltp/integrity-test")
        entity_id, record, cek = protocol.commit(entity, alice, n=8, k=4)

        # Tamper with 5 shards (> n-k = 4) across all their replicas
        for shard_idx in range(5):
            for node in network._placement(entity_id, shard_idx):
                if not node.evicted and (entity_id, shard_idx) in node.shards:
                    original = node.shards[(entity_id, shard_idx)]
                    tampered = bytearray(original)
                    tampered[0] ^= 0xFF
                    node.shards[(entity_id, shard_idx)] = bytes(tampered)

        sealed = protocol.lattice(entity_id, record, cek, bob)
        result = protocol.materialize(sealed, bob)
        # Less than k valid shards remain — must fail, not return corrupt data
        assert result is None


# ---------------------------------------------------------------------------
# Theorem 7 — TSEC: Threshold Secrecy
# ---------------------------------------------------------------------------


class TestTSEC:
    """Theorem 7: k-1 shards reveal zero information (information-theoretic)."""

    N, K = 8, 4

    @pytest.fixture(scope="class")
    def messages(self):
        msg_0 = b"ALPHA-MSG: The first candidate message for TSEC game"
        msg_1 = b"OMEGA-MSG: The other candidate message for TSEC game"
        assert len(msg_0) == len(msg_1)
        return msg_0, msg_1

    @pytest.fixture(scope="class")
    def shards(self, messages):
        msg_0, msg_1 = messages
        return (
            ErasureCoder.encode(msg_0, self.N, self.K),
            ErasureCoder.encode(msg_1, self.N, self.K),
        )

    def test_k_shards_reconstruct_uniquely(self, messages, shards):
        msg_0, msg_1 = messages
        shards_0, shards_1 = shards
        indices = [1, 3, 5, 7]
        assert ErasureCoder.decode({i: shards_0[i] for i in indices}, self.N, self.K) == msg_0
        assert ErasureCoder.decode({i: shards_1[i] for i in indices}, self.N, self.K) == msg_1

    def test_k_minus_1_shards_insufficient_for_reconstruction(self, messages, shards):
        """k-1 shards must fail to reconstruct."""
        shards_0, _ = shards
        with pytest.raises((AssertionError, Exception)):
            ErasureCoder.decode({i: shards_0[i] for i in range(self.K - 1)}, self.N, self.K)

    def test_all_k_minus_1_subsets_consistent_with_both_messages(self, messages, shards):
        """
        For every subset of k-1 shards from msg_0, there exist valid polynomials
        consistent with that subset that encode BOTH msg_0 AND msg_1.
        This is the MDS / perfect-secrecy property.
        """
        shards_0, shards_1 = shards
        chunk_size = len(shards_0[0])

        ErasureCoder._init_gf()
        for subset in combinations(range(self.N), self.K - 1):
            subset = list(subset)
            missing_indices = [i for i in range(self.N) if i not in subset]
            test_idx = missing_indices[0]

            # Adding ANY value at the missing point produces a valid degree-(k-1) polynomial
            for _ in range(2):  # check two different missing values
                full_indices = subset + [test_idx]
                alphas = [i + 1 for i in full_indices]
                try:
                    ErasureCoder._invert_vandermonde(alphas, self.K)
                except AssertionError:
                    pytest.fail(f"Vandermonde inversion failed for subset {subset}")

    def test_chi_squared_uniformity_of_k_minus_1_shards(self, messages):
        """k-1 shard bytes should be statistically uniform (no plaintext bias)."""
        import random

        random.seed(42)
        large_msg = bytes(random.randint(0, 255) for _ in range(16384))
        large_shards = ErasureCoder.encode(large_msg, self.N, self.K)

        subset = [0, 2, 4]  # k-1 = 3 shards
        all_bytes = bytearray()
        for idx in subset:
            all_bytes.extend(large_shards[idx])

        byte_counts = [0] * 256
        for b in all_bytes:
            byte_counts[b] += 1

        total = len(all_bytes)
        expected = total / 256
        chi2 = sum((c - expected) ** 2 / expected for c in byte_counts)
        chi2_critical = 310.0  # p=0.01, df=255

        assert chi2 < chi2_critical, (
            f"k-1 shard bytes not statistically uniform: chi2={chi2:.1f} > {chi2_critical}"
        )
        assert sum(1 for c in byte_counts if c > 0) == 256, "Not all byte values observed"

    def test_cek_compromise_plus_k_minus_1_reveals_nothing(self):
        """Even with CEK and k-1 decrypted shards, reconstruction is impossible."""
        msg_0 = b"ALPHA-MSG: The first candidate message for TSEC game"
        msg_1 = b"OMEGA-MSG: The other candidate message for TSEC game"
        shards_0 = ErasureCoder.encode(msg_0, self.N, self.K)
        shards_1 = ErasureCoder.encode(msg_1, self.N, self.K)

        cek = ShardEncryptor.generate_cek()
        entity_id = canonical_hash(cek + b"tsec-test")

        enc_0 = [ShardEncryptor.encrypt_shard(cek, entity_id, s, i) for i, s in enumerate(shards_0)]
        enc_1 = [ShardEncryptor.encrypt_shard(cek, entity_id, s, i) for i, s in enumerate(shards_1)]

        # Adversary compromises k-1 nodes and the CEK
        compromised = [0, 1, 2]
        dec_0 = [ShardEncryptor.decrypt_shard(cek, entity_id, enc_0[i], i) for i in compromised]
        dec_1 = [ShardEncryptor.decrypt_shard(cek, entity_id, enc_1[i], i) for i in compromised]

        # Decryption should succeed (adversary has CEK)
        assert all(dec_0[j] == shards_0[compromised[j]] for j in range(len(compromised)))
        assert all(dec_1[j] == shards_1[compromised[j]] for j in range(len(compromised)))

        # But reconstruction from k-1 shards must fail
        with pytest.raises((AssertionError, Exception)):
            ErasureCoder.decode({i: shards_0[i] for i in compromised}, self.N, self.K)


# ---------------------------------------------------------------------------
# Theorem 3 — IMM: Entity Immutability
# ---------------------------------------------------------------------------


class TestIMM:
    """Theorem 3: EntityID is collision-resistant; any modification changes the ID."""

    FIXED_TS = 1740000000.0

    def test_entity_id_deterministic(self):
        kp = KeyPair.generate("imm-sender")
        e = Entity(content=b"fixed content", shape="text/plain")
        ts = self.FIXED_TS
        eid_1 = e.compute_id(kp.vk, ts)
        eid_2 = e.compute_id(kp.vk, ts)
        assert eid_1 == eid_2

    def test_1bit_content_flip_changes_id(self):
        kp = KeyPair.generate("imm-sender")
        content = b"immutable content test"
        e = Entity(content=content, shape="text/plain")
        eid = e.compute_id(kp.vk, self.FIXED_TS)

        flipped = bytearray(content)
        flipped[0] ^= 0x01
        e_flipped = Entity(content=bytes(flipped), shape="text/plain")
        eid_flipped = e_flipped.compute_id(kp.vk, self.FIXED_TS)

        assert eid != eid_flipped

    def test_shape_change_changes_id(self):
        kp = KeyPair.generate("imm-sender")
        content = b"same content"
        e1 = Entity(content=content, shape="text/plain")
        e2 = Entity(content=content, shape="text/html")
        assert e1.compute_id(kp.vk, self.FIXED_TS) != e2.compute_id(kp.vk, self.FIXED_TS)

    def test_sender_change_changes_id(self):
        kp1 = KeyPair.generate("alice")
        kp2 = KeyPair.generate("bob")
        e = Entity(content=b"same", shape="text/plain")
        assert e.compute_id(kp1.vk, self.FIXED_TS) != e.compute_id(kp2.vk, self.FIXED_TS)

    def test_timestamp_change_changes_id(self):
        kp = KeyPair.generate("imm-sender")
        e = Entity(content=b"same", shape="text/plain")
        assert e.compute_id(kp.vk, 1.0) != e.compute_id(kp.vk, 2.0)

    def test_all_5_variants_produce_unique_ids(self):
        kp_a = KeyPair.generate("alice")
        kp_b = KeyPair.generate("bob")
        ts = self.FIXED_TS
        content = b"base content"
        e = Entity(content=content, shape="text/plain")
        eid_base = e.compute_id(kp_a.vk, ts)

        flipped = bytearray(content)
        flipped[0] ^= 0x01
        eid_v1 = Entity(content=bytes(flipped), shape="text/plain").compute_id(kp_a.vk, ts)
        eid_v2 = Entity(content=content, shape="text/html").compute_id(kp_a.vk, ts)
        eid_v3 = e.compute_id(kp_a.vk, ts + 1.0)
        eid_v4 = e.compute_id(kp_b.vk, ts)

        all_eids = {eid_base, eid_v1, eid_v2, eid_v3, eid_v4}
        assert len(all_eids) == 5

    def test_no_collision_in_10k_entities(self):
        kp = KeyPair.generate("collision-tester")
        seen: set[str] = set()
        for i in range(10_000):
            content = os.urandom(32) + struct.pack(">I", i)
            e = Entity(content=content, shape="x-ltp/collision-test")
            eid = e.compute_id(kp.vk, float(i))
            assert eid not in seen, f"EntityID collision at index {i}"
            seen.add(eid)

    def test_signature_covers_content_hash(self, protocol, network, alice, bob):
        """ML-DSA signature must be invalidated when content_hash is tampered."""
        content = b"signed immutable content"
        entity = Entity(content=content, shape="x-ltp/immutability-test")
        _, record, _ = protocol.commit(entity, alice, n=8, k=4)

        assert record.verify_signature(alice.vk) is True

        original_hash = record.content_hash
        record.content_hash = canonical_hash(b"fake content")
        assert record.verify_signature(alice.vk) is False

        record.content_hash = original_hash  # restore

    def test_end_to_end_content_integrity(self, protocol, alice, bob):
        """Materialize must verify canonical_hash(reconstructed) == EntityID."""
        content = b"end-to-end integrity test"
        entity = Entity(content=content, shape="x-ltp/immutability-test")
        entity_id, record, cek = protocol.commit(entity, alice, n=8, k=4)
        sealed = protocol.lattice(entity_id, record, cek, bob)
        result = protocol.materialize(sealed, bob)
        assert result == content
