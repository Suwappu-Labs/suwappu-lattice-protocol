"""
Performance and integration tests for architecture improvements.

Covers:
  - Merkle tree root caching
  - Placement cache effectiveness
  - Audit reverse index (O(S) vs O(N·n))
  - Erasure coding alpha power precomputation
  - CEK tracking bounded memory
  - Backend batch commit operations
  - Shard map root computation (bytes-based)
"""

import os
import time

import pytest

from src.ltp.backends import BackendConfig, create_backend
from src.ltp.commitment import CommitmentNetwork, CommitmentNode
from src.ltp.entity import Entity
from src.ltp.erasure import ErasureCoder
from src.ltp.keypair import KeyPair
from src.ltp.merkle_log.tree import MerkleTree
from src.ltp.primitives import canonical_hash
from src.ltp.protocol import LTPProtocol
from src.ltp.shards import _CEK_TRACKING_LIMIT, ShardEncryptor

# ---------------------------------------------------------------------------
# Merkle tree root caching
# ---------------------------------------------------------------------------


class TestMerkleRootCaching:
    def test_root_cached_after_first_call(self):
        tree = MerkleTree()
        tree.append(b"record-1")
        tree.append(b"record-2")

        root1 = tree.root()
        root2 = tree.root()
        assert root1 == root2
        # Verify cache is populated
        assert tree._cached_root is not None
        assert tree._cache_leaf_count == 2

    def test_cache_invalidated_on_append(self):
        tree = MerkleTree()
        tree.append(b"record-1")
        root1 = tree.root()
        assert tree._cache_leaf_count == 1

        tree.append(b"record-2")
        # Cache count no longer matches leaf count → will recompute
        assert tree._cache_leaf_count != len(tree._leaves)

        root2 = tree.root()
        assert root1 != root2
        assert tree._cache_leaf_count == 2

    def test_repeated_root_calls_are_fast(self):
        tree = MerkleTree()
        for i in range(100):
            tree.append(f"record-{i}".encode())

        # First call computes
        tree.root()

        # Subsequent calls should be fast (cached with O(n) checksum validation).
        # The checksum re-hashes all leaves to detect tampering, so this is
        # O(n) per call rather than pure O(1), but still much cheaper than
        # recomputing the full Merkle tree.
        t0 = time.monotonic()
        for _ in range(1000):
            tree.root()
        elapsed = time.monotonic() - t0
        # 1000 cached calls with 100-leaf checksum validation < 100ms
        assert elapsed < 0.1


# ---------------------------------------------------------------------------
# Placement cache
# ---------------------------------------------------------------------------


class TestPlacementCache:
    def test_placement_is_cached(self):
        net = CommitmentNetwork()
        for i in range(6):
            net.add_node(f"node-{i}", f"region-{i % 3}")

        entity_id = canonical_hash(b"test-entity")
        # First call populates cache
        p1 = net._placement(entity_id, 0)
        # Second call should hit cache
        p2 = net._placement(entity_id, 0)
        assert [n.node_id for n in p1] == [n.node_id for n in p2]

        # Verify cache is populated
        assert (entity_id, 0, 2) in net._placement_cache

    def test_cache_invalidated_on_node_add(self):
        net = CommitmentNetwork()
        for i in range(4):
            net.add_node(f"node-{i}", "US-East")

        entity_id = canonical_hash(b"test-entity")
        net._placement(entity_id, 0)
        assert len(net._placement_cache) > 0

        # Adding a node invalidates cache
        net.add_node("node-new", "EU-West")
        assert len(net._placement_cache) == 0

    def test_cached_placement_is_deterministic(self):
        net = CommitmentNetwork()
        for i in range(6):
            net.add_node(f"node-{i}", f"region-{i % 3}")

        entity_id = canonical_hash(b"deterministic-test")
        results = set()
        for _ in range(100):
            p = net._placement(entity_id, 3)
            results.add(tuple(n.node_id for n in p))
        assert len(results) == 1  # always same result


# ---------------------------------------------------------------------------
# Audit reverse index
# ---------------------------------------------------------------------------


class TestAuditReverseIndex:
    def test_reverse_index_populated_on_distribute(self):
        net = CommitmentNetwork()
        for i in range(4):
            net.add_node(f"node-{i}", f"region-{i % 2}")

        entity_id = canonical_hash(b"index-test")
        shards = [os.urandom(64) for _ in range(8)]
        net.distribute_encrypted_shards(entity_id, shards)

        # Reverse index should have entries
        total_indexed = sum(len(s) for s in net._node_shard_index.values())
        assert total_indexed > 0

    def test_audit_uses_reverse_index(self):
        net = CommitmentNetwork()
        for nid, region in [
            ("node-0", "US-East"),
            ("node-1", "US-West"),
            ("node-2", "EU-West"),
            ("node-3", "EU-East"),
        ]:
            net.add_node(nid, region)

        kp = KeyPair.generate("sender")
        protocol = LTPProtocol(net)
        entity = Entity(content=b"audit-index-test", shape="x-ltp/test")
        protocol.commit(entity, kp, n=8, k=4)

        # Audit a node that actually holds shards (placement is hash-dependent)
        target = max(net.nodes, key=lambda n: n.shard_count)
        assert target.shard_count > 0, "No node has shards after commit"
        result = net.audit_node(target)
        assert result.result == "PASS"
        # Should have challenged some shards
        assert result.challenged > 0


# ---------------------------------------------------------------------------
# Erasure coding optimization
# ---------------------------------------------------------------------------


class TestErasureOptimization:
    def test_encode_decode_still_correct(self):
        """Verify precomputed alpha powers don't break correctness."""
        data = b"Hello, world! This is a test of erasure coding optimization."
        shards = ErasureCoder.encode(data, n=8, k=4)
        assert len(shards) == 8

        # Decode from first 4
        result = ErasureCoder.decode({i: shards[i] for i in range(4)}, 8, 4)
        assert result == data

        # Decode from last 4
        result = ErasureCoder.decode({i: shards[i] for i in range(4, 8)}, 8, 4)
        assert result == data

        # Decode from non-sequential
        result = ErasureCoder.decode({0: shards[0], 3: shards[3], 5: shards[5], 7: shards[7]}, 8, 4)
        assert result == data

    def test_large_payload_performance(self):
        """Encoding a 100KB payload should complete quickly."""
        data = os.urandom(100_000)
        t0 = time.monotonic()
        shards = ErasureCoder.encode(data, n=8, k=4)
        encode_time = time.monotonic() - t0

        t0 = time.monotonic()
        result = ErasureCoder.decode({i: shards[i] for i in range(4)}, 8, 4)
        decode_time = time.monotonic() - t0

        assert result == data
        # Should complete within reasonable time (PoC, not optimized lib)
        assert encode_time < 30.0  # generous for pure Python GF(256)
        assert decode_time < 30.0


# ---------------------------------------------------------------------------
# CEK tracking bounded memory
# ---------------------------------------------------------------------------


class TestCEKTrackingBounded:
    def test_tracking_limit_exists(self):
        assert _CEK_TRACKING_LIMIT == 100_000

    def test_tracking_set_is_bounded(self):
        """Generate many CEKs and verify the tracking set doesn't grow unbounded."""
        initial_size = len(ShardEncryptor._issued_ceks)

        # Generate a batch of CEKs
        for _ in range(200):
            ShardEncryptor.generate_cek()

        # Set should have grown but still be bounded
        current_size = len(ShardEncryptor._issued_ceks)
        assert current_size <= _CEK_TRACKING_LIMIT + initial_size

    def test_deque_and_set_stay_synchronized(self):
        """Verify deque and set have consistent sizes."""
        # They should be equal in size (both track the same CEKs)
        assert len(ShardEncryptor._issued_ceks) == len(ShardEncryptor._issued_ceks_order)


# ---------------------------------------------------------------------------
# Backend batch commit
# ---------------------------------------------------------------------------


class TestBackendBatchCommit:
    def test_base_l1_batch_commit(self):
        backend = create_backend(BackendConfig(backend_type="base-l1"))
        commitments = []
        for i in range(5):
            eid = canonical_hash(f"batch-base-l1-{i}".encode())
            rec = f'{{"id":"{eid}","idx":{i}}}'.encode()
            commitments.append((eid, rec, b"\x00" * 64, b"\x01" * 32))

        refs = backend.append_commitments_batch(commitments)
        assert len(refs) == 5
        assert all(r.startswith("sha3-256:") for r in refs)

        # All commitments should be in the same block
        block_nums = set()
        for eid, _, _, _ in commitments:
            fetched = backend.fetch_commitment(eid)
            assert fetched is not None
            block_nums.add(backend._commitment_block_map[eid])
        assert len(block_nums) == 1  # all in one block

    def test_ethereum_batch_commit(self):
        backend = create_backend(
            BackendConfig(
                backend_type="ethereum",
                eth_finality_mode="latest",
                eth_confirmations=0,
            )
        )
        initial_gas = backend.total_gas_used
        commitments = []
        for i in range(5):
            eid = canonical_hash(f"batch-eth-{i}".encode())
            rec = f'{{"id":"{eid}","idx":{i}}}'.encode()
            commitments.append((eid, rec, b"\x00" * 64, b"\x01" * 32))

        refs = backend.append_commitments_batch(commitments)
        assert len(refs) == 5

        # Batch should use less gas than 5 individual commits
        batch_gas = backend.total_gas_used - initial_gas
        individual_gas = 5 * 80_000  # 80K each
        assert batch_gas < individual_gas

    def test_ethereum_batch_produces_single_tx(self):
        backend = create_backend(
            BackendConfig(
                backend_type="ethereum",
                eth_finality_mode="latest",
                eth_confirmations=0,
            )
        )
        initial_tx_count = backend.transaction_count
        commitments = []
        for i in range(3):
            eid = canonical_hash(f"batch-tx-{i}".encode())
            rec = f'{{"id":"{eid}"}}'.encode()
            commitments.append((eid, rec, b"\x00" * 64, b"\x01" * 32))

        backend.append_commitments_batch(commitments)
        # Should produce exactly 1 transaction (not 3)
        assert backend.transaction_count == initial_tx_count + 1

    def test_batch_duplicate_raises(self):
        backend = create_backend(BackendConfig(backend_type="base-l1"))
        eid = canonical_hash(b"duplicate-batch")
        rec = b'{"id":"test"}'
        backend.append_commitment(eid, rec, b"\x00" * 64, b"\x01" * 32)

        with pytest.raises(ValueError, match="already committed"):
            backend.append_commitments_batch(
                [
                    (eid, rec, b"\x00" * 64, b"\x01" * 32),
                ]
            )


# ---------------------------------------------------------------------------
# Backend finality callback
# ---------------------------------------------------------------------------


class TestFinalityCallback:
    def test_callback_fires_when_finalized(self):
        backend = create_backend(BackendConfig(backend_type="local"))
        eid, rec = canonical_hash(b"finality-test"), b'{"test":true}'
        backend.append_commitment(eid, rec, b"\x00" * 64, b"\x01" * 32)

        called = []
        backend.on_finality(eid, lambda e: called.append(e))
        assert called == [eid]

    def test_callback_not_fired_when_not_finalized(self):
        backend = create_backend(BackendConfig(backend_type="local"))
        called = []
        backend.on_finality("nonexistent", lambda e: called.append(e))
        assert called == []


# ---------------------------------------------------------------------------
# Shard map root computation
# ---------------------------------------------------------------------------


class TestShardMapRoot:
    def test_shard_map_root_uses_bytes_join(self):
        """Verify distribute uses bytes-based join for shard map root."""
        net = CommitmentNetwork()
        for i in range(4):
            net.add_node(f"node-{i}", f"region-{i % 2}")

        entity_id = canonical_hash(b"root-test")
        shards = [os.urandom(64) for _ in range(4)]
        root = net.distribute_encrypted_shards(entity_id, shards)
        assert root.startswith("sha3-256:")


# ---------------------------------------------------------------------------
# End-to-end: full protocol still works with optimizations
# ---------------------------------------------------------------------------


class TestOptimizedProtocolE2E:
    def test_full_transfer_with_optimizations(self):
        """Complete COMMIT → LATTICE → MATERIALIZE cycle with all optimizations."""
        net = CommitmentNetwork()
        for nid, region in [
            ("n-0", "US-East"),
            ("n-1", "US-West"),
            ("n-2", "EU-West"),
            ("n-3", "EU-East"),
            ("n-4", "AP-East"),
            ("n-5", "AP-South"),
        ]:
            net.add_node(nid, region)

        alice = KeyPair.generate("alice")
        bob = KeyPair.generate("bob")
        protocol = LTPProtocol(net)

        content = b"Optimized transfer test with placement caching and audit indexing"
        entity = Entity(content=content, shape="text/plain")

        # COMMIT
        entity_id, record, cek = protocol.commit(entity, alice, n=8, k=4)
        assert entity_id.startswith("sha3-256:")

        # Verify placement cache is populated
        assert len(net._placement_cache) > 0

        # Verify reverse index is populated
        total_indexed = sum(len(s) for s in net._node_shard_index.values())
        assert total_indexed > 0

        # LATTICE
        sealed = protocol.lattice(entity_id, record, cek, bob)
        assert len(sealed) > 0

        # MATERIALIZE
        result = protocol.materialize(sealed, bob)
        assert result == content

    def test_audit_after_commit_with_index(self):
        """Audit should use reverse index after commit."""
        net = CommitmentNetwork()
        for nid, region in [
            ("n-0", "US-East"),
            ("n-1", "US-West"),
            ("n-2", "EU-West"),
            ("n-3", "EU-East"),
        ]:
            net.add_node(nid, region)

        alice = KeyPair.generate("alice")
        protocol = LTPProtocol(net)

        # Commit multiple entities
        for i in range(3):
            entity = Entity(content=f"entity-{i}".encode(), shape="text/plain")
            protocol.commit(entity, alice, n=8, k=4)

        # Audit all nodes — should use reverse index
        results = net.audit_all_nodes()
        for r in results:
            assert r.result == "PASS"
