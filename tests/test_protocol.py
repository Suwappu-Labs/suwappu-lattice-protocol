"""
Integration tests for the three-phase LTP protocol.

Covers:
  - Transfer scenarios (small, JSON, large)
  - Unauthorized receiver blocked
  - Node stores only ciphertext
  - Degraded materialization (any k-of-n)
  - Regional failure resilience
"""

import json
import os

import pytest

from src.ltp import Entity, LTPProtocol

# ---------------------------------------------------------------------------
# Three-phase transfer scenarios
# ---------------------------------------------------------------------------


class TestTransfers:
    def test_transfer_small_message(self, protocol, alice, bob):
        content = b"Hello, this is a secure immutable transfer via LTP!"
        entity = Entity(content=content, shape="text/plain")

        entity_id, record, cek = protocol.commit(entity, alice, n=8, k=4)
        sealed = protocol.lattice(
            entity_id,
            record,
            cek,
            bob,
            access_policy={"type": "one-time"},
        )
        result = protocol.materialize(sealed, bob)

        assert result == content

    def test_transfer_json_document(self, protocol, alice, bob):
        content = json.dumps(
            {
                "patient_id": "P-29381",
                "diagnosis": "healthy",
                "lab_results": {"blood_pressure": "120/80", "heart_rate": 72},
            },
            indent=2,
        ).encode()
        entity = Entity(content=content, shape="application/json")

        entity_id, record, cek = protocol.commit(entity, alice, n=8, k=4)
        sealed = protocol.lattice(entity_id, record, cek, bob)
        result = protocol.materialize(sealed, bob)

        assert result == content

    def test_transfer_large_payload(self, protocol, alice, bob):
        content = os.urandom(100_000)
        entity = Entity(content=content, shape="application/octet-stream")

        entity_id, record, cek = protocol.commit(entity, alice, n=8, k=4)
        sealed = protocol.lattice(entity_id, record, cek, bob)
        result = protocol.materialize(sealed, bob)

        assert result == content

    def test_commit_returns_entity_id_and_cek(self, protocol, alice):
        entity = Entity(content=b"test", shape="text/plain")
        entity_id, record, cek = protocol.commit(entity, alice)

        assert entity_id.startswith("sha3-256:")
        assert isinstance(cek, bytes)
        assert len(cek) == 32
        assert record.entity_id == entity_id

    def test_lattice_returns_sealed_bytes(self, protocol, alice, bob):
        entity = Entity(content=b"test", shape="text/plain")
        entity_id, record, cek = protocol.commit(entity, alice)
        sealed = protocol.lattice(entity_id, record, cek, bob)

        assert isinstance(sealed, bytes)
        assert len(sealed) > 1000  # ML-KEM overhead alone is 1088B


# ---------------------------------------------------------------------------
# Security: unauthorized receiver
# ---------------------------------------------------------------------------


class TestUnauthorizedReceiver:
    def test_wrong_receiver_cannot_materialize(self, protocol, alice, bob, eve):
        content = b"confidential"
        entity = Entity(content=content, shape="text/plain")
        entity_id, record, cek = protocol.commit(entity, alice)
        sealed = protocol.lattice(entity_id, record, cek, bob)

        result = protocol.materialize(sealed, eve)
        assert result is None

    def test_correct_receiver_can_materialize(self, protocol, alice, bob, eve):
        content = b"for bob only"
        entity = Entity(content=content, shape="text/plain")
        entity_id, record, cek = protocol.commit(entity, alice)
        sealed = protocol.lattice(entity_id, record, cek, bob)

        assert protocol.materialize(sealed, bob) == content
        assert protocol.materialize(sealed, eve) is None

    def test_nodes_store_only_ciphertext(self, protocol, network, alice, bob):
        content = b"secret content"
        entity = Entity(content=content, shape="text/plain")
        entity_id, record, cek = protocol.commit(entity, alice)

        # Fetch raw encrypted shards from the network
        encrypted_shards = network.fetch_encrypted_shards(entity_id, 8, 4)
        assert len(encrypted_shards) >= 4

        # Verify shards are not plaintext
        for shard in encrypted_shards.values():
            assert shard != content
            # Ciphertext should not contain the content as a substring
            assert content not in shard


# ---------------------------------------------------------------------------
# Degraded materialization (availability guarantee)
# ---------------------------------------------------------------------------


class TestDegradedMaterialization:
    def test_reconstruct_from_non_sequential_shards(self, protocol, network, alice, bob):
        content = b"any k-of-n shards work"
        entity = Entity(content=content, shape="x-ltp/test")
        entity_id, record, cek = protocol.commit(entity, alice, n=8, k=4)

        # Destroy first 3 shards across all replicas
        for idx in [0, 1, 2]:
            for node in network._placement(entity_id, idx):
                if not node.evicted:
                    node.remove_shard(entity_id, idx)

        sealed = protocol.lattice(entity_id, record, cek, bob)
        result = protocol.materialize(sealed, bob)
        assert result == content

    def test_reconstruct_at_k_boundary(self, protocol, network, alice, bob):
        content = b"exactly k shards remaining"
        entity = Entity(content=content, shape="x-ltp/test")
        entity_id, record, cek = protocol.commit(entity, alice, n=8, k=4)

        # Destroy shards 0–3 (leaving exactly 4 = k)
        for idx in [0, 1, 2, 3]:
            for node in network._placement(entity_id, idx):
                if not node.evicted:
                    node.remove_shard(entity_id, idx)

        sealed = protocol.lattice(entity_id, record, cek, bob)
        result = protocol.materialize(sealed, bob)
        assert result == content

    def test_below_k_threshold_fails_gracefully(self, protocol, network, alice, bob):
        content = b"below threshold test"
        entity = Entity(content=content, shape="x-ltp/test")
        entity_id, record, cek = protocol.commit(entity, alice, n=8, k=4)

        # Destroy shards 0–4 (leaving only 3 < k=4)
        for idx in range(5):
            for node in network._placement(entity_id, idx):
                if not node.evicted:
                    node.remove_shard(entity_id, idx)

        sealed = protocol.lattice(entity_id, record, cek, bob)
        result = protocol.materialize(sealed, bob)
        assert result is None


# ---------------------------------------------------------------------------
# Regional failure resilience
# ---------------------------------------------------------------------------


class TestRegionalFailure:
    def test_survives_single_region_failure(self, protocol, network, alice, bob):
        content = b"survives regional outage"
        entity = Entity(content=content, shape="x-ltp/test")
        entity_id, record, cek = protocol.commit(entity, alice, n=8, k=4)

        # Verify each region failure individually leaves enough shards
        regions = sorted(set(nd.region for nd in network.nodes))
        for region in regions:
            avail = network.availability_under_region_failure(entity_id, 8, 4, region)
            assert avail["can_reconstruct"] is True, f"Cannot reconstruct after {region} failure"

    def test_live_region_failure_materialization(self, protocol, network, alice, bob):
        content = b"live failure test"
        entity = Entity(content=content, shape="x-ltp/test")
        entity_id, record, cek = protocol.commit(entity, alice, n=8, k=4)

        # Take a region offline
        affected = network.region_failure("US-East")
        assert len(affected) > 0

        # Shard fetch should still succeed
        shards = network.fetch_encrypted_shards(entity_id, 8, 4)
        assert len(shards) >= 4

        # Restore region
        network.restore_region("US-East")
