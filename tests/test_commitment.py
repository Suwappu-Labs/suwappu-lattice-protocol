"""
Tests for CommitmentRecord, CommitmentLog, CommitmentNetwork, and audit protocol.
"""

import os

import pytest

from src.ltp.commitment import (
    AuditResult,
    CommitmentLog,
    CommitmentNetwork,
    CommitmentNode,
    CommitmentRecord,
)
from src.ltp.entity import Entity
from src.ltp.keypair import KeyPair
from src.ltp.primitives import canonical_hash

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_record(keypair: KeyPair) -> CommitmentRecord:
    entity_id = canonical_hash(os.urandom(32))
    record = CommitmentRecord(
        entity_id=entity_id,
        sender_id=keypair.label,
        shard_map_root=canonical_hash(b"root"),
        content_hash=canonical_hash(b"content"),
        encoding_params={
            "n": 8,
            "k": 4,
            "algorithm": "reed-solomon-gf256",
            "gf_poly": "0x11d",
            "eval": "vandermonde-powers-of-0x02",
        },
        shape="text/plain",
        shape_hash=canonical_hash(b"text/plain"),
        timestamp=1740000000.0,
    )
    record.sign(keypair.sk)
    return record


# ---------------------------------------------------------------------------
# CommitmentRecord
# ---------------------------------------------------------------------------


class TestCommitmentRecord:
    def test_sign_and_verify(self):
        kp = KeyPair.generate("alice")
        record = _make_record(kp)
        assert record.verify_signature(kp.vk) is True

    def test_wrong_vk_fails(self):
        kp1 = KeyPair.generate("alice")
        kp2 = KeyPair.generate("bob")
        record = _make_record(kp1)
        assert record.verify_signature(kp2.vk) is False

    def test_tamper_content_hash_breaks_sig(self):
        kp = KeyPair.generate("alice")
        record = _make_record(kp)
        record.content_hash = canonical_hash(b"different content")
        assert record.verify_signature(kp.vk) is False

    def test_tamper_entity_id_breaks_sig(self):
        kp = KeyPair.generate("alice")
        record = _make_record(kp)
        record.entity_id = canonical_hash(b"fake entity")
        assert record.verify_signature(kp.vk) is False

    def test_predecessor_excluded_from_signable_payload(self):
        """Setting predecessor after signing must NOT invalidate the signature."""
        kp = KeyPair.generate("alice")
        record = _make_record(kp)
        assert record.verify_signature(kp.vk)  # valid before predecessor set
        record.predecessor = "0" * 64
        assert record.verify_signature(kp.vk)  # still valid after predecessor set

    def test_empty_signature_fails(self):
        kp = KeyPair.generate("alice")
        record = _make_record(kp)
        record.signature = b""
        assert record.verify_signature(kp.vk) is False

    def test_to_dict_round_trip(self):
        kp = KeyPair.generate("alice")
        record = _make_record(kp)
        d = record.to_dict()
        assert d["entity_id"] == record.entity_id
        assert d["sender_id"] == record.sender_id
        assert "shape" in d


# ---------------------------------------------------------------------------
# CommitmentLog
# ---------------------------------------------------------------------------


class TestCommitmentLog:
    def test_append_and_fetch(self):
        log = CommitmentLog()
        kp = KeyPair.generate("sender")
        record = _make_record(kp)
        log.append(record)
        assert log.fetch(record.entity_id) is record

    def test_append_returns_hash(self):
        log = CommitmentLog()
        kp = KeyPair.generate("sender")
        record = _make_record(kp)
        ref = log.append(record)
        assert ref.startswith("sha3-256:")

    def test_duplicate_append_raises(self):
        log = CommitmentLog()
        kp = KeyPair.generate("sender")
        record = _make_record(kp)
        log.append(record)
        with pytest.raises(ValueError, match="already committed"):
            log.append(record)

    def test_chain_integrity_empty(self):
        log = CommitmentLog()
        ok, _ = log.verify_chain_integrity()
        assert ok is True

    def test_chain_integrity_multiple_records(self):
        log = CommitmentLog()
        kp = KeyPair.generate("sender")
        for _ in range(5):
            record = _make_record(kp)
            log.append(record)
        ok, idx = log.verify_chain_integrity()
        assert ok is True

    def test_tamper_breaks_chain(self):
        log = CommitmentLog()
        kp = KeyPair.generate("sender")
        records = []
        for _ in range(3):
            r = _make_record(kp)
            log.append(r)
            records.append(r)

        # Tamper with first record
        original_hash = records[0].content_hash
        prefix, hex_part = original_hash.split(":", 1)
        records[0].content_hash = prefix + ":" + hex(int(hex_part, 16) ^ 1)[2:].zfill(64)

        ok, break_idx = log.verify_chain_integrity()
        assert ok is False
        assert break_idx == 0

        # Restore
        records[0].content_hash = original_hash
        ok, _ = log.verify_chain_integrity()
        assert ok is True

    def test_inclusion_proof_valid(self):
        log = CommitmentLog()
        kp = KeyPair.generate("sender")
        record = _make_record(kp)
        log.append(record)
        proof = log.get_inclusion_proof(record.entity_id)
        assert proof is not None
        assert log.verify_inclusion(record.entity_id, proof) is True

    def test_inclusion_proof_unknown_entity(self):
        log = CommitmentLog()
        assert log.get_inclusion_proof("unknown-entity-id") is None

    def test_head_hash_updates(self):
        log = CommitmentLog()
        initial = log.head_hash
        kp = KeyPair.generate("sender")
        log.append(_make_record(kp))
        assert log.head_hash != initial

    def test_length_property(self):
        log = CommitmentLog()
        kp = KeyPair.generate("sender")
        assert log.length == 0
        log.append(_make_record(kp))
        assert log.length == 1
        log.append(_make_record(kp))
        assert log.length == 2


# ---------------------------------------------------------------------------
# CommitmentNetwork — shard distribution and retrieval
# ---------------------------------------------------------------------------


class TestCommitmentNetwork:
    def test_add_node(self, network):
        assert len(network.nodes) == 6

    def test_distribute_and_fetch(self, network):
        entity_id = canonical_hash(b"test-entity")
        shards = [os.urandom(64) for _ in range(8)]
        network.distribute_encrypted_shards(entity_id, shards)
        fetched = network.fetch_encrypted_shards(entity_id, 8, 4)
        assert len(fetched) >= 4

    def test_fetch_returns_at_most_requested(self, network):
        entity_id = canonical_hash(b"fetch-limit-test")
        shards = [os.urandom(64) for _ in range(8)]
        network.distribute_encrypted_shards(entity_id, shards)
        fetched = network.fetch_encrypted_shards(entity_id, 8, 4)
        # fetch_encrypted_shards fetches up to the k argument
        assert len(fetched) <= 8

    def test_placement_deterministic(self, network):
        entity_id = canonical_hash(b"stable-entity")
        p1 = network._placement(entity_id, 0)
        p2 = network._placement(entity_id, 0)
        assert [n.node_id for n in p1] == [n.node_id for n in p2]

    def test_evict_node(self, network, alice):
        """Evicting a node should trigger shard repair."""
        from src.ltp.protocol import LTPProtocol

        protocol = LTPProtocol(network)
        entity = Entity(content=b"repair test", shape="x-ltp/test")
        entity_id, record, cek = protocol.commit(entity, alice, n=8, k=4)

        target = network.nodes[0]
        result = network.evict_node(target)
        assert target.evicted is True
        assert result["evicted_node"] == target.node_id
        assert isinstance(result["repaired"], int)

    def test_active_node_count(self, network):
        assert network.active_node_count == 6
        network.nodes[0].evicted = True
        assert network.active_node_count == 5


# ---------------------------------------------------------------------------
# Audit protocol
# ---------------------------------------------------------------------------


class TestAuditProtocol:
    def test_audit_result_type(self, network, alice):
        from src.ltp.protocol import LTPProtocol

        protocol = LTPProtocol(network)
        entity = Entity(content=b"audit target", shape="x-ltp/test")
        protocol.commit(entity, alice, n=8, k=4)

        results = network.audit_all_nodes()
        assert all(isinstance(r, AuditResult) for r in results)

    def test_healthy_nodes_pass_audit(self, network, alice):
        from src.ltp.protocol import LTPProtocol

        protocol = LTPProtocol(network)
        entity = Entity(content=b"healthy test", shape="x-ltp/test")
        protocol.commit(entity, alice, n=8, k=4)

        results = network.audit_all_nodes()
        for r in results:
            assert r.result == "PASS"

    def test_degraded_node_fails_audit(self, network, alice):
        from src.ltp.protocol import LTPProtocol

        protocol = LTPProtocol(network)
        entity = Entity(content=b"degraded audit", shape="x-ltp/test")
        protocol.commit(entity, alice, n=8, k=4)

        # Pick a node that actually holds shards (placement is hash-dependent)
        target = max(network.nodes, key=lambda n: n.shard_count)
        assert target.shard_count > 0, "No node has shards after commit"

        # Forcibly delete all shards from that node
        for key in list(target.shards.keys()):
            target.remove_shard(key[0], key[1])

        result = network.audit_node(target)
        assert result.result == "FAIL"
        assert result.failed > 0

    def test_burst_audit_produces_more_challenges(self, network, alice):
        from src.ltp.protocol import LTPProtocol

        protocol = LTPProtocol(network)
        entity = Entity(content=b"burst audit", shape="x-ltp/test")
        protocol.commit(entity, alice, n=8, k=4)

        result_burst1 = network.audit_node(network.nodes[0], burst=1)
        result_burst4 = network.audit_node(network.nodes[0], burst=4)
        # With burst=4, challenged count should be ~4× higher
        assert result_burst4.challenged >= result_burst1.challenged * 3

    def test_audit_result_fields(self, network, alice):
        from src.ltp.protocol import LTPProtocol

        protocol = LTPProtocol(network)
        entity = Entity(content=b"field test", shape="x-ltp/test")
        protocol.commit(entity, alice, n=8, k=4)

        r = network.audit_node(network.nodes[0])
        assert hasattr(r, "node_id")
        assert hasattr(r, "challenged")
        assert hasattr(r, "passed")
        assert hasattr(r, "failed")
        assert hasattr(r, "missing")
        assert hasattr(r, "result")
        assert hasattr(r, "strikes")
        assert hasattr(r, "avg_response_us")


# ---------------------------------------------------------------------------
# Correlated failure
# ---------------------------------------------------------------------------


class TestCorrelatedFailure:
    def test_region_failure_and_restore(self, network):
        affected = network.region_failure("US-East")
        assert all(n.evicted for n in affected)
        restored = network.restore_region("US-East")
        assert all(not n.evicted for n in restored)

    def test_availability_under_region_failure(self, network, alice):
        from src.ltp.protocol import LTPProtocol

        protocol = LTPProtocol(network)
        entity = Entity(content=b"regional failure test", shape="x-ltp/test")
        entity_id, record, _ = protocol.commit(entity, alice, n=8, k=4)

        regions = sorted(set(nd.region for nd in network.nodes))
        for region in regions:
            avail = network.availability_under_region_failure(entity_id, 8, 4, region)
            assert avail["can_reconstruct"] is True, (
                f"Entity cannot be reconstructed after {region} failure"
            )

    def test_cross_region_placement(self, network, alice):
        from src.ltp.protocol import LTPProtocol

        protocol = LTPProtocol(network)
        entity = Entity(content=b"placement test", shape="x-ltp/test")
        entity_id, record, _ = protocol.commit(entity, alice, n=8, k=4)

        placement = network.check_cross_region_placement(entity_id, 8)
        assert "regions_used" in placement
        assert len(placement["regions_used"]) > 1


# ---------------------------------------------------------------------------
# TTL-Based Shard Eviction (Whitepaper §5.4.4)
# ---------------------------------------------------------------------------


class TestShardTTL:
    """Tests for shard TTL, expiry, and renewal mechanisms."""

    def test_store_with_ttl(self):
        node = CommitmentNode("node-1", "us-east")
        assert node.store_shard_with_ttl("e1", 0, b"data", stored_at_epoch=10, ttl_epochs=100)
        assert node.fetch_shard("e1", 0) == b"data"

    def test_shard_not_expired_before_ttl(self):
        node = CommitmentNode("node-1", "us-east")
        node.store_shard_with_ttl("e1", 0, b"data", stored_at_epoch=10, ttl_epochs=100)
        assert not node.is_shard_expired("e1", 0, current_epoch=50)
        assert not node.is_shard_expired("e1", 0, current_epoch=109)

    def test_shard_expired_at_ttl(self):
        node = CommitmentNode("node-1", "us-east")
        node.store_shard_with_ttl("e1", 0, b"data", stored_at_epoch=10, ttl_epochs=100)
        assert node.is_shard_expired("e1", 0, current_epoch=110)
        assert node.is_shard_expired("e1", 0, current_epoch=200)

    def test_permanent_shard_never_expires(self):
        node = CommitmentNode("node-1", "us-east")
        node.store_shard_with_ttl("e1", 0, b"data", stored_at_epoch=10, ttl_epochs=None)
        assert not node.is_shard_expired("e1", 0, current_epoch=999_999)

    def test_no_ttl_metadata_never_expires(self):
        node = CommitmentNode("node-1", "us-east")
        node.store_shard("e1", 0, b"data")  # No TTL
        assert not node.is_shard_expired("e1", 0, current_epoch=999_999)

    def test_evict_expired_shards(self):
        node = CommitmentNode("node-1", "us-east")
        node.store_shard_with_ttl("e1", 0, b"data1", stored_at_epoch=10, ttl_epochs=50)
        node.store_shard_with_ttl("e1", 1, b"data2", stored_at_epoch=10, ttl_epochs=200)
        node.store_shard_with_ttl("e2", 0, b"data3", stored_at_epoch=10, ttl_epochs=50)

        evicted = node.evict_expired_shards(current_epoch=61)
        assert evicted == 2  # e1:0 and e2:0 expired
        assert node.fetch_shard("e1", 0) is None
        assert node.fetch_shard("e1", 1) == b"data2"
        assert node.fetch_shard("e2", 0) is None

    def test_renew_shard_ttl(self):
        node = CommitmentNode("node-1", "us-east")
        node.store_shard_with_ttl("e1", 0, b"data", stored_at_epoch=10, ttl_epochs=100)

        assert node.renew_shard_ttl("e1", 0, additional_epochs=50)
        # Was 10+100=110, now 10+150=160
        assert not node.is_shard_expired("e1", 0, current_epoch=150)
        assert node.is_shard_expired("e1", 0, current_epoch=160)

    def test_renew_nonexistent_shard_fails(self):
        node = CommitmentNode("node-1", "us-east")
        assert not node.renew_shard_ttl("e1", 0, additional_epochs=50)

    def test_renew_permanent_shard_noop(self):
        node = CommitmentNode("node-1", "us-east")
        node.store_shard_with_ttl("e1", 0, b"data", stored_at_epoch=10, ttl_epochs=None)
        assert node.renew_shard_ttl("e1", 0, additional_epochs=50)
        assert not node.is_shard_expired("e1", 0, current_epoch=999_999)

    def test_network_evict_expired(self):
        network = CommitmentNetwork()
        network.add_node("n1", "us-east")
        network.add_node("n2", "us-west")

        shards = [b"shard-0", b"shard-1", b"shard-2", b"shard-3"]
        network.distribute_encrypted_shards_with_ttl(
            "entity-1",
            shards,
            epoch=10,
            ttl_epochs=100,
            replicas=2,
        )

        result = network.evict_expired_shards(current_epoch=50)
        assert result["total_evicted"] == 0

        result = network.evict_expired_shards(current_epoch=110)
        assert result["total_evicted"] > 0
        assert result["entities_affected"] == 1

    def test_network_renew_entity_ttl(self):
        network = CommitmentNetwork()
        network.add_node("n1", "us-east")
        network.add_node("n2", "us-west")

        shards = [b"shard-0", b"shard-1"]
        network.distribute_encrypted_shards_with_ttl(
            "entity-1",
            shards,
            epoch=10,
            ttl_epochs=100,
            replicas=2,
        )

        renewed = network.renew_entity_ttl("entity-1", additional_epochs=100)
        assert renewed > 0

        # Should not be expired at 110 anymore (renewed to 210)
        result = network.evict_expired_shards(current_epoch=110)
        assert result["total_evicted"] == 0

    def test_commitment_record_ttl_field(self):
        record = CommitmentRecord(
            entity_id="e1",
            sender_id="s1",
            shard_map_root="root",
            content_hash="hash",
            encoding_params={"n": 8, "k": 4},
            shape="text/plain",
            shape_hash="sh",
            timestamp=1.0,
            ttl_epochs=720,
        )
        assert record.ttl_epochs == 720

    def test_commitment_record_default_permanent(self):
        record = CommitmentRecord(
            entity_id="e1",
            sender_id="s1",
            shard_map_root="root",
            content_hash="hash",
            encoding_params={"n": 8, "k": 4},
            shape="text/plain",
            shape_hash="sh",
            timestamp=1.0,
        )
        assert record.ttl_epochs is None

    def test_evicted_node_rejects_ttl_store(self):
        node = CommitmentNode("node-1", "us-east")
        node.evicted = True
        assert not node.store_shard_with_ttl("e1", 0, b"data", 10, 100)
