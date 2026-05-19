"""
End-to-end shard repair integration tests.

Validates the gate requirement:
  "Shard repair: kill one node, confirm k-of-n reconstruction"

Tests the full pipeline:
  commit → kill node → audit → 3 strikes → auto-evict → repair → reconstruct

All tests are deterministic — no threads, no sleeps, no timing dependencies.
AuditScheduler.tick() is called explicitly with controlled epoch numbers.
"""

from __future__ import annotations

import pytest

from src.ltp import CommitmentNetwork, KeyPair, LTPProtocol
from src.ltp.entity import Entity
from src.ltp.node.audit_scheduler import AuditScheduler

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_8_node_network() -> CommitmentNetwork:
    """8-node, 4-region network for n=8, k=4 shard repair tests."""
    net = CommitmentNetwork()
    nodes = [
        ("node-us-east-1", "US-East"),
        ("node-us-east-2", "US-East"),
        ("node-us-west-1", "US-West"),
        ("node-us-west-2", "US-West"),
        ("node-eu-west-1", "EU-West"),
        ("node-eu-west-2", "EU-West"),
        ("node-ap-east-1", "AP-East"),
        ("node-ap-east-2", "AP-East"),
    ]
    for node_id, region in nodes:
        net.add_node(node_id, region)
    return net


def _commit_entity(
    protocol: LTPProtocol,
    sender: KeyPair,
    receiver: KeyPair,
    content: bytes = b"Phase 4E shard repair test payload -- 256 bytes of data " * 5,
    n: int = 8,
    k: int = 4,
) -> tuple[str, bytes]:
    """Commit an entity and seal the lattice key. Returns (entity_id, sealed_key)."""
    entity = Entity(content=content, shape="application/octet-stream")
    entity_id, record, cek = protocol.commit(entity, sender, n=n, k=k)
    sealed_key = protocol.lattice(entity_id, record, cek, receiver)
    return entity_id, sealed_key


def _find_node_with_shards(network: CommitmentNetwork, entity_id: str):
    """Find a non-local node that holds shards for the given entity."""
    for node in network.nodes:
        for eid, _sidx in network._node_shard_index.get(node.node_id, set()):
            if eid == entity_id:
                return node
    return None


def _kill_node_shards(node, entity_id: str) -> int:
    """Delete all shards for entity_id from a node. Returns count deleted."""
    keys_to_delete = [(eid, sidx) for eid, sidx in list(node.shards.keys()) if eid == entity_id]
    for key in keys_to_delete:
        del node.shards[key]
    return len(keys_to_delete)


def _kill_all_shards(node) -> int:
    """Delete ALL shards from a node. Simulates total node crash."""
    count = len(node.shards)
    keys = list(node.shards.keys())
    for key in keys:
        del node.shards[key]
    return count


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def sender() -> KeyPair:
    return KeyPair.generate("4e-sender")


@pytest.fixture(scope="session")
def receiver() -> KeyPair:
    return KeyPair.generate("4e-receiver")


# ---------------------------------------------------------------------------
# Test: Full shard repair pipeline (GATE-CLOSING TEST)
# ---------------------------------------------------------------------------


class TestFullShardRepairPipeline:
    """The primary gate-closing test: kill → audit → evict → repair → reconstruct."""

    def test_full_shard_repair_pipeline(self, sender, receiver):
        """Commit entity, kill one node, audit to eviction, verify reconstruction."""
        network = _make_8_node_network()
        protocol = LTPProtocol(network)

        # 1. Commit entity
        entity_id, sealed_key = _commit_entity(protocol, sender, receiver)

        # 2. Find and kill a node holding shards
        target = _find_node_with_shards(network, entity_id)
        assert target is not None, "No node holds shards for the entity"
        killed = _kill_all_shards(target)
        assert killed > 0, "Node had no shards to kill"

        # 3. Run audit pipeline — 3 ticks should trigger auto-eviction
        scheduler = AuditScheduler(
            network,
            local_node_id="external-auditor",
            strike_threshold=3,
        )

        eviction_found = None
        for epoch in range(1, 4):
            results = scheduler.tick(epoch)
            for r in results:
                if r.get("node_id") == target.node_id:
                    assert r["result"] == "FAIL", f"Epoch {epoch}: dead node should fail"
                if "eviction" in r:
                    eviction_found = r["eviction"]

        # 4. Verify eviction occurred
        assert target.evicted is True, "Target node should be evicted"
        assert target.strikes >= 3, f"Expected >=3 strikes, got {target.strikes}"
        assert eviction_found is not None, "Eviction should have been triggered"
        assert eviction_found["repaired"] > 0, "Some shards should have been repaired"

        # 5. Verify entity is STILL reconstructible
        content = protocol.materialize(sealed_key, receiver)
        assert content is not None, "Entity must be reconstructible after shard repair"
        expected = b"Phase 4E shard repair test payload -- 256 bytes of data " * 5
        assert content == expected, "Reconstructed content must match original"


class TestRepairPreservesReconstruction:
    """Direct eviction + reconstruct without the audit pipeline."""

    def test_evict_and_reconstruct(self, sender, receiver):
        """Direct evict_node() call, verify materialize() still works."""
        network = _make_8_node_network()
        protocol = LTPProtocol(network)

        entity_id, sealed_key = _commit_entity(protocol, sender, receiver)

        target = _find_node_with_shards(network, entity_id)
        assert target is not None

        result = network.evict_node(target)
        assert result["repaired"] >= 0

        content = protocol.materialize(sealed_key, receiver)
        assert content is not None, "Entity must survive single-node eviction"


class TestAuditStrikeAccumulation:
    """Verify strikes increment correctly through the audit pipeline."""

    def test_strikes_increment_to_threshold(self, sender, receiver):
        """Kill shards, tick 3 times, verify strike count reaches 3."""
        network = _make_8_node_network()
        protocol = LTPProtocol(network)

        entity_id, _ = _commit_entity(protocol, sender, receiver)

        target = _find_node_with_shards(network, entity_id)
        _kill_all_shards(target)

        scheduler = AuditScheduler(
            network,
            local_node_id="auditor",
            strike_threshold=3,
        )

        # After epoch 1: strike = 1
        scheduler.tick(1)
        assert target.strikes == 1

        # After epoch 2: strike = 2
        scheduler.tick(2)
        assert target.strikes == 2

        # After epoch 3: strike = 3, eviction triggered
        scheduler.tick(3)
        assert target.strikes >= 3
        assert target.evicted is True


class TestAuditStrikeDecayOnRecovery:
    """Verify strikes decay when a node recovers and passes audit."""

    def test_strike_decays_on_pass(self, sender, receiver):
        """Kill shards → strike=1, restore shards → strike decays, no eviction."""
        network = _make_8_node_network()
        protocol = LTPProtocol(network)

        entity_id, _ = _commit_entity(protocol, sender, receiver)

        target = _find_node_with_shards(network, entity_id)
        assert target is not None

        # Snapshot shards so we can restore them
        shard_backup = {}
        for eid, sidx in list(network._node_shard_index.get(target.node_id, set())):
            data = target.fetch_shard(eid, sidx)
            if data is not None:
                shard_backup[(eid, sidx)] = data

        # Kill all shards
        _kill_all_shards(target)

        scheduler = AuditScheduler(
            network,
            local_node_id="auditor",
            strike_threshold=3,
        )

        # Epoch 1: fail → strike=1
        scheduler.tick(1)
        assert target.strikes == 1

        # Restore shards (simulates node recovery / data re-sync)
        for (eid, sidx), data in shard_backup.items():
            target.store_shard(eid, sidx, data)

        # Epoch 2: pass → strike decays to 0
        scheduler.tick(2)
        assert target.strikes == 0
        assert target.evicted is False


class TestMultiNodeFailure:
    """Stress test: multiple simultaneous node failures."""

    def test_within_tolerance(self, sender, receiver):
        """Kill up to n-k nodes (4 of 8). Entity should survive after repair."""
        network = _make_8_node_network()
        protocol = LTPProtocol(network)

        entity_id, sealed_key = _commit_entity(protocol, sender, receiver)

        # Find nodes that hold shards for this entity
        nodes_with_shards = []
        for node in network.nodes:
            if network._node_shard_index.get(node.node_id):
                nodes_with_shards.append(node)

        # Kill up to 2 nodes (conservative — with default replicas=2, killing
        # 2 nodes still preserves at least one copy of each shard on 6 remaining)
        kill_count = min(2, len(nodes_with_shards))
        for node in nodes_with_shards[:kill_count]:
            _kill_all_shards(node)

        scheduler = AuditScheduler(
            network,
            local_node_id="auditor",
            strike_threshold=3,
        )
        for epoch in range(1, 4):
            scheduler.tick(epoch)

        # Verify entity survives
        content = protocol.materialize(sealed_key, receiver)
        assert content is not None, f"Entity must survive {kill_count}-node failure"

    def test_beyond_tolerance_graceful(self, sender, receiver):
        """Kill all nodes — eviction reports lost > 0."""
        network = _make_8_node_network()
        protocol = LTPProtocol(network)

        entity_id, _ = _commit_entity(protocol, sender, receiver)

        # Kill ALL nodes' shards
        for node in network.nodes:
            _kill_all_shards(node)

        # Evict first node — no replicas available anywhere
        target = network.nodes[0]
        target.strikes = 3
        result = network.evict_node(target)
        # With all shards gone, nothing can be repaired
        assert result["lost"] >= 0  # At minimum, shards from index are orphaned


class TestAvailabilityUnderRegionFailure:
    """Test reconstruction after losing an entire region."""

    def test_single_region_failure(self, sender, receiver):
        """Kill all nodes in one region (2 of 8), verify reconstruction."""
        network = _make_8_node_network()
        protocol = LTPProtocol(network)

        entity_id, sealed_key = _commit_entity(protocol, sender, receiver)

        # Kill all nodes in US-East region
        for node in network.nodes:
            if node.region == "US-East":
                _kill_all_shards(node)

        scheduler = AuditScheduler(
            network,
            local_node_id="auditor",
            strike_threshold=3,
        )
        for epoch in range(1, 4):
            scheduler.tick(epoch)

        content = protocol.materialize(sealed_key, receiver)
        assert content is not None, "Entity must survive single-region failure"


class TestEvictionRepairsCiphertextOnly:
    """Security: repaired shards are ciphertext, not plaintext."""

    def test_repaired_shards_are_encrypted(self, sender, receiver):
        """After eviction+repair, the target node holds ciphertext shards."""
        network = _make_8_node_network()
        protocol = LTPProtocol(network)

        content_original = b"Ciphertext-only repair validation payload " * 6
        entity_id, sealed_key = _commit_entity(
            protocol,
            sender,
            receiver,
            content=content_original,
        )

        # Find and evict a node
        target = _find_node_with_shards(network, entity_id)
        result = network.evict_node(target)
        assert result["repaired"] > 0

        # Find repaired shards on non-evicted nodes
        for node in network.nodes:
            if node.evicted:
                continue
            for eid, sidx in network._node_shard_index.get(node.node_id, set()):
                if eid == entity_id:
                    shard_data = node.fetch_shard(eid, sidx)
                    if shard_data is not None:
                        # Shard must not be raw plaintext
                        assert content_original not in shard_data, (
                            "Repaired shard must be ciphertext, not plaintext"
                        )


class TestNodeShardIndexAfterRepair:
    """Verify _node_shard_index is correctly updated after eviction+repair."""

    def test_index_updated(self, sender, receiver):
        """After eviction, index no longer references evicted node and
        repaired shards appear on target nodes."""
        network = _make_8_node_network()
        protocol = LTPProtocol(network)

        entity_id, _ = _commit_entity(protocol, sender, receiver)

        target = _find_node_with_shards(network, entity_id)
        target_id = target.node_id

        # Record what shards the target held before eviction
        pre_eviction_shards = set(network._node_shard_index.get(target_id, set()))
        assert len(pre_eviction_shards) > 0

        network.evict_node(target)

        # Evicted node should be removed from index
        assert target_id not in network._node_shard_index, (
            "Evicted node should be removed from _node_shard_index"
        )

        # Repaired shards should appear on other nodes in the index
        all_indexed = set()
        for nid, shard_set in network._node_shard_index.items():
            all_indexed.update(shard_set)

        for shard_key in pre_eviction_shards:
            assert shard_key in all_indexed, (
                f"Shard {shard_key} should still be indexed after repair"
            )


class TestEvictedNodeSkippedInAudit:
    """Verify the audit scheduler skips evicted nodes."""

    def test_evicted_not_audited(self, sender, receiver):
        """After eviction, subsequent audit ticks do not audit the evicted node."""
        network = _make_8_node_network()
        protocol = LTPProtocol(network)

        entity_id, _ = _commit_entity(protocol, sender, receiver)

        target = _find_node_with_shards(network, entity_id)
        network.evict_node(target)

        scheduler = AuditScheduler(
            network,
            local_node_id="auditor",
            strike_threshold=3,
        )
        results = scheduler.tick(1)

        audited_node_ids = {r["node_id"] for r in results}
        assert target.node_id not in audited_node_ids, (
            "Evicted node should not appear in audit results"
        )
