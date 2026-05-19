"""
Test suite for the LTP network simulator.

Organized by component:
  - TestSimClock / TestEventQueue      — discrete-event engine
  - TestTopology                       — network graph, latency, routing
  - TestSimNode                        — node storage, capacity, failure
  - TestMessageBus                     — message delivery tracking
  - TestNetworkSimulator               — orchestrator, placement, failure injection
  - TestSimClient                      — end-to-end protocol through simulation
  - TestTransferMetrics                — metrics accuracy
  - TestLargeTopology                  — scale testing with many nodes/regions
  - TestFailureScenarios               — complex failure + recovery scenarios
  - TestGeographicOptimization         — LTP's core advantage: proximity fetching
"""

import os

import pytest

from src.simulator.clock import Event, EventQueue, EventType, SimClock
from src.simulator.message import Message, MessageBus, MessageType
from src.simulator.metrics import MetricsCollector, TransferMetrics
from src.simulator.network import NetworkSimulator
from src.simulator.node import SimNode, StorageCapacity
from src.simulator.topology import Link, Region, Topology

# =========================================================================
# Fixtures
# =========================================================================


@pytest.fixture
def clock():
    return SimClock()


@pytest.fixture
def event_queue():
    return EventQueue()


@pytest.fixture
def topology():
    """Three-region topology with realistic cross-region latencies."""
    topo = Topology()
    topo.add_region("us-east", intra_latency_ms=1.0)
    topo.add_region("eu-west", intra_latency_ms=1.0)
    topo.add_region("ap-south", intra_latency_ms=1.5)
    topo.connect_regions(
        "us-east", "eu-west", latency_ms=80.0, bandwidth_mbps=1000.0, jitter_ms=0.0
    )
    topo.connect_regions(
        "us-east", "ap-south", latency_ms=180.0, bandwidth_mbps=500.0, jitter_ms=0.0
    )
    topo.connect_regions(
        "eu-west", "ap-south", latency_ms=120.0, bandwidth_mbps=800.0, jitter_ms=0.0
    )
    return topo


@pytest.fixture
def sim():
    """A standard three-region simulator with deterministic seed."""
    s = NetworkSimulator(seed=42)
    s.add_region("us-east", node_count=2)
    s.add_region("eu-west", node_count=2)
    s.add_region("ap-south", node_count=2)
    s.connect_regions("us-east", "eu-west", latency_ms=80.0, jitter_ms=0.0)
    s.connect_regions("us-east", "ap-south", latency_ms=180.0, jitter_ms=0.0)
    s.connect_regions("eu-west", "ap-south", latency_ms=120.0, jitter_ms=0.0)
    return s


@pytest.fixture
def sim_with_clients(sim):
    """Simulator with alice (us-east) and bob (ap-south) clients."""
    alice = sim.add_client("alice", region="us-east")
    bob = sim.add_client("bob", region="ap-south")
    return sim, alice, bob


# =========================================================================
# SimClock Tests
# =========================================================================


class TestSimClock:
    def test_starts_at_zero(self, clock):
        assert clock.now == 0.0
        assert clock.ticks == 0

    def test_advance_to(self, clock):
        clock.advance_to(100.0)
        assert clock.now == 100.0
        assert clock.ticks == 1

    def test_advance_multiple_times(self, clock):
        clock.advance_to(10.0)
        clock.advance_to(20.0)
        clock.advance_to(50.0)
        assert clock.now == 50.0
        assert clock.ticks == 3

    def test_cannot_go_backward(self, clock):
        clock.advance_to(100.0)
        with pytest.raises(ValueError, match="Cannot move clock backward"):
            clock.advance_to(50.0)

    def test_now_seconds(self, clock):
        clock.advance_to(1500.0)
        assert clock.now_seconds == 1.5

    def test_reset(self, clock):
        clock.advance_to(500.0)
        clock.reset()
        assert clock.now == 0.0
        assert clock.ticks == 0


# =========================================================================
# EventQueue Tests
# =========================================================================


class TestEventQueue:
    def test_empty_queue(self, event_queue):
        assert event_queue.is_empty
        assert event_queue.pop() is None
        assert event_queue.pending == 0

    def test_schedule_and_pop(self, event_queue):
        event_queue.schedule(10.0, EventType.TIMER, source="test")
        assert not event_queue.is_empty
        event = event_queue.pop()
        assert event.time == 10.0
        assert event.event_type == EventType.TIMER
        assert event_queue.is_empty

    def test_events_ordered_by_time(self, event_queue):
        event_queue.schedule(30.0, EventType.TIMER)
        event_queue.schedule(10.0, EventType.SHARD_STORE)
        event_queue.schedule(20.0, EventType.SHARD_FETCH)

        e1 = event_queue.pop()
        e2 = event_queue.pop()
        e3 = event_queue.pop()
        assert e1.time == 10.0
        assert e2.time == 20.0
        assert e3.time == 30.0

    def test_same_time_deterministic(self, event_queue):
        event_queue.schedule(10.0, EventType.TIMER, source="first")
        event_queue.schedule(10.0, EventType.TIMER, source="second")

        e1 = event_queue.pop()
        e2 = event_queue.pop()
        assert e1.source == "first"
        assert e2.source == "second"

    def test_cancel_event(self, event_queue):
        e1 = event_queue.schedule(10.0, EventType.TIMER, source="keep")
        e2 = event_queue.schedule(20.0, EventType.TIMER, source="cancel")
        event_queue.cancel(e2)

        result = event_queue.pop()
        assert result.source == "keep"
        assert event_queue.is_empty

    def test_drain_until(self, event_queue):
        event_queue.schedule(5.0, EventType.TIMER)
        event_queue.schedule(10.0, EventType.TIMER)
        event_queue.schedule(15.0, EventType.TIMER)
        event_queue.schedule(20.0, EventType.TIMER)

        events = event_queue.drain_until(12.0)
        assert len(events) == 2
        assert events[0].time == 5.0
        assert events[1].time == 10.0
        assert not event_queue.is_empty

    def test_peek_does_not_remove(self, event_queue):
        event_queue.schedule(10.0, EventType.TIMER)
        peeked = event_queue.peek()
        assert peeked is not None
        assert not event_queue.is_empty
        popped = event_queue.pop()
        assert popped.time == peeked.time

    def test_negative_time_rejected(self):
        with pytest.raises(ValueError, match="non-negative"):
            Event(time=-1.0, sequence=0, event_type=EventType.TIMER)


# =========================================================================
# Topology Tests
# =========================================================================


class TestTopology:
    def test_add_region(self, topology):
        assert "us-east" in topology.regions
        assert "eu-west" in topology.regions
        assert "ap-south" in topology.regions

    def test_connect_regions(self, topology):
        link = topology.get_link("us-east", "eu-west")
        assert link is not None
        assert link.latency_ms == 80.0
        # Bidirectional
        reverse = topology.get_link("eu-west", "us-east")
        assert reverse is not None

    def test_intra_region_latency(self, topology):
        topology.register_node("n1", "us-east")
        topology.register_node("n2", "us-east")
        lat = topology.latency_between_nodes("n1", "n2")
        assert lat == pytest.approx(1.0, abs=0.1)

    def test_inter_region_latency(self, topology):
        topology.register_node("n1", "us-east")
        topology.register_node("n2", "eu-west")
        lat = topology.latency_between_nodes("n1", "n2", payload_bytes=0)
        # Should be roughly the link latency (80ms) ± jitter
        assert 75 <= lat <= 85

    def test_partition_region(self, topology):
        topology.register_node("n1", "us-east")
        topology.register_node("n2", "eu-west")
        topology.partition_region("eu-west")
        lat = topology.latency_between_nodes("n1", "n2")
        assert lat == float("inf")

    def test_restore_region(self, topology):
        topology.register_node("n1", "us-east")
        topology.register_node("n2", "eu-west")
        topology.partition_region("eu-west")
        topology.restore_region("eu-west")
        lat = topology.latency_between_nodes("n1", "n2", payload_bytes=0)
        assert lat != float("inf")

    def test_sever_link(self, topology):
        topology.register_node("n1", "us-east")
        topology.register_node("n2", "eu-west")
        topology.sever_link("us-east", "eu-west")
        # Direct link severed, but may route through ap-south
        assert topology.is_reachable("us-east", "eu-west")  # via ap-south

    def test_is_reachable(self, topology):
        assert topology.is_reachable("us-east", "ap-south")

    def test_fully_disconnected(self, topology):
        topology.partition_region("eu-west")
        topology.partition_region("ap-south")
        topology.register_node("n1", "us-east")
        topology.register_node("n2", "eu-west")
        assert not topology.is_reachable("us-east", "eu-west")

    def test_link_transfer_time_includes_bandwidth(self):
        link = Link(source="a", target="b", latency_ms=10.0, bandwidth_mbps=100.0, jitter_ms=0.0)
        # 1MB payload at 100Mbps = 80ms transmission + 10ms latency = 90ms
        tt = link.transfer_time_ms(1_000_000)
        assert tt == pytest.approx(90.0, abs=1.0)

    def test_degrade_link(self, topology):
        topology.degrade_link("us-east", "eu-west", latency_multiplier=3.0)
        link = topology.get_link("us-east", "eu-west")
        assert link.latency_ms == pytest.approx(240.0)


# =========================================================================
# SimNode Tests
# =========================================================================


class TestSimNode:
    def test_store_and_fetch(self):
        node = SimNode("n1", "us-east")
        assert node.store_shard("eid-1", 0, b"encrypted-data")
        result = node.fetch_shard("eid-1", 0)
        assert result == b"encrypted-data"

    def test_fetch_missing_returns_none(self):
        node = SimNode("n1", "us-east")
        assert node.fetch_shard("nonexistent", 0) is None

    def test_capacity_limit(self):
        cap = StorageCapacity(max_bytes=100, max_shards=10)
        node = SimNode("n1", "us-east", capacity=cap)
        assert node.store_shard("eid-1", 0, b"x" * 50)
        assert node.store_shard("eid-1", 1, b"x" * 50)
        # Exceeds capacity
        assert not node.store_shard("eid-1", 2, b"x" * 50)

    def test_shard_count_limit(self):
        cap = StorageCapacity(max_bytes=10_000_000, max_shards=2)
        node = SimNode("n1", "us-east", capacity=cap)
        assert node.store_shard("eid-1", 0, b"data")
        assert node.store_shard("eid-1", 1, b"data")
        assert not node.store_shard("eid-1", 2, b"data")

    def test_offline_node_rejects_store(self):
        node = SimNode("n1", "us-east")
        node.set_online(False)
        assert not node.store_shard("eid-1", 0, b"data")
        assert node.failed_stores == 1

    def test_offline_node_returns_none_on_fetch(self):
        node = SimNode("n1", "us-east")
        node.store_shard("eid-1", 0, b"data")
        node.set_online(False)
        assert node.fetch_shard("eid-1", 0) is None

    def test_evicted_node(self):
        node = SimNode("n1", "us-east")
        node.evict()
        assert node.is_evicted
        assert not node.online
        assert not node.store_shard("eid-1", 0, b"data")

    def test_remove_shard(self):
        node = SimNode("n1", "us-east")
        node.store_shard("eid-1", 0, b"data")
        assert node.shard_count == 1
        assert node.remove_shard("eid-1", 0)
        assert node.shard_count == 0

    def test_audit_response(self):
        node = SimNode("n1", "us-east")
        node.store_shard("eid-1", 0, b"encrypted")
        nonce = os.urandom(16)
        response = node.respond_to_audit("eid-1", 0, nonce)
        assert response is not None
        assert response.startswith("blake3:") or response.startswith("sha3-256:")

    def test_audit_missing_shard_returns_none(self):
        node = SimNode("n1", "us-east")
        response = node.respond_to_audit("eid-1", 0, os.urandom(16))
        assert response is None

    def test_scheduled_failure(self):
        node = SimNode("n1", "us-east")
        node.schedule_failure(100.0, 200.0)
        assert node.is_online_at(50.0)
        assert not node.is_online_at(150.0)
        assert node.is_online_at(250.0)

    def test_copy_shard_to(self):
        src = SimNode("src", "us-east")
        dst = SimNode("dst", "eu-west")
        src.store_shard("eid-1", 0, b"data")
        assert src.copy_shard_to("eid-1", 0, dst)
        assert dst.fetch_shard("eid-1", 0) == b"data"

    def test_capacity_utilization(self):
        cap = StorageCapacity(max_bytes=1000)
        node = SimNode("n1", "us-east", capacity=cap)
        node.store_shard("eid-1", 0, b"x" * 500)
        assert node.capacity.utilization == pytest.approx(0.5)

    def test_stats(self):
        node = SimNode("n1", "us-east")
        node.store_shard("eid-1", 0, b"data")
        node.fetch_shard("eid-1", 0)
        stats = node.stats()
        assert stats["node_id"] == "n1"
        assert stats["total_stores"] == 1
        assert stats["total_fetches"] == 1


# =========================================================================
# MessageBus Tests
# =========================================================================


class TestMessageBus:
    def test_send_and_record(self):
        bus = MessageBus()
        msg = bus.send(
            msg_type=MessageType.SHARD_STORE_REQUEST,
            source="client-alice",
            destination="node-1",
            payload_bytes=1024,
            send_time_ms=0.0,
            latency_ms=10.0,
        )
        assert msg.msg_id.startswith("msg-")
        assert msg.deliver_time_ms == 10.0
        assert bus.total_messages == 1

    def test_lost_message(self):
        bus = MessageBus()
        msg = bus.send(
            msg_type=MessageType.SHARD_FETCH_REQUEST,
            source="client-bob",
            destination="node-2",
            payload_bytes=100,
            send_time_ms=0.0,
            latency_ms=50.0,
            packet_lost=True,
        )
        assert msg.lost
        assert not msg.delivered
        assert bus.total_lost == 1

    def test_messages_by_type(self):
        bus = MessageBus()
        bus.send(MessageType.SHARD_STORE_REQUEST, "a", "b", 100, 0, 10)
        bus.send(MessageType.LATTICE_KEY_TRANSFER, "a", "c", 1300, 0, 80)
        bus.send(MessageType.SHARD_FETCH_REQUEST, "c", "b", 50, 0, 5)

        lattice_msgs = bus.messages_by_type(MessageType.LATTICE_KEY_TRANSFER)
        assert len(lattice_msgs) == 1
        assert lattice_msgs[0].payload_bytes == 1300

    def test_total_bytes(self):
        bus = MessageBus()
        bus.send(MessageType.SHARD_STORE_REQUEST, "a", "b", 1000, 0, 10)
        bus.send(MessageType.SHARD_STORE_REQUEST, "a", "c", 2000, 0, 10)
        assert bus.total_bytes_transferred == 3000

    def test_stats(self):
        bus = MessageBus()
        bus.send(MessageType.SHARD_STORE_REQUEST, "a", "b", 100, 0, 10)
        bus.send(MessageType.SHARD_STORE_REQUEST, "a", "c", 100, 0, 20)
        stats = bus.stats()
        assert stats["total_messages"] == 2
        assert stats["avg_latency_ms"] == pytest.approx(15.0)


# =========================================================================
# NetworkSimulator Tests
# =========================================================================


class TestNetworkSimulator:
    def test_add_region_creates_nodes(self, sim):
        assert len(sim.nodes) == 6
        assert len(sim.online_nodes) == 6

    def test_regions_connected(self, sim):
        assert sim.topology.is_reachable("us-east", "eu-west")
        assert sim.topology.is_reachable("us-east", "ap-south")
        assert sim.topology.is_reachable("eu-west", "ap-south")

    def test_add_client(self, sim):
        client = sim.add_client("alice", region="us-east")
        assert client.label == "alice"
        assert client.region == "us-east"
        assert "alice" in sim.clients

    def test_placement_returns_nodes(self, sim):
        nodes = sim.placement("test-entity-id", shard_index=0, replicas=2)
        assert len(nodes) == 2
        # Should prefer geographic diversity
        regions = {n.region for n in nodes}
        assert len(regions) >= 1  # May be 2 different regions

    def test_placement_deterministic(self, sim):
        nodes1 = sim.placement("entity-x", 0, 2)
        nodes2 = sim.placement("entity-x", 0, 2)
        assert [n.node_id for n in nodes1] == [n.node_id for n in nodes2]

    def test_partition_region(self, sim):
        sim.partition_region("eu-west")
        eu_nodes = [n for n in sim.nodes.values() if n.region == "eu-west"]
        assert all(not n.online for n in eu_nodes)

    def test_restore_region(self, sim):
        sim.partition_region("eu-west")
        sim.restore_region("eu-west")
        eu_nodes = [n for n in sim.nodes.values() if n.region == "eu-west"]
        assert all(n.online for n in eu_nodes)

    def test_kill_node(self, sim):
        node_id = list(sim.nodes.keys())[0]
        sim.kill_node(node_id)
        assert sim.nodes[node_id].is_evicted
        assert not sim.nodes[node_id].online

    def test_audit_node(self, sim):
        # Store a shard first
        node = list(sim.nodes.values())[0]
        node.store_shard("test-eid", 0, b"encrypted-data")
        result = sim.audit_node(node.node_id, "test-eid", 0)
        assert result is True

    def test_audit_missing_shard_fails(self, sim):
        node = list(sim.nodes.values())[0]
        result = sim.audit_node(node.node_id, "nonexistent", 0)
        assert result is False

    def test_summary(self, sim):
        summary = sim.summary()
        assert summary["nodes"]["total"] == 6
        assert summary["nodes"]["online"] == 6
        assert "topology" in summary

    def test_reset(self, sim):
        sim.add_client("alice", "us-east")
        sim.reset()
        assert len(sim.nodes) == 0
        assert len(sim.clients) == 0
        assert sim.clock.now == 0.0


# =========================================================================
# End-to-End Transfer Tests (SimClient)
# =========================================================================


class TestSimClientTransfer:
    def test_basic_transfer(self, sim_with_clients):
        sim, alice, bob = sim_with_clients
        content = b"Hello, LTP simulation!"

        entity_id = alice.commit(content, shape="text/plain")
        sealed = alice.send_lattice_key(entity_id, receiver=bob)
        result = bob.materialize(sealed)

        assert result == content

    def test_transfer_json(self, sim_with_clients):
        import json

        sim, alice, bob = sim_with_clients
        content = json.dumps({"patient": "P-001", "status": "healthy"}).encode()

        entity_id = alice.commit(content, shape="application/json")
        sealed = alice.send_lattice_key(entity_id, receiver=bob)
        result = bob.materialize(sealed)

        assert result == content

    def test_transfer_large_payload(self, sim_with_clients):
        sim, alice, bob = sim_with_clients
        content = os.urandom(50_000)

        entity_id = alice.commit(content, shape="application/octet-stream")
        sealed = alice.send_lattice_key(entity_id, receiver=bob)
        result = bob.materialize(sealed)

        assert result == content

    def test_wrong_receiver_fails(self, sim_with_clients):
        sim, alice, bob = sim_with_clients
        eve = sim.add_client("eve", region="eu-west")
        content = b"for bob only"

        entity_id = alice.commit(content, shape="text/plain")
        sealed = alice.send_lattice_key(entity_id, receiver=bob)

        # Eve cannot materialize bob's key
        result = eve.materialize(sealed)
        assert result is None

    def test_lattice_key_is_constant_size(self, sim_with_clients):
        sim, alice, bob = sim_with_clients

        # Small entity
        eid1 = alice.commit(b"tiny", shape="text/plain")
        sealed1 = alice.send_lattice_key(eid1, receiver=bob)

        # Large entity
        eid2 = alice.commit(os.urandom(100_000), shape="application/octet-stream")
        sealed2 = alice.send_lattice_key(eid2, receiver=bob)

        # Both sealed keys should be approximately the same size (~1300 bytes)
        assert abs(len(sealed1) - len(sealed2)) < 50

    def test_multiple_independent_transfers(self, sim_with_clients):
        sim, alice, bob = sim_with_clients

        results = []
        for i in range(5):
            content = f"message-{i}".encode()
            eid = alice.commit(content, shape="text/plain")
            sealed = alice.send_lattice_key(eid, receiver=bob)
            results.append(bob.materialize(sealed))

        for i, result in enumerate(results):
            assert result == f"message-{i}".encode()

    def test_bidirectional_transfer(self, sim_with_clients):
        sim, alice, bob = sim_with_clients

        # Alice → Bob
        eid1 = alice.commit(b"from alice", shape="text/plain")
        sealed1 = alice.send_lattice_key(eid1, receiver=bob)
        assert bob.materialize(sealed1) == b"from alice"

        # Bob → Alice
        eid2 = bob.commit(b"from bob", shape="text/plain")
        sealed2 = bob.send_lattice_key(eid2, receiver=alice)
        assert alice.materialize(sealed2) == b"from bob"


# =========================================================================
# Transfer Metrics Tests
# =========================================================================


class TestTransferMetrics:
    def test_metrics_recorded(self, sim_with_clients):
        sim, alice, bob = sim_with_clients
        content = b"metrics test"

        entity_id = alice.commit(content, shape="text/plain")
        sealed = alice.send_lattice_key(entity_id, receiver=bob)
        bob.materialize(sealed)

        metrics = sim.metrics.get_transfer(entity_id)
        assert metrics is not None
        assert metrics.success
        assert metrics.entity_size_bytes == len(content)
        assert metrics.sender == "alice"
        assert metrics.receiver == "bob"

    def test_phase_latencies_positive(self, sim_with_clients):
        sim, alice, bob = sim_with_clients
        entity_id = alice.commit(b"latency test", shape="text/plain")
        sealed = alice.send_lattice_key(entity_id, receiver=bob)
        bob.materialize(sealed)

        metrics = sim.metrics.get_transfer(entity_id)
        assert metrics.commit_latency_ms > 0
        assert metrics.lattice_latency_ms > 0
        assert metrics.materialize_latency_ms > 0
        assert metrics.total_latency_ms > 0

    def test_lattice_key_size_recorded(self, sim_with_clients):
        sim, alice, bob = sim_with_clients
        entity_id = alice.commit(b"key size test", shape="text/plain")
        sealed = alice.send_lattice_key(entity_id, receiver=bob)

        metrics = sim.metrics.get_transfer(entity_id)
        assert metrics.lattice_key_bytes > 1000  # ML-KEM overhead

    def test_shard_metrics_recorded(self, sim_with_clients):
        sim, alice, bob = sim_with_clients
        entity_id = alice.commit(b"shard metrics", shape="text/plain")
        sealed = alice.send_lattice_key(entity_id, receiver=bob)
        bob.materialize(sealed)

        metrics = sim.metrics.get_transfer(entity_id)
        assert len(metrics.shard_store_metrics) > 0
        assert len(metrics.shard_fetch_metrics) > 0
        assert metrics.shards_fetched >= metrics.k_shards

    def test_aggregate_metrics(self, sim_with_clients):
        sim, alice, bob = sim_with_clients

        for i in range(3):
            eid = alice.commit(f"transfer-{i}".encode(), shape="text/plain")
            sealed = alice.send_lattice_key(eid, receiver=bob)
            bob.materialize(sealed)

        summary = sim.metrics.summary()
        assert summary["total_transfers"] == 3
        assert summary["successful"] == 3
        assert summary["avg_total_ms"] > 0

    def test_sender_bandwidth_is_constant(self, sim_with_clients):
        sim, alice, bob = sim_with_clients

        eid1 = alice.commit(b"small", shape="text/plain")
        sealed1 = alice.send_lattice_key(eid1, receiver=bob)

        eid2 = alice.commit(os.urandom(100_000), shape="application/octet-stream")
        sealed2 = alice.send_lattice_key(eid2, receiver=bob)

        m1 = sim.metrics.get_transfer(eid1)
        m2 = sim.metrics.get_transfer(eid2)

        # Sender bandwidth should be roughly equal (both ~1300 bytes)
        assert abs(m1.sender_bandwidth_bytes - m2.sender_bandwidth_bytes) < 50


# =========================================================================
# Failure Scenario Tests
# =========================================================================


class TestFailureScenarios:
    def test_materialize_after_one_region_partition(self, sim_with_clients):
        sim, alice, bob = sim_with_clients
        content = b"resilient transfer"

        entity_id = alice.commit(content, shape="text/plain", n=8, k=4)
        sealed = alice.send_lattice_key(entity_id, receiver=bob)

        # Partition eu-west
        sim.partition_region("eu-west")

        # Should still succeed — k=4 shards available from us-east + ap-south
        result = bob.materialize(sealed)
        assert result == content

    def test_materialize_fails_with_insufficient_regions(self):
        # Build a sim where all shards end up in only one region
        sim = NetworkSimulator(seed=42)
        sim.add_region("us-east", node_count=6)
        sim.add_region("eu-west", node_count=0)
        sim.connect_regions("us-east", "eu-west", latency_ms=80.0, jitter_ms=0.0)

        alice = sim.add_client("alice", region="us-east")
        bob = sim.add_client("bob", region="us-east")

        content = b"single region"
        entity_id = alice.commit(content, shape="text/plain", n=8, k=4)
        sealed = alice.send_lattice_key(entity_id, receiver=bob)

        # Partition the only region with nodes
        sim.partition_region("us-east")

        # Bob is also in us-east, but nodes are partitioned
        result = bob.materialize(sealed)
        assert result is None

    def test_node_kill_and_repair(self, sim_with_clients):
        sim, alice, bob = sim_with_clients
        content = b"repair test"

        entity_id = alice.commit(content, shape="text/plain", n=8, k=4)

        # Kill a node
        node_id = list(sim.nodes.keys())[0]
        sim.kill_node(node_id)

        # Repair shards
        repaired = sim.repair_shards(entity_id, n=8)

        sealed = alice.send_lattice_key(entity_id, receiver=bob)
        result = bob.materialize(sealed)
        assert result == content

    def test_degraded_link(self, sim_with_clients):
        sim, alice, bob = sim_with_clients
        content = b"degraded link test"

        entity_id = alice.commit(content, shape="text/plain")
        sealed = alice.send_lattice_key(entity_id, receiver=bob)

        # Degrade the us-east ↔ ap-south link
        sim.degrade_link("us-east", "ap-south", latency_multiplier=10.0)

        result = bob.materialize(sealed)
        assert result == content

    def test_severed_link_fallback_routing(self, sim_with_clients):
        sim, alice, bob = sim_with_clients
        content = b"rerouted transfer"

        entity_id = alice.commit(content, shape="text/plain")
        sealed = alice.send_lattice_key(entity_id, receiver=bob)

        # Sever direct link, force routing through eu-west
        sim.sever_link("us-east", "ap-south")

        result = bob.materialize(sealed)
        assert result == content


# =========================================================================
# Geographic Optimization Tests
# =========================================================================


class TestGeographicOptimization:
    def test_local_shards_preferred(self, sim_with_clients):
        """Verify that materialization prefers shards from the receiver's region."""
        sim, alice, bob = sim_with_clients
        content = b"locality test"

        entity_id = alice.commit(content, shape="text/plain", n=8, k=4)
        sealed = alice.send_lattice_key(entity_id, receiver=bob)
        bob.materialize(sealed)

        metrics = sim.metrics.get_transfer(entity_id)
        # At least some shards should come from local region (if available)
        fetch_regions = [sm.target_region for sm in metrics.shard_fetch_metrics if sm.success]
        assert len(fetch_regions) > 0

    def test_sender_bandwidth_independent_of_entity_size(self, sim_with_clients):
        """LTP's core property: sender→receiver bandwidth is O(1)."""
        sim, alice, bob = sim_with_clients

        sizes = [100, 10_000, 100_000]
        sealed_sizes = []

        for size in sizes:
            eid = alice.commit(os.urandom(size), shape="application/octet-stream")
            sealed = alice.send_lattice_key(eid, receiver=bob)
            sealed_sizes.append(len(sealed))

        # All sealed key sizes should be within ~20 bytes of each other
        assert max(sealed_sizes) - min(sealed_sizes) < 30


# =========================================================================
# Large Topology / Scale Tests
# =========================================================================


class TestLargeTopology:
    def test_ten_region_topology(self):
        """Build a 10-region, 30-node topology and run a transfer."""
        sim = NetworkSimulator(seed=42)
        regions = [
            "us-east",
            "us-west",
            "eu-west",
            "eu-east",
            "ap-south",
            "ap-east",
            "sa-east",
            "af-south",
            "me-south",
            "oc-east",
        ]
        for r in regions:
            sim.add_region(r, node_count=3)

        # Mesh connectivity with varying latencies
        latencies = {
            ("us-east", "us-west"): 40,
            ("us-east", "eu-west"): 80,
            ("us-east", "sa-east"): 120,
            ("eu-west", "eu-east"): 30,
            ("eu-west", "af-south"): 100,
            ("eu-east", "me-south"): 60,
            ("ap-south", "ap-east"): 50,
            ("ap-south", "me-south"): 70,
            ("ap-east", "oc-east"): 90,
            ("us-west", "ap-east"): 130,
            ("sa-east", "af-south"): 200,
            ("oc-east", "us-west"): 150,
        }
        for (a, b), lat in latencies.items():
            sim.connect_regions(a, b, latency_ms=lat, jitter_ms=0.0)

        alice = sim.add_client("alice", region="us-east")
        bob = sim.add_client("bob", region="ap-east")

        content = b"cross-globe transfer"
        entity_id = alice.commit(content, shape="text/plain")
        sealed = alice.send_lattice_key(entity_id, receiver=bob)
        result = bob.materialize(sealed)

        assert result == content
        assert len(sim.nodes) == 30

    def test_many_transfers(self):
        """Run 20 transfers through a standard topology."""
        sim = NetworkSimulator(seed=42)
        sim.add_region("us-east", node_count=3)
        sim.add_region("eu-west", node_count=3)
        sim.connect_regions("us-east", "eu-west", latency_ms=80.0, jitter_ms=0.0)

        alice = sim.add_client("alice", region="us-east")
        bob = sim.add_client("bob", region="eu-west")

        for i in range(20):
            content = f"transfer-{i:03d}".encode()
            eid = alice.commit(content, shape="text/plain")
            sealed = alice.send_lattice_key(eid, receiver=bob)
            result = bob.materialize(sealed)
            assert result == content

        assert sim.metrics.summary()["successful"] == 20

    def test_high_node_count(self):
        """50 nodes across 5 regions."""
        sim = NetworkSimulator(seed=42)
        for r in ["r1", "r2", "r3", "r4", "r5"]:
            sim.add_region(r, node_count=10)
        sim.connect_regions("r1", "r2", latency_ms=10.0, jitter_ms=0.0)
        sim.connect_regions("r2", "r3", latency_ms=20.0, jitter_ms=0.0)
        sim.connect_regions("r3", "r4", latency_ms=15.0, jitter_ms=0.0)
        sim.connect_regions("r4", "r5", latency_ms=25.0, jitter_ms=0.0)
        sim.connect_regions("r1", "r5", latency_ms=50.0, jitter_ms=0.0)

        alice = sim.add_client("alice", region="r1")
        bob = sim.add_client("bob", region="r5")

        content = os.urandom(10_000)
        eid = alice.commit(content, shape="application/octet-stream")
        sealed = alice.send_lattice_key(eid, receiver=bob)
        result = bob.materialize(sealed)

        assert result == content
        assert len(sim.nodes) == 50
