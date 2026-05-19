"""
Network simulator — the top-level orchestrator for LTP network simulation.

Manages the topology, nodes, clients, event queue, message bus, and
metrics collector. Provides failure injection, shard placement, and
the fetch routing logic that models geographic optimization.
"""

from __future__ import annotations

import os
import struct
from typing import Optional

from src.ltp.commitment import CommitmentLog
from src.ltp.keypair import KeyPair
from src.ltp.primitives import canonical_hash_bytes, internal_hash

from .clock import EventQueue, EventType, SimClock
from .message import Message, MessageBus, MessageType
from .metrics import MetricsCollector, ShardMetrics
from .node import SimNode, StorageCapacity
from .topology import Link, Region, Topology


class NetworkSimulator:
    """
    Top-level orchestrator for the LTP network simulation.

    Responsibilities:
      - Manage the global simulation clock and event queue
      - Build and modify network topology (regions, links, nodes)
      - Create clients (senders/receivers) at geographic locations
      - Route shard operations with latency from the topology
      - Provide failure injection (partitions, node kills, link degradation)
      - Coordinate the message bus and metrics collector
      - Support deterministic (seeded) and stochastic simulation modes
    """

    # Expose MessageType for clients
    _msg_types = MessageType

    def __init__(self, seed: int | None = None) -> None:
        self.clock = SimClock()
        self.events = EventQueue()
        self.topology = Topology()
        self.bus = MessageBus()
        self.metrics = MetricsCollector()
        self.commitment_log = CommitmentLog()

        self._nodes: dict[str, SimNode] = {}
        self._clients: dict[str, "SimClient"] = {}
        self._sender_keypairs: dict[str, KeyPair] = {}
        self._seed = seed

        if seed is not None:
            import random

            random.seed(seed)

    # ------------------------------------------------------------------
    # Topology construction
    # ------------------------------------------------------------------

    def add_region(
        self,
        name: str,
        node_count: int = 2,
        intra_latency_ms: float = 1.0,
        node_capacity: StorageCapacity | None = None,
        processing_delay_ms: float = 0.5,
    ) -> Region:
        """
        Add a geographic region with the specified number of nodes.

        Each node is created with the given capacity and registered in
        the topology. Returns the Region object.
        """
        region = self.topology.add_region(name, intra_latency_ms)

        for i in range(node_count):
            node_id = f"node-{name}-{i + 1}"
            node = SimNode(
                node_id=node_id,
                region=name,
                capacity=node_capacity or StorageCapacity(),
                processing_delay_ms=processing_delay_ms,
            )
            self._nodes[node_id] = node
            self.topology.register_node(node_id, name)

        return region

    def connect_regions(
        self,
        region_a: str,
        region_b: str,
        latency_ms: float,
        bandwidth_mbps: float = 1000.0,
        jitter_ms: float = 2.0,
        packet_loss: float = 0.0,
    ) -> tuple[Link, Link]:
        """Connect two regions with bidirectional links."""
        return self.topology.connect_regions(
            region_a,
            region_b,
            latency_ms=latency_ms,
            bandwidth_mbps=bandwidth_mbps,
            jitter_ms=jitter_ms,
            packet_loss=packet_loss,
        )

    def add_node(
        self,
        node_id: str,
        region: str,
        capacity: StorageCapacity | None = None,
        processing_delay_ms: float = 0.5,
    ) -> SimNode:
        """Add a single node to an existing region."""
        if region not in self.topology.regions:
            raise ValueError(f"Region '{region}' does not exist")
        node = SimNode(
            node_id=node_id,
            region=region,
            capacity=capacity or StorageCapacity(),
            processing_delay_ms=processing_delay_ms,
        )
        self._nodes[node_id] = node
        self.topology.register_node(node_id, region)
        return node

    # ------------------------------------------------------------------
    # Client management
    # ------------------------------------------------------------------

    def add_client(
        self,
        label: str,
        region: str,
        keypair: KeyPair | None = None,
    ) -> "SimClient":
        """
        Create a client (sender/receiver) located in the given region.

        Generates a fresh KeyPair if not provided.
        """
        from .client import SimClient

        if region not in self.topology.regions:
            raise ValueError(f"Region '{region}' does not exist")
        kp = keypair or KeyPair.generate(label)
        client = SimClient(
            label=label,
            region=region,
            keypair=kp,
            simulator=self,
        )
        self._clients[label] = client
        # Register client as a virtual node in the topology
        self.topology.register_node(client.node_id, region)
        return client

    def get_client(self, label: str) -> Optional["SimClient"]:
        return self._clients.get(label)

    # ------------------------------------------------------------------
    # Sender registry (for signature verification during materialize)
    # ------------------------------------------------------------------

    def register_sender(self, label: str, keypair: KeyPair) -> None:
        self._sender_keypairs[label] = keypair

    def get_sender_keypair(self, label: str) -> Optional[KeyPair]:
        return self._sender_keypairs.get(label)

    # ------------------------------------------------------------------
    # Shard placement
    # ------------------------------------------------------------------

    def placement(
        self,
        entity_id: str,
        shard_index: int,
        replicas: int = 2,
    ) -> list[SimNode]:
        """
        Deterministic shard placement via consistent hashing.

        Returns a list of nodes that should store this shard, selecting
        from different regions when possible for geographic redundancy.
        """
        if not self._nodes:
            raise ValueError("No nodes in the network")

        placement_key = f"{entity_id}:{shard_index}"
        h = int.from_bytes(canonical_hash_bytes(placement_key.encode()), "big")

        online_nodes = [n for n in self._nodes.values() if n.online]
        if not online_nodes:
            raise ValueError("No online nodes available")

        # Sort nodes deterministically by hash distance
        def node_score(node: SimNode) -> int:
            node_hash = int.from_bytes(canonical_hash_bytes(node.node_id.encode()), "big")
            return (h ^ node_hash) % (2**256)

        sorted_nodes = sorted(online_nodes, key=node_score)

        selected: list[SimNode] = []
        selected_regions: set[str] = set()

        # First pass: pick one node per region (geographic diversity)
        for node in sorted_nodes:
            if len(selected) >= replicas:
                break
            if node.region not in selected_regions:
                selected.append(node)
                selected_regions.add(node.region)

        # Second pass: fill remaining replicas from any region
        for node in sorted_nodes:
            if len(selected) >= replicas:
                break
            if node not in selected:
                selected.append(node)

        return selected

    # ------------------------------------------------------------------
    # Shard fetch (for materialize — proximity-optimized)
    # ------------------------------------------------------------------

    def fetch_shards_for_client(
        self,
        client: "SimClient",
        entity_id: str,
        n: int,
        k: int,
        replicas: int = 2,
    ) -> tuple[dict[int, bytes], list[ShardMetrics]]:
        """
        Fetch shards for a materializing client, optimizing for proximity.

        For each shard, finds the nearest online node that holds it.
        Shards are fetched "in parallel" — the total fetch time is
        the max individual fetch time (not the sum).

        Returns: (shard_dict, shard_metrics)
        """
        fetched: dict[int, bytes] = {}
        shard_metrics: list[ShardMetrics] = []
        max_fetch_time = 0.0

        for i in range(n):
            if len(fetched) >= k:
                break

            target_nodes = self.placement(entity_id, i, replicas)

            # Sort by latency from the client (nearest first)
            candidates = []
            for node in target_nodes:
                if node.online and node.is_online_at(self.clock.now):
                    lat = self.topology.latency_between_nodes(client.node_id, node.node_id)
                    candidates.append((lat, node))
            # Also check all nodes — shard might have been repaired elsewhere
            for node in self._nodes.values():
                if node.online and node not in target_nodes:
                    if node.has_shard(entity_id, i):
                        lat = self.topology.latency_between_nodes(client.node_id, node.node_id)
                        candidates.append((lat, node))

            candidates.sort(key=lambda x: x[0])

            fetched_this_shard = False
            for attempt, (latency, node) in enumerate(candidates, 1):
                data = node.fetch_shard(entity_id, i)

                # Check for packet loss
                link = self._get_link_for_nodes(client.node_id, node.node_id)
                lost = link.is_packet_lost() if link else False

                if data is not None and not lost:
                    # Compute transfer time including payload
                    full_latency = self.topology.latency_between_nodes(
                        client.node_id,
                        node.node_id,
                        payload_bytes=len(data),
                    )

                    sm = ShardMetrics(
                        shard_index=i,
                        target_node=node.node_id,
                        target_region=node.region,
                        latency_ms=full_latency,
                        payload_bytes=len(data),
                        success=True,
                        attempt=attempt,
                    )
                    shard_metrics.append(sm)

                    self.bus.send(
                        msg_type=MessageType.SHARD_FETCH_RESPONSE,
                        source=node.node_id,
                        destination=client.node_id,
                        payload_bytes=len(data),
                        send_time_ms=self.clock.now,
                        latency_ms=full_latency,
                        payload={"entity_id": entity_id, "shard_index": i},
                    )

                    fetched[i] = data
                    if full_latency != float("inf"):
                        max_fetch_time = max(max_fetch_time, full_latency)
                    fetched_this_shard = True
                    break
                else:
                    sm = ShardMetrics(
                        shard_index=i,
                        target_node=node.node_id,
                        target_region=node.region,
                        latency_ms=latency,
                        payload_bytes=0,
                        success=False,
                        attempt=attempt,
                    )
                    shard_metrics.append(sm)

            if not fetched_this_shard:
                sm = ShardMetrics(
                    shard_index=i,
                    target_node="none",
                    target_region="none",
                    latency_ms=0,
                    payload_bytes=0,
                    success=False,
                )
                shard_metrics.append(sm)

        # Advance clock by the max fetch latency (parallel fetch)
        if max_fetch_time > 0 and max_fetch_time != float("inf"):
            self.clock.advance_to(self.clock.now + max_fetch_time)

        return fetched, shard_metrics

    # ------------------------------------------------------------------
    # Link lookup helper
    # ------------------------------------------------------------------

    def _get_link_for_nodes(self, node_a: str, node_b: str) -> Optional[Link]:
        """Get the inter-region link between two nodes (if different regions)."""
        region_a = self.topology.get_node_region(node_a)
        region_b = self.topology.get_node_region(node_b)
        if region_a is None or region_b is None or region_a == region_b:
            return None
        return self.topology.get_link(region_a, region_b)

    def _make_shard_metric(
        self, index: int, node: SimNode, latency: float, size: int, success: bool
    ) -> ShardMetrics:
        return ShardMetrics(
            shard_index=index,
            target_node=node.node_id,
            target_region=node.region,
            latency_ms=latency,
            payload_bytes=size,
            success=success,
        )

    # ------------------------------------------------------------------
    # Failure injection
    # ------------------------------------------------------------------

    def partition_region(self, region_name: str) -> None:
        """
        Partition a region — all nodes become unreachable from outside,
        and all links to/from the region are severed.
        """
        self.topology.partition_region(region_name)
        for node in self._nodes.values():
            if node.region == region_name:
                node.set_online(False)

    def restore_region(self, region_name: str) -> None:
        """Restore a partitioned region."""
        self.topology.restore_region(region_name)
        for node in self._nodes.values():
            if node.region == region_name and not node.is_evicted:
                node.set_online(True)

    def kill_node(self, node_id: str) -> None:
        """Permanently kill a node (evict + unregister)."""
        node = self._nodes.get(node_id)
        if node:
            node.evict()

    def recover_node(self, node_id: str) -> None:
        """Recover a temporarily offline node (not evicted)."""
        node = self._nodes.get(node_id)
        if node and not node.is_evicted:
            node.set_online(True)

    def degrade_link(
        self,
        region_a: str,
        region_b: str,
        latency_multiplier: float = 1.0,
        packet_loss: float | None = None,
        bandwidth_mbps: float | None = None,
    ) -> None:
        """Degrade the link between two regions."""
        self.topology.degrade_link(
            region_a,
            region_b,
            latency_multiplier=latency_multiplier,
            packet_loss=packet_loss,
            bandwidth_mbps=bandwidth_mbps,
        )

    def sever_link(self, region_a: str, region_b: str) -> None:
        """Completely sever the link between two regions."""
        self.topology.sever_link(region_a, region_b)

    def restore_link(self, region_a: str, region_b: str) -> None:
        """Restore a severed link."""
        self.topology.restore_link(region_a, region_b)

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    def audit_node(self, node_id: str, entity_id: str, shard_index: int) -> bool:
        """Run an audit challenge against a node for a specific shard."""
        node = self._nodes.get(node_id)
        if node is None:
            return False

        nonce = os.urandom(16)
        response = node.respond_to_audit(entity_id, shard_index, nonce)
        if response is None:
            node.strikes += 1
            return False

        # Verify the audit response
        data = node.fetch_shard(entity_id, shard_index)
        if data is None:
            node.strikes += 1
            return False

        expected = internal_hash(data + nonce)
        if response == expected:
            node.audit_passes += 1
            return True
        else:
            node.strikes += 1
            return False

    # ------------------------------------------------------------------
    # Repair
    # ------------------------------------------------------------------

    def repair_shards(self, entity_id: str, n: int, replicas: int = 2) -> int:
        """
        Repair missing shard replicas for an entity.

        Checks each shard placement and copies from healthy replicas
        to new nodes if the target is offline or missing the shard.

        Returns the number of shards repaired.
        """
        repaired = 0
        for i in range(n):
            target_nodes = self.placement(entity_id, i, replicas)

            # Find a healthy source
            source_data = None
            for node in self._nodes.values():
                if node.online and node.has_shard(entity_id, i):
                    source_data = node.fetch_shard(entity_id, i)
                    break

            if source_data is None:
                continue

            # Store on any target that's missing it
            for node in target_nodes:
                if node.online and not node.has_shard(entity_id, i):
                    if node.store_shard(entity_id, i, source_data):
                        repaired += 1

        return repaired

    # ------------------------------------------------------------------
    # Inspection
    # ------------------------------------------------------------------

    @property
    def nodes(self) -> dict[str, SimNode]:
        return dict(self._nodes)

    @property
    def online_nodes(self) -> list[SimNode]:
        return [n for n in self._nodes.values() if n.online]

    @property
    def clients(self) -> dict[str, "SimClient"]:
        return dict(self._clients)

    def node_stats(self) -> list[dict]:
        return [n.stats() for n in self._nodes.values()]

    def summary(self) -> dict:
        return {
            "clock_ms": self.clock.now,
            "topology": self.topology.summary(),
            "nodes": {
                "total": len(self._nodes),
                "online": len(self.online_nodes),
            },
            "clients": len(self._clients),
            "commitment_log_length": self.commitment_log.length,
            "message_bus": self.bus.stats(),
            "metrics": self.metrics.summary(),
        }

    def reset(self) -> None:
        """Reset the entire simulation state."""
        self.clock.reset()
        self.events.clear()
        self.bus.clear()
        self.metrics.clear()
        self.commitment_log = CommitmentLog()
        self._nodes.clear()
        self._clients.clear()
        self._sender_keypairs.clear()
        self.topology = Topology()
