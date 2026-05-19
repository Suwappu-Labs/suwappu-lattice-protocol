"""
Network topology model for the LTP simulator.

Models the physical network as a graph of Regions connected by Links.
Each Link has configurable latency, bandwidth, jitter, and packet loss.
The Topology class provides shortest-path routing and supports dynamic
modification (link degradation, region partitioning) during simulation.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Link:
    """
    A network link between two regions.

    Attributes:
        source:        source region name
        target:        target region name
        latency_ms:    base one-way latency in milliseconds
        bandwidth_mbps: link capacity in megabits per second
        jitter_ms:     max random jitter added to latency (uniform ±jitter)
        packet_loss:   probability of packet loss [0.0, 1.0)
        active:        whether the link is currently usable
    """

    source: str
    target: str
    latency_ms: float
    bandwidth_mbps: float = 1000.0
    jitter_ms: float = 2.0
    packet_loss: float = 0.0
    active: bool = True

    def __post_init__(self):
        if self.latency_ms < 0:
            raise ValueError(f"Latency must be non-negative: {self.latency_ms}")
        if self.bandwidth_mbps <= 0:
            raise ValueError(f"Bandwidth must be positive: {self.bandwidth_mbps}")
        if not (0.0 <= self.packet_loss < 1.0):
            raise ValueError(f"Packet loss must be in [0, 1): {self.packet_loss}")

    def transfer_time_ms(self, payload_bytes: int) -> float:
        """
        Compute total transfer time for a payload across this link.

        transfer_time = base_latency + jitter + (payload_bits / bandwidth)
        """
        if not self.active:
            return float("inf")
        jitter = random.uniform(-self.jitter_ms, self.jitter_ms)
        propagation = max(0.0, self.latency_ms + jitter)
        transmission = (payload_bytes * 8) / (self.bandwidth_mbps * 1_000_000) * 1000
        return propagation + transmission

    def is_packet_lost(self) -> bool:
        """Randomly determine if a packet is lost on this link."""
        if self.packet_loss <= 0.0:
            return False
        return random.random() < self.packet_loss


@dataclass
class Region:
    """
    A geographic region containing network nodes.

    Attributes:
        name:             region identifier (e.g., "us-east", "eu-west")
        intra_latency_ms: latency between nodes within this region
        active:           whether the region is online
    """

    name: str
    intra_latency_ms: float = 1.0
    active: bool = True
    _node_ids: list[str] = field(default_factory=list, repr=False)

    def add_node(self, node_id: str) -> None:
        if node_id not in self._node_ids:
            self._node_ids.append(node_id)

    def remove_node(self, node_id: str) -> None:
        if node_id in self._node_ids:
            self._node_ids.remove(node_id)

    @property
    def node_ids(self) -> list[str]:
        return list(self._node_ids)

    @property
    def node_count(self) -> int:
        return len(self._node_ids)


class Topology:
    """
    Network topology: a graph of Regions connected by Links.

    Supports:
      - Region management (add, remove, partition, restore)
      - Link management (connect, degrade, sever, restore)
      - Shortest-path routing between regions (Dijkstra)
      - Dynamic topology modification during simulation
    """

    def __init__(self) -> None:
        self._regions: dict[str, Region] = {}
        self._links: dict[tuple[str, str], Link] = {}
        self._node_region_map: dict[str, str] = {}

    # --- Region management ---

    def add_region(self, name: str, intra_latency_ms: float = 1.0) -> Region:
        """Add a geographic region. Returns the Region object."""
        if name in self._regions:
            return self._regions[name]
        region = Region(name=name, intra_latency_ms=intra_latency_ms)
        self._regions[name] = region
        return region

    def get_region(self, name: str) -> Optional[Region]:
        return self._regions.get(name)

    def get_node_region(self, node_id: str) -> Optional[str]:
        return self._node_region_map.get(node_id)

    def register_node(self, node_id: str, region_name: str) -> None:
        """Register a node in a region."""
        if region_name not in self._regions:
            raise ValueError(f"Region '{region_name}' does not exist")
        self._node_region_map[node_id] = region_name
        self._regions[region_name].add_node(node_id)

    def unregister_node(self, node_id: str) -> None:
        """Remove a node from the topology."""
        region_name = self._node_region_map.pop(node_id, None)
        if region_name and region_name in self._regions:
            self._regions[region_name].remove_node(node_id)

    @property
    def regions(self) -> dict[str, Region]:
        return dict(self._regions)

    @property
    def region_names(self) -> list[str]:
        return list(self._regions.keys())

    # --- Link management ---

    def connect_regions(
        self,
        region_a: str,
        region_b: str,
        latency_ms: float,
        bandwidth_mbps: float = 1000.0,
        jitter_ms: float = 2.0,
        packet_loss: float = 0.0,
    ) -> tuple[Link, Link]:
        """
        Create bidirectional links between two regions.
        Returns (link_a_to_b, link_b_to_a).
        """
        for name in (region_a, region_b):
            if name not in self._regions:
                raise ValueError(f"Region '{name}' does not exist")

        link_ab = Link(
            source=region_a,
            target=region_b,
            latency_ms=latency_ms,
            bandwidth_mbps=bandwidth_mbps,
            jitter_ms=jitter_ms,
            packet_loss=packet_loss,
        )
        link_ba = Link(
            source=region_b,
            target=region_a,
            latency_ms=latency_ms,
            bandwidth_mbps=bandwidth_mbps,
            jitter_ms=jitter_ms,
            packet_loss=packet_loss,
        )
        self._links[(region_a, region_b)] = link_ab
        self._links[(region_b, region_a)] = link_ba
        return link_ab, link_ba

    def get_link(self, source: str, target: str) -> Optional[Link]:
        return self._links.get((source, target))

    def get_links_from(self, region_name: str) -> list[Link]:
        """Get all outgoing links from a region."""
        return [link for (src, _), link in self._links.items() if src == region_name]

    # --- Latency computation ---

    def latency_between_nodes(self, node_a: str, node_b: str, payload_bytes: int = 0) -> float:
        """
        Compute simulated transfer time between two nodes in milliseconds.

        If same region: intra-region latency + transmission time.
        If different regions: shortest path latency via Dijkstra.
        Returns float('inf') if no path exists.
        """
        region_a = self._node_region_map.get(node_a)
        region_b = self._node_region_map.get(node_b)
        if region_a is None or region_b is None:
            return float("inf")

        if region_a == region_b:
            region = self._regions[region_a]
            if not region.active:
                return float("inf")
            base = region.intra_latency_ms
            if payload_bytes > 0:
                # Intra-region: assume 10Gbps local fabric
                base += (payload_bytes * 8) / (10_000 * 1_000_000) * 1000
            return base

        return self._shortest_path_latency(region_a, region_b, payload_bytes)

    def _shortest_path_latency(self, source: str, target: str, payload_bytes: int) -> float:
        """Dijkstra shortest-path by transfer time between regions."""
        dist: dict[str, float] = {r: float("inf") for r in self._regions}
        dist[source] = 0.0
        visited: set[str] = set()
        # Simple Dijkstra — regions are typically small (< 100)
        while True:
            # Pick unvisited node with smallest distance
            current = None
            current_dist = float("inf")
            for r, d in dist.items():
                if r not in visited and d < current_dist:
                    current = r
                    current_dist = d
            if current is None or current == target:
                break
            visited.add(current)
            region = self._regions[current]
            if not region.active:
                continue
            for link in self.get_links_from(current):
                if not link.active:
                    continue
                neighbor = link.target
                if neighbor in visited:
                    continue
                neighbor_region = self._regions.get(neighbor)
                if neighbor_region and not neighbor_region.active:
                    continue
                cost = current_dist + link.transfer_time_ms(payload_bytes)
                if cost < dist[neighbor]:
                    dist[neighbor] = cost
        return dist.get(target, float("inf"))

    # --- Failure injection ---

    def partition_region(self, region_name: str) -> None:
        """Take a region offline (all nodes become unreachable)."""
        region = self._regions.get(region_name)
        if region:
            region.active = False

    def restore_region(self, region_name: str) -> None:
        """Bring a region back online."""
        region = self._regions.get(region_name)
        if region:
            region.active = True

    def degrade_link(
        self,
        source: str,
        target: str,
        latency_multiplier: float = 1.0,
        packet_loss: Optional[float] = None,
        bandwidth_mbps: Optional[float] = None,
    ) -> None:
        """Degrade a link's performance."""
        for key in [(source, target), (target, source)]:
            link = self._links.get(key)
            if link:
                link.latency_ms *= latency_multiplier
                if packet_loss is not None:
                    link.packet_loss = packet_loss
                if bandwidth_mbps is not None:
                    link.bandwidth_mbps = bandwidth_mbps

    def sever_link(self, source: str, target: str) -> None:
        """Sever a bidirectional link."""
        for key in [(source, target), (target, source)]:
            link = self._links.get(key)
            if link:
                link.active = False

    def restore_link(self, source: str, target: str) -> None:
        """Restore a severed bidirectional link."""
        for key in [(source, target), (target, source)]:
            link = self._links.get(key)
            if link:
                link.active = True

    def is_reachable(self, source_region: str, target_region: str) -> bool:
        """Check if there's any active path between two regions (BFS)."""
        if source_region == target_region:
            region = self._regions.get(source_region)
            return region is not None and region.active
        visited: set[str] = set()
        queue = [source_region]
        while queue:
            current = queue.pop(0)
            if current == target_region:
                return True
            if current in visited:
                continue
            visited.add(current)
            region = self._regions.get(current)
            if not region or not region.active:
                continue
            for link in self.get_links_from(current):
                if link.active and link.target not in visited:
                    target_r = self._regions.get(link.target)
                    if target_r and target_r.active:
                        queue.append(link.target)
        return False

    # --- Topology inspection ---

    @property
    def link_count(self) -> int:
        return len(self._links)

    @property
    def total_nodes(self) -> int:
        return len(self._node_region_map)

    def summary(self) -> dict:
        """Return a summary of the topology."""
        return {
            "regions": {
                name: {
                    "node_count": r.node_count,
                    "active": r.active,
                    "intra_latency_ms": r.intra_latency_ms,
                }
                for name, r in self._regions.items()
            },
            "links": [
                {
                    "source": link.source,
                    "target": link.target,
                    "latency_ms": link.latency_ms,
                    "bandwidth_mbps": link.bandwidth_mbps,
                    "packet_loss": link.packet_loss,
                    "active": link.active,
                }
                for link in self._links.values()
            ],
            "total_nodes": self.total_nodes,
        }
