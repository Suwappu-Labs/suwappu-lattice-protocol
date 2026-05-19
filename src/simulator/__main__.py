"""
LTP Network Simulator — CLI entry point.

Usage:
    python -m src.simulator              # Run default demo scenario
    python -m src.simulator --scenario mars   # Run Mars thought experiment
    python -m src.simulator --regions 10 --nodes-per-region 5  # Custom scale
"""

from __future__ import annotations

import argparse
import os
import sys

from .network import NetworkSimulator
from .node import StorageCapacity


def build_standard_topology(sim: NetworkSimulator, regions: int = 3, nodes_per_region: int = 2):
    """Build a standard multi-region topology."""
    region_configs = [
        ("us-east", 1.0),
        ("us-west", 1.0),
        ("eu-west", 1.0),
        ("eu-east", 1.0),
        ("ap-south", 1.5),
        ("ap-east", 1.5),
        ("sa-east", 2.0),
        ("af-south", 2.0),
        ("me-south", 1.5),
        ("oc-east", 2.0),
    ][:regions]

    for name, intra_lat in region_configs:
        sim.add_region(name, node_count=nodes_per_region, intra_latency_ms=intra_lat)

    # Connect with realistic cross-region latencies
    cross_region_latencies = {
        ("us-east", "us-west"): (40, 10000),
        ("us-east", "eu-west"): (80, 1000),
        ("us-east", "eu-east"): (100, 800),
        ("us-east", "sa-east"): (120, 500),
        ("us-west", "ap-east"): (130, 500),
        ("eu-west", "eu-east"): (30, 5000),
        ("eu-west", "af-south"): (100, 300),
        ("eu-east", "me-south"): (60, 500),
        ("ap-south", "ap-east"): (50, 1000),
        ("ap-south", "me-south"): (70, 500),
        ("ap-east", "oc-east"): (90, 800),
        ("sa-east", "af-south"): (200, 200),
        ("oc-east", "us-west"): (150, 500),
    }
    region_names = {name for name, _ in region_configs}
    for (a, b), (lat, bw) in cross_region_latencies.items():
        if a in region_names and b in region_names:
            sim.connect_regions(a, b, latency_ms=lat, bandwidth_mbps=bw, jitter_ms=2.0)


def run_demo(sim: NetworkSimulator):
    """Run the standard demo scenario."""
    print("=" * 70)
    print("  LTP Network Simulator — Demo Scenario")
    print("=" * 70)
    print()

    alice = sim.add_client("alice", region="us-east")
    bob = sim.add_client("bob", region=list(sim.topology.regions.keys())[-1])

    print(f"  Topology: {len(sim.topology.regions)} regions, {len(sim.nodes)} nodes")
    print(f"  Alice: {alice.region} | Bob: {bob.region}")
    print()

    # Transfer 1: Small message
    print("--- Transfer 1: Small Text Message ---")
    content = b"Hello from the LTP network simulation!"
    eid = alice.commit(content, shape="text/plain")
    sealed = alice.send_lattice_key(eid, receiver=bob)
    result = bob.materialize(sealed)
    m = sim.metrics.get_transfer(eid)
    print(f"  Content: {len(content)} bytes")
    print(f"  Sealed key: {len(sealed)} bytes (O(1) sender bandwidth)")
    print(f"  Result: {'SUCCESS' if result == content else 'FAILED'}")
    print(
        f"  Commit: {m.commit_latency_ms:.1f}ms | Lattice: {m.lattice_latency_ms:.1f}ms | Materialize: {m.materialize_latency_ms:.1f}ms"
    )
    print()

    # Transfer 2: Large payload
    print("--- Transfer 2: Large Binary Payload ---")
    content2 = os.urandom(100_000)
    eid2 = alice.commit(content2, shape="application/octet-stream")
    sealed2 = alice.send_lattice_key(eid2, receiver=bob)
    result2 = bob.materialize(sealed2)
    m2 = sim.metrics.get_transfer(eid2)
    print(f"  Content: {len(content2):,} bytes")
    print(f"  Sealed key: {len(sealed2)} bytes (SAME O(1) size!)")
    print(f"  Result: {'SUCCESS' if result2 == content2 else 'FAILED'}")
    print(
        f"  Commit: {m2.commit_latency_ms:.1f}ms | Lattice: {m2.lattice_latency_ms:.1f}ms | Materialize: {m2.materialize_latency_ms:.1f}ms"
    )
    print()

    # Transfer 3: Under region failure
    print("--- Transfer 3: Region Failure Resilience ---")
    content3 = b"surviving regional failure"
    eid3 = alice.commit(content3, shape="text/plain")
    sealed3 = alice.send_lattice_key(eid3, receiver=bob)

    # Partition a region
    regions = list(sim.topology.regions.keys())
    if len(regions) > 2:
        partitioned = regions[1]  # Pick a middle region
        sim.partition_region(partitioned)
        print(f"  Partitioned region: {partitioned}")
    result3 = bob.materialize(sealed3)
    print(f"  Result: {'SUCCESS' if result3 == content3 else 'FAILED'}")
    if len(regions) > 2:
        sim.restore_region(partitioned)
    print()

    # Summary
    print("=" * 70)
    print("  Simulation Summary")
    print("=" * 70)
    summary = sim.metrics.summary()
    for k, v in summary.items():
        print(f"  {k}: {v}")
    print()
    bus_stats = sim.bus.stats()
    print(f"  Network messages: {bus_stats['total_messages']}")
    print(f"  Bytes transferred: {bus_stats['total_bytes']:,}")
    print(f"  Clock advanced to: {sim.clock.now:.1f}ms")


def main():
    parser = argparse.ArgumentParser(description="LTP Network Simulator")
    parser.add_argument("--regions", type=int, default=3, help="Number of regions (max 10)")
    parser.add_argument("--nodes-per-region", type=int, default=2, help="Nodes per region")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    sim = NetworkSimulator(seed=args.seed)
    build_standard_topology(sim, regions=args.regions, nodes_per_region=args.nodes_per_region)
    run_demo(sim)


if __name__ == "__main__":
    main()
