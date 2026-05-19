"""
Deterministic Simulation Testing (DST) for ETP.

FoundationDB-style DST: run the entire distributed system in a single thread
with seeded randomness and fault injection. Every execution is perfectly
reproducible from its seed.

Reference: FoundationDB simulation framework, Antithesis DST platform.

Usage:
    from src.simulator.dst import DSTRunner
    result = DSTRunner(seed=42, fault_rate=0.1).run(steps=500)
    print(f"Violations: {result.violations}")
    # Replay: DSTRunner(seed=42, fault_rate=0.1).run(steps=500) → identical result
"""

from __future__ import annotations

import random
import time as _time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

from .clock import Event, EventQueue, EventType, SimClock
from .message import Message, MessageBus, MessageType
from .metrics import MetricsCollector
from .node import SimNode, StorageCapacity
from .topology import Link, Region, Topology

__all__ = ["DSTRunner", "DSTResult", "PropertyViolation"]


# ---------------------------------------------------------------------------
# Result Types
# ---------------------------------------------------------------------------


@dataclass
class PropertyViolation:
    """A property invariant that was violated during simulation."""

    property_name: str
    step: int
    description: str
    context: dict = field(default_factory=dict)


@dataclass
class DSTResult:
    """Results of a deterministic simulation run."""

    seed: int
    steps_executed: int
    events_processed: int
    properties_checked: int
    violations: list[PropertyViolation] = field(default_factory=list)
    event_log: list[dict] = field(default_factory=list)
    faults_injected: int = 0
    duration_ms: float = 0.0
    nodes_online: int = 0
    nodes_offline: int = 0

    @property
    def passed(self) -> bool:
        return len(self.violations) == 0


# ---------------------------------------------------------------------------
# Fault Types
# ---------------------------------------------------------------------------


class FaultType(Enum):
    NODE_CRASH = "node_crash"
    NODE_RECOVERY = "node_recovery"
    NETWORK_PARTITION = "network_partition"
    PARTITION_HEAL = "partition_heal"
    LINK_DEGRADE = "link_degrade"
    LINK_RESTORE = "link_restore"
    CLOCK_SKEW = "clock_skew"
    MESSAGE_DROP = "message_drop"
    AUDIT_TICK = "audit_tick"
    SHARD_CORRUPTION = "shard_corruption"


# ---------------------------------------------------------------------------
# DST Runner
# ---------------------------------------------------------------------------


class DSTRunner:
    """
    FoundationDB-style Deterministic Simulation Testing.

    Runs the entire commitment network in a single thread with:
    - Seeded randomness (perfect reproducibility)
    - BUGGIFY-style probabilistic fault injection
    - Property checking at every step
    - Full event trace logging

    Usage:
        runner = DSTRunner(seed=42, fault_rate=0.1)
        runner.add_property("my_invariant", lambda r: len(r.online_nodes) > 0)
        result = runner.run(steps=1000)
        assert result.passed
    """

    def __init__(
        self,
        seed: int = 42,
        fault_rate: float = 0.1,
        num_nodes: int = 6,
        num_regions: int = 3,
    ):
        self.seed = seed
        self.fault_rate = fault_rate
        self.rng = random.Random(seed)

        # Core simulation components
        self.clock = SimClock()
        self.events = EventQueue()
        self.topology = Topology()
        self.bus = MessageBus()
        self.metrics = MetricsCollector()

        # State tracking
        self.nodes: dict[str, SimNode] = {}
        self.regions: list[Region] = []
        self._properties: list[tuple[str, Callable]] = []
        self._event_log: list[dict] = []
        self._faults_injected: int = 0
        self._committed_entities: list[str] = []
        self._log_length: int = 0

        # Set up topology
        self._setup_topology(num_nodes, num_regions)
        self._register_default_properties()

    def _setup_topology(self, num_nodes: int, num_regions: int) -> None:
        """Create a standard multi-region topology with nodes."""
        region_names = ["us-east", "eu-west", "ap-south", "us-west", "eu-east", "ap-north"][
            :num_regions
        ]

        for name in region_names:
            region = self.topology.add_region(name, intra_latency_ms=self.rng.uniform(1, 5))
            self.regions.append(region)

        # Connect regions with realistic latencies
        for i in range(len(self.regions)):
            for j in range(i + 1, len(self.regions)):
                latency = self.rng.uniform(40, 200)
                self.topology.connect_regions(
                    self.regions[i].name,
                    self.regions[j].name,
                    latency_ms=latency,
                    bandwidth_mbps=self.rng.uniform(100, 1000),
                    jitter_ms=latency * 0.1,
                    packet_loss=self.rng.uniform(0, 0.01),
                )

        # Distribute nodes across regions
        for i in range(num_nodes):
            region = self.regions[i % num_regions]
            node_id = f"node-{region.name}-{i}"
            capacity = StorageCapacity(
                max_bytes=1024 * 1024 * 100,  # 100MB
                max_shards=1000,
            )
            node = SimNode(
                node_id=node_id,
                region=region.name,
                capacity=capacity,
            )
            self.nodes[node_id] = node
            self.topology.register_node(node_id, region.name)

    def _register_default_properties(self) -> None:
        """Register built-in simulation properties."""
        self.add_property("at_least_one_node_online", self._prop_at_least_one_online)
        self.add_property("merkle_log_monotonic", self._prop_log_monotonic)
        self.add_property("no_negative_storage", self._prop_no_negative_storage)
        self.add_property("node_ids_unique", self._prop_node_ids_unique)

    # --- Properties ---

    def _prop_at_least_one_online(self, _runner: "DSTRunner") -> bool:
        """At least one node must be online at all times."""
        return any(n.online for n in self.nodes.values())

    def _prop_log_monotonic(self, _runner: "DSTRunner") -> bool:
        """Commitment log length never decreases (append-only)."""
        current = len(self._committed_entities)
        if current < self._log_length:
            return False
        self._log_length = current
        return True

    def _prop_no_negative_storage(self, _runner: "DSTRunner") -> bool:
        """No node has negative used storage."""
        return all(n.capacity.used_bytes >= 0 for n in self.nodes.values())

    def _prop_node_ids_unique(self, _runner: "DSTRunner") -> bool:
        """All node IDs are distinct."""
        ids = [n.node_id for n in self.nodes.values()]
        return len(ids) == len(set(ids))

    # --- Public API ---

    def add_property(self, name: str, check_fn: Callable[["DSTRunner"], bool]) -> None:
        """Register a property invariant to check every simulation step."""
        self._properties.append((name, check_fn))

    @property
    def online_nodes(self) -> list[SimNode]:
        return [n for n in self.nodes.values() if n.online]

    @property
    def offline_nodes(self) -> list[SimNode]:
        return [n for n in self.nodes.values() if not n.online]

    def run(self, steps: int = 1000) -> DSTResult:
        """
        Execute the deterministic simulation.

        For each step:
        1. Advance simulation clock
        2. Process pending events
        3. BUGGIFY: probabilistically inject faults
        4. Generate workload (store/fetch shards)
        5. Check all property invariants
        6. Log event to trace

        Returns DSTResult with all violations and event log.
        """
        start_time = _time.perf_counter()
        events_processed = 0
        properties_checked = 0
        violations: list[PropertyViolation] = []

        for step in range(steps):
            # 1. Advance clock
            time_advance = self.rng.uniform(1, 100)  # 1-100ms per step
            self.clock.advance_to(self.clock.now + time_advance)

            # 2. Process pending events
            while not self.events.is_empty and self.events.peek().time <= self.clock.now:
                event = self.events.pop()
                if event and event.callback:
                    event.callback(event)
                events_processed += 1

            # 3. BUGGIFY: fault injection
            if self.rng.random() < self.fault_rate:
                self._buggify(step)

            # 4. Generate workload
            self._generate_workload(step)

            # 5. Check properties
            for prop_name, check_fn in self._properties:
                properties_checked += 1
                try:
                    if not check_fn(self):
                        violations.append(
                            PropertyViolation(
                                property_name=prop_name,
                                step=step,
                                description=f"Property '{prop_name}' violated at step {step}",
                                context={
                                    "time_ms": self.clock.now,
                                    "online_nodes": len(self.online_nodes),
                                    "offline_nodes": len(self.offline_nodes),
                                },
                            )
                        )
                except Exception as e:
                    violations.append(
                        PropertyViolation(
                            property_name=prop_name,
                            step=step,
                            description=f"Property check raised: {e}",
                            context={"exception": str(e)},
                        )
                    )

            # 6. Log event
            self._event_log.append(
                {
                    "step": step,
                    "time_ms": self.clock.now,
                    "online_nodes": len(self.online_nodes),
                    "offline_nodes": len(self.offline_nodes),
                    "events_queued": self.events.pending,
                    "faults_total": self._faults_injected,
                    "entities_committed": len(self._committed_entities),
                    "violations_total": len(violations),
                }
            )

        duration = (_time.perf_counter() - start_time) * 1000

        return DSTResult(
            seed=self.seed,
            steps_executed=steps,
            events_processed=events_processed,
            properties_checked=properties_checked,
            violations=violations,
            event_log=self._event_log,
            faults_injected=self._faults_injected,
            duration_ms=duration,
            nodes_online=len(self.online_nodes),
            nodes_offline=len(self.offline_nodes),
        )

    def replay(self, seed: int | None = None) -> DSTResult:
        """Replay a simulation with the same (or new) seed."""
        new_runner = DSTRunner(
            seed=seed or self.seed,
            fault_rate=self.fault_rate,
            num_nodes=len(self.nodes),
            num_regions=len(self.regions),
        )
        # Copy custom properties
        for name, fn in self._properties:
            if name not in [p[0] for p in new_runner._properties]:
                new_runner.add_property(name, fn)
        return new_runner.run(steps=len(self._event_log) or 1000)

    # --- Fault Injection (BUGGIFY) ---

    def _buggify(self, step: int) -> None:
        """FoundationDB-style probabilistic fault injection."""
        online = self.online_nodes
        offline = self.offline_nodes

        faults = []
        if online:
            faults.append(FaultType.NODE_CRASH)
        if offline:
            faults.append(FaultType.NODE_RECOVERY)
        if len(self.regions) > 1:
            faults.extend([FaultType.NETWORK_PARTITION, FaultType.PARTITION_HEAL])
        faults.extend([FaultType.LINK_DEGRADE, FaultType.CLOCK_SKEW])
        if hasattr(self, "_commitment_network") and self._commitment_network is not None:
            faults.extend([FaultType.AUDIT_TICK, FaultType.SHARD_CORRUPTION])

        if not faults:
            return

        fault = self.rng.choice(faults)
        self.inject_fault(fault, step)

    def inject_fault(self, fault_type: FaultType, step: int = 0) -> None:
        """Inject a specific fault into the simulation."""
        self._faults_injected += 1

        if fault_type == FaultType.NODE_CRASH:
            online = self.online_nodes
            if online:
                node = self.rng.choice(online)
                node.set_online(False)
                self._log_fault(step, "node_crash", node.node_id)

        elif fault_type == FaultType.NODE_RECOVERY:
            offline = self.offline_nodes
            if offline:
                node = self.rng.choice(offline)
                node.set_online(True)
                self._log_fault(step, "node_recovery", node.node_id)

        elif fault_type == FaultType.NETWORK_PARTITION:
            if self.regions:
                region = self.rng.choice(self.regions)
                region.active = False
                self._log_fault(step, "network_partition", region.name)

        elif fault_type == FaultType.PARTITION_HEAL:
            inactive = [r for r in self.regions if not r.active]
            if inactive:
                region = self.rng.choice(inactive)
                region.active = True
                self._log_fault(step, "partition_heal", region.name)

        elif fault_type == FaultType.LINK_DEGRADE:
            if len(self.regions) >= 2:
                r1, r2 = self.rng.sample(self.regions, 2)
                link = self.topology.get_link(r1.name, r2.name)
                if link:
                    link.latency_ms *= self.rng.uniform(2, 10)
                    self._log_fault(step, "link_degrade", f"{r1.name}↔{r2.name}")

        elif fault_type == FaultType.CLOCK_SKEW:
            # Only advance forward — SimClock rejects backward movement
            skew = self.rng.uniform(10, 2000)
            self.clock.advance_to(self.clock.now + skew)
            self._log_fault(step, "clock_skew", f"+{skew:.0f}ms")

        elif fault_type == FaultType.AUDIT_TICK:
            if hasattr(self, "_audit_scheduler") and self._audit_scheduler is not None:
                self._audit_epoch += 1
                results = self._audit_scheduler.tick(self._audit_epoch)
                for r in results:
                    if "eviction" in r:
                        self._eviction_history.append(
                            {
                                "step": step,
                                "epoch": self._audit_epoch,
                                **r["eviction"],
                            }
                        )
                self._log_fault(step, "audit_tick", f"epoch={self._audit_epoch}")

        elif fault_type == FaultType.SHARD_CORRUPTION:
            if hasattr(self, "_commitment_network") and self._commitment_network is not None:
                active = [n for n in self._commitment_network.nodes if not n.evicted]
                if active:
                    node = self.rng.choice(active)
                    shard_keys = list(node.shards.keys())
                    if shard_keys:
                        key = self.rng.choice(shard_keys)
                        del node.shards[key]
                        self._log_fault(step, "shard_corruption", f"{node.node_id}:{key}")

    def _log_fault(self, step: int, fault_type: str, target: str) -> None:
        """Record a fault injection event."""
        self._event_log.append(
            {
                "step": step,
                "fault": fault_type,
                "target": target,
                "time_ms": self.clock.now,
            }
        )

    # --- Commitment Network Integration ---

    def set_commitment_network(
        self,
        commitment_network,
        protocol,
        local_node_id: str = "dst-auditor",
        strike_threshold: int = 3,
    ) -> None:
        """Attach a CommitmentNetwork for audit/eviction simulation.

        Enables AUDIT_TICK and SHARD_CORRUPTION fault types and adds
        the entity_available property check.
        """
        from src.ltp.node.audit_scheduler import AuditScheduler

        self._commitment_network = commitment_network
        self._protocol = protocol
        self._audit_scheduler = AuditScheduler(
            commitment_network,
            local_node_id,
            strike_threshold=strike_threshold,
        )
        self._audit_epoch = 0
        self._eviction_history: list[dict] = []

        self.add_property("entity_available", self._prop_entity_available)

    def _prop_entity_available(self, _runner: "DSTRunner") -> bool:
        """Committed entities remain fetchable (k-of-n shards accessible)."""
        if not hasattr(self, "_commitment_network") or self._commitment_network is None:
            return True
        network = self._commitment_network
        for node in network.nodes:
            if node.evicted:
                continue
            for eid, _sidx in network._node_shard_index.get(node.node_id, set()):
                if node.fetch_shard(eid, _sidx) is None:
                    return False
        return True

    @property
    def eviction_history(self) -> list[dict]:
        """Return the eviction event history (for reproducibility checks)."""
        if hasattr(self, "_eviction_history"):
            return list(self._eviction_history)
        return []

    # --- Workload Generation ---

    def _generate_workload(self, step: int) -> None:
        """Generate simulated shard storage workload."""
        if self.rng.random() < 0.3:  # 30% chance per step
            online = self.online_nodes
            if not online:
                return

            node = self.rng.choice(online)
            entity_id = f"entity-{step}-{self.rng.randint(0, 99999)}"
            shard_data = bytes(self.rng.getrandbits(8) for _ in range(self.rng.randint(64, 4096)))

            success = node.store_shard(entity_id, step % 8, shard_data)
            if success:
                self._committed_entities.append(entity_id)
