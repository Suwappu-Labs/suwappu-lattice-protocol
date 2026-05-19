"""
Enforcement pipeline: wires isolated enforcement mechanisms into operational code.

Connects the enforcement layer (PDP, programmable slashing, VDF, disputes,
invariants, governance) to the economics engine and commitment network.

Pipeline flow:
  audit_failure → condition_evaluation → slash_computation → batch_accumulation
  → epoch_finalization → pending_slash_grace → stake_deduction

Design decision: docs/design-decisions/ENFORCEMENT_MECHANISMS.md
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

from .economics import (
    EconomicsEngine,
    NodeEconomics,
    PendingSlash,
    SlashingTier,
)
from .enforcement import (
    AuditFailureCondition,
    BatchSlashEntry,
    BatchSlashingAccumulator,
    CommitRevealEnforcement,
    DataWithholdingCondition,
    DecentralizationMetrics,
    DisputeRegistry,
    DisputeResolution,
    EnforcementInvariants,
    GovernanceTransition,
    IntersubjectiveDispute,
    LatencyDegradationCondition,
    ProofFailureCondition,
    SlashingConditionRegistry,
    SlashResult,
    StorageProofStrategy,
    VDFConfig,
    VDFVerifier,
)

__all__ = [
    "EnforcementPipelineConfig",
    "EnforcementPipeline",
]


@dataclass
class EnforcementPipelineConfig:
    """Configuration for the enforcement pipeline."""

    storage_proof_strategy: StorageProofStrategy = StorageProofStrategy.PDP
    vdf_enabled: bool = False
    vdf_config: VDFConfig = field(default_factory=VDFConfig)
    enable_runtime_invariants: bool = True
    enable_disputes: bool = False  # Only enabled in MATURITY phase
    register_default_conditions: bool = True


class EnforcementPipeline:
    """
    Orchestrates enforcement mechanisms into a coherent pipeline.

    Sits between CommitmentNetwork and the economics engine, connecting:
      - Audit results → SlashingConditionRegistry → condition evaluation
      - Condition violations → EconomicsEngine → slash computation
      - Slash amounts → BatchSlashingAccumulator → epoch batching
      - Epoch finalization → PendingSlash creation → grace period
      - Governance transitions → DecentralizationMetrics gating
    """

    def __init__(
        self,
        config: EnforcementPipelineConfig | None = None,
        message_queue=None,
        orchestrator=None,
    ) -> None:
        self.config = config or EnforcementPipelineConfig()
        self.condition_registry = SlashingConditionRegistry()
        self.batch_accumulator = BatchSlashingAccumulator()
        self.commit_reveal = CommitRevealEnforcement()
        self.dispute_registry = DisputeRegistry()
        self.governance = GovernanceTransition()
        self.vdf_verifier: Optional[VDFVerifier] = None

        # Optional cloud infrastructure
        self._message_queue = message_queue  # Optional MessageQueue
        self._orchestrator = orchestrator  # Optional WorkflowOrchestrator

        if self.config.vdf_enabled:
            self.vdf_verifier = VDFVerifier(self.config.vdf_config)

        if self.config.register_default_conditions:
            self._register_default_conditions()

        # Track pipeline activity for observability
        self._total_violations: int = 0
        self._total_slashes_queued: int = 0
        self._total_epochs_finalized: int = 0
        self._total_disputes_resolved: int = 0

    def _register_default_conditions(self) -> None:
        """Register the four built-in slashing conditions."""
        self.condition_registry.register(AuditFailureCondition(stake_allocation_bps=5000))
        self.condition_registry.register(ProofFailureCondition(stake_allocation_bps=3000))
        self.condition_registry.register(DataWithholdingCondition(stake_allocation_bps=1500))
        self.condition_registry.register(LatencyDegradationCondition(stake_allocation_bps=500))

    # ------------------------------------------------------------------
    # Audit result handling
    # ------------------------------------------------------------------

    def handle_audit_result(
        self,
        audit_result: dict,
        node: NodeEconomics,
        engine: EconomicsEngine,
        epoch: int,
        total_network_stake: int = 0,
    ) -> Optional[SlashResult]:
        """
        Process a burst-challenge audit result through the enforcement pipeline.

        If the audit failed, evaluates the AuditFailureCondition, computes
        the slash, and queues it in the batch accumulator.

        Returns the SlashResult if a violation was found, None otherwise.
        """
        if audit_result.get("result") == "PASS":
            node.clean_epochs_since_offense += 1
            return None

        # Build evidence from audit result
        evidence = json.dumps(
            {
                "node_id": node.node_id,
                "consecutive_failures": audit_result.get("strikes", node.offense_count + 1),
                "challenged": audit_result.get("challenged", 0),
                "failed": audit_result.get("failed", 0),
                "missing": audit_result.get("missing", 0),
            }
        ).encode()

        return self._evaluate_and_queue(
            condition_id="audit_failure",
            evidence=evidence,
            node=node,
            engine=engine,
            epoch=epoch,
            total_network_stake=total_network_stake,
        )

    def handle_pdp_result(
        self,
        pdp_result: dict,
        node: NodeEconomics,
        engine: EconomicsEngine,
        epoch: int,
        total_network_stake: int = 0,
    ) -> Optional[SlashResult]:
        """
        Process a PDP audit result through the enforcement pipeline.

        If proofs failed, evaluates the ProofFailureCondition.
        """
        if pdp_result.get("result") == "PASS":
            node.clean_epochs_since_offense += 1
            return None

        evidence = json.dumps(
            {
                "node_id": node.node_id,
                "proof_failures": pdp_result.get("failed", 0),
                "total_challenges": (pdp_result.get("passed", 0) + pdp_result.get("failed", 0)),
            }
        ).encode()

        return self._evaluate_and_queue(
            condition_id="proof_failure",
            evidence=evidence,
            node=node,
            engine=engine,
            epoch=epoch,
            total_network_stake=total_network_stake,
        )

    def _evaluate_and_queue(
        self,
        condition_id: str,
        evidence: bytes,
        node: NodeEconomics,
        engine: EconomicsEngine,
        epoch: int,
        total_network_stake: int = 0,
    ) -> Optional[SlashResult]:
        """Evaluate a condition and queue the slash if violated."""
        result = self.condition_registry.evaluate(condition_id, evidence)

        if not result.violated:
            return result

        self._total_violations += 1
        node.offense_count += 1
        node.clean_epochs_since_offense = 0

        # Compute slash amount via economics engine
        condition = self.condition_registry.get(condition_id)
        allocation_bps = condition.stake_allocation_bps if condition else 5000

        slash_amount, tier = engine.compute_slash_for_condition(
            node=node,
            condition_allocation_bps=allocation_bps,
            severity=result.severity,
            total_network_stake=total_network_stake,
        )

        # Queue violation — route through MessageQueue if available
        if self._message_queue is not None:
            self._message_queue.enqueue(
                str(epoch),
                {
                    "node_id": node.node_id,
                    "condition_id": condition_id,
                    "evidence_hash": result.evidence_hash,
                    "slash_amount": slash_amount,
                    "severity": result.severity,
                },
            )
        else:
            self.batch_accumulator.add(
                epoch=epoch,
                node_id=node.node_id,
                condition_id=condition_id,
                evidence_hash=result.evidence_hash,
                slash_amount=slash_amount,
                severity=result.severity,
            )
        self._total_slashes_queued += 1

        # Runtime invariant check
        if self.config.enable_runtime_invariants:
            assert EnforcementInvariants.check_safety_s1(result, True), (
                "INV-S1 violated: node slashed without violated=True"
            )
            assert EnforcementInvariants.check_safety_s4(node.total_slashed, node.stake), (
                "INV-S4 violated: total_slashed > stake"
            )

        return result

    # ------------------------------------------------------------------
    # Epoch finalization
    # ------------------------------------------------------------------

    def finalize_epoch(
        self,
        epoch: int,
        nodes: list[NodeEconomics],
        engine: EconomicsEngine,
    ) -> dict:
        """
        Finalize all enforcement actions for an epoch.

        Steps:
          1. Drain batch accumulator for this epoch
          2. Create PendingSlash for each queued slash
          3. Finalize any expired pending slashes from previous epochs
          4. Check governance transition readiness
          5. Resolve expired disputes

        Returns summary dict.
        """
        node_map = {n.node_id: n for n in nodes}

        # Drain violations — from MessageQueue if available, else batch_accumulator
        if self._message_queue is not None:
            raw_messages = self._message_queue.dequeue(str(epoch))
            batch_entries = [BatchSlashEntry(**msg["payload"]) for msg in raw_messages]
        else:
            batch_entries = self.batch_accumulator.finalize_epoch(epoch)

        # 1. Create pending slashes from batch
        pending_created = 0
        for entry in batch_entries:
            node = node_map.get(entry.node_id)
            if node is None:
                continue
            tier = _severity_to_tier(entry.severity)
            engine.create_pending_slash(
                node=node,
                slash_amount=entry.slash_amount,
                tier=tier,
                current_epoch=epoch,
            )
            pending_created += 1

        # 2. Finalize expired pending slashes
        total_finalized = 0
        total_stake_deducted = 0
        for node in nodes:
            finalized = engine.finalize_pending_slashes(node, epoch)
            for ps in finalized:
                node.stake = max(0, node.stake - ps.amount)
                node.total_slashed += ps.amount
                total_finalized += 1
                total_stake_deducted += ps.amount

                # Invariant check
                if self.config.enable_runtime_invariants:
                    assert EnforcementInvariants.check_safety_s4(
                        node.total_slashed, node.stake + node.total_slashed
                    ), "INV-S4 violated during finalization"

        # 3. Check eviction eligibility
        evicted_nodes = []
        for node in nodes:
            if not node.evicted and engine.should_evict(node):
                node.evicted = True
                evicted_nodes.append(node.node_id)

        # 4. Resolve expired disputes
        disputes_resolved = 0
        if self.config.enable_disputes:
            disputes_resolved = self._resolve_expired_disputes(epoch, node_map, engine)

        # 5. Cleanup expired commit-reveal entries
        self.commit_reveal.cleanup_expired(epoch)

        self._total_epochs_finalized += 1

        return {
            "epoch": epoch,
            "batch_entries": len(batch_entries),
            "pending_created": pending_created,
            "slashes_finalized": total_finalized,
            "stake_deducted": total_stake_deducted,
            "nodes_evicted": evicted_nodes,
            "disputes_resolved": disputes_resolved,
        }

    def _resolve_expired_disputes(
        self,
        epoch: int,
        node_map: dict[str, NodeEconomics],
        engine: EconomicsEngine,
    ) -> int:
        """Resolve disputes past voting deadline."""
        resolved = 0
        for dispute in list(self.dispute_registry.pending_disputes):
            if not dispute.can_resolve(epoch):
                continue
            resolution = self.dispute_registry.resolve(dispute.dispute_id, epoch)
            if resolution == DisputeResolution.UPHELD:
                target = node_map.get(dispute.target)
                if target:
                    engine.create_pending_slash(
                        node=target,
                        slash_amount=dispute.slash_amount,
                        tier=SlashingTier.MAJOR,
                        current_epoch=epoch,
                    )
            resolved += 1
        self._total_disputes_resolved += resolved
        return resolved

    # ------------------------------------------------------------------
    # Governance transitions
    # ------------------------------------------------------------------

    def check_governance_transition(
        self,
        from_phase: str,
        to_phase: str,
        nodes: list[NodeEconomics],
        governance_participation: float = 0.0,
    ) -> tuple[bool, list[str]]:
        """
        Check if a governance phase transition is possible.

        Computes decentralization metrics from current node state
        and checks against transition requirements.
        """
        stakes = [float(n.stake) for n in nodes if not n.evicted]
        hhi = DecentralizationMetrics.compute_hhi(stakes)
        gini = DecentralizationMetrics.compute_gini(stakes)

        metrics = DecentralizationMetrics(
            active_operators=len(stakes),
            hhi=hhi,
            gini_coefficient=gini,
            governance_participation=governance_participation,
            foundation_veto_active=(from_phase != "maturity"),
        )

        return self.governance.can_transition(from_phase, to_phase, metrics)

    def execute_governance_transition(
        self,
        from_phase: str,
        to_phase: str,
        nodes: list[NodeEconomics],
        governance_participation: float = 0.0,
    ) -> bool:
        """Execute a governance phase transition if metrics are met."""
        stakes = [float(n.stake) for n in nodes if not n.evicted]
        hhi = DecentralizationMetrics.compute_hhi(stakes)
        gini = DecentralizationMetrics.compute_gini(stakes)

        metrics = DecentralizationMetrics(
            active_operators=len(stakes),
            hhi=hhi,
            gini_coefficient=gini,
            governance_participation=governance_participation,
            foundation_veto_active=(from_phase != "maturity"),
        )

        return self.governance.execute_transition(from_phase, to_phase, metrics)

    # ------------------------------------------------------------------
    # Dispute management
    # ------------------------------------------------------------------

    def create_dispute(
        self,
        challenger: str,
        target_node: NodeEconomics,
        evidence_uri: str,
        evidence_hash: str,
        dispute_bond: int,
        slash_amount: int,
        current_epoch: int,
    ) -> IntersubjectiveDispute:
        """Create a new intersubjective dispute."""
        return self.dispute_registry.create_dispute(
            challenger=challenger,
            target=target_node.node_id,
            target_stake=target_node.stake,
            evidence_uri=evidence_uri,
            evidence_hash=evidence_hash,
            dispute_bond=dispute_bond,
            slash_amount=slash_amount,
            current_epoch=current_epoch,
        )

    def cast_dispute_vote(
        self,
        dispute_id: str,
        voter_stake: int,
        vote_for: bool,
        current_epoch: int,
    ) -> bool:
        """Cast a stake-weighted vote on a dispute."""
        return self.dispute_registry.cast_vote(dispute_id, voter_stake, vote_for, current_epoch)

    # ------------------------------------------------------------------
    # Observability
    # ------------------------------------------------------------------

    @property
    def stats(self) -> dict:
        """Pipeline activity statistics."""
        return {
            "total_violations": self._total_violations,
            "total_slashes_queued": self._total_slashes_queued,
            "total_epochs_finalized": self._total_epochs_finalized,
            "total_disputes_resolved": self._total_disputes_resolved,
            "registered_conditions": len(self.condition_registry.conditions),
            "pending_disputes": len(self.dispute_registry.pending_disputes),
            "completed_transitions": self.governance.completed_transitions,
        }


def _severity_to_tier(severity: str) -> SlashingTier:
    """Map severity string to SlashingTier."""
    mapping = {
        "warning": SlashingTier.WARNING,
        "minor": SlashingTier.MINOR,
        "major": SlashingTier.MAJOR,
        "critical": SlashingTier.CRITICAL,
    }
    return mapping.get(severity, SlashingTier.WARNING)
