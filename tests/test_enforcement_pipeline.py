"""
Tests for the EnforcementPipeline — end-to-end enforcement integration.

Tests the full pipeline:
  audit failure → condition evaluation → slash computation → batch accumulation
  → epoch finalization → pending slash → grace period → stake deduction
"""

import json

import pytest

from src.ltp.commitment import CommitmentNetwork
from src.ltp.economics import (
    WEI_PER_LTP,
    EconomicsConfig,
    EconomicsEngine,
    NodeEconomics,
    SlashingTier,
)
from src.ltp.enforcement import (
    DecentralizationMetrics,
    DisputeResolution,
    StorageProofStrategy,
    VDFConfig,
    VDFVerifier,
)
from src.ltp.enforcement_pipeline import (
    EnforcementPipeline,
    EnforcementPipelineConfig,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_engine() -> EconomicsEngine:
    return EconomicsEngine(EconomicsConfig())


def _make_node(node_id: str = "node-1", stake: int = 1000 * WEI_PER_LTP) -> NodeEconomics:
    return NodeEconomics(
        node_id=node_id,
        stake=stake,
        shards_stored=10,
        audit_score=100,
    )


def _make_pipeline(**kwargs) -> EnforcementPipeline:
    config = EnforcementPipelineConfig(**kwargs)
    return EnforcementPipeline(config)


# ---------------------------------------------------------------------------
# Pipeline config and initialization
# ---------------------------------------------------------------------------


class TestPipelineInit:
    def test_default_config(self):
        pipeline = _make_pipeline()
        assert len(pipeline.condition_registry.conditions) == 4
        assert pipeline.vdf_verifier is None
        assert pipeline.config.enable_runtime_invariants is True

    def test_vdf_enabled(self):
        pipeline = _make_pipeline(
            vdf_enabled=True,
            vdf_config=VDFConfig(enabled=True, difficulty=10),
        )
        assert pipeline.vdf_verifier is not None

    def test_no_default_conditions(self):
        pipeline = _make_pipeline(register_default_conditions=False)
        assert len(pipeline.condition_registry.conditions) == 0

    def test_default_conditions_registered(self):
        pipeline = _make_pipeline()
        conditions = pipeline.condition_registry.conditions
        assert "audit_failure" in conditions
        assert "proof_failure" in conditions
        assert "data_withholding" in conditions
        assert "latency_degradation" in conditions


# ---------------------------------------------------------------------------
# Audit result → enforcement pipeline
# ---------------------------------------------------------------------------


class TestHandleAuditResult:
    def setup_method(self):
        self.pipeline = _make_pipeline()
        self.engine = _make_engine()
        self.node = _make_node()

    def test_pass_result_no_violation(self):
        audit = {"result": "PASS", "node_id": "node-1"}
        result = self.pipeline.handle_audit_result(
            audit,
            self.node,
            self.engine,
            epoch=100,
        )
        assert result is None
        assert self.pipeline._total_violations == 0

    def test_fail_result_below_threshold(self):
        # 1 failure is below audit_failure threshold of 3
        audit = {"result": "FAIL", "strikes": 1, "challenged": 5, "failed": 1, "missing": 0}
        result = self.pipeline.handle_audit_result(
            audit,
            self.node,
            self.engine,
            epoch=100,
        )
        assert result is not None
        assert result.violated is False  # Below 3-failure threshold

    def test_fail_result_above_threshold(self):
        audit = {"result": "FAIL", "strikes": 4, "challenged": 10, "failed": 5, "missing": 2}
        result = self.pipeline.handle_audit_result(
            audit,
            self.node,
            self.engine,
            epoch=100,
        )
        assert result is not None
        assert result.violated is True
        assert result.severity == "major"
        assert self.pipeline._total_violations == 1
        assert self.pipeline._total_slashes_queued == 1

    def test_violation_queues_in_batch(self):
        audit = {"result": "FAIL", "strikes": 4, "challenged": 10, "failed": 5, "missing": 0}
        self.pipeline.handle_audit_result(
            audit,
            self.node,
            self.engine,
            epoch=100,
        )
        pending = self.pipeline.batch_accumulator.pending_for_epoch(100)
        assert len(pending) == 1
        assert pending[0].node_id == "node-1"
        assert pending[0].condition_id == "audit_failure"

    def test_violation_increments_offense(self):
        initial = self.node.offense_count
        audit = {"result": "FAIL", "strikes": 4, "challenged": 10, "failed": 5, "missing": 0}
        self.pipeline.handle_audit_result(
            audit,
            self.node,
            self.engine,
            epoch=100,
        )
        assert self.node.offense_count == initial + 1


# ---------------------------------------------------------------------------
# PDP result → enforcement pipeline
# ---------------------------------------------------------------------------


class TestHandlePDPResult:
    def setup_method(self):
        self.pipeline = _make_pipeline()
        self.engine = _make_engine()
        self.node = _make_node()

    def test_pass_result(self):
        pdp = {"result": "PASS", "passed": 3, "failed": 0}
        result = self.pipeline.handle_pdp_result(
            pdp,
            self.node,
            self.engine,
            epoch=100,
        )
        assert result is None

    def test_fail_triggers_proof_failure_condition(self):
        pdp = {"result": "FAIL", "passed": 1, "failed": 2}
        result = self.pipeline.handle_pdp_result(
            pdp,
            self.node,
            self.engine,
            epoch=100,
        )
        assert result is not None
        assert result.violated is True
        assert result.condition_id == "proof_failure"
        assert self.pipeline._total_violations == 1


# ---------------------------------------------------------------------------
# Epoch finalization
# ---------------------------------------------------------------------------


class TestEpochFinalization:
    def setup_method(self):
        self.pipeline = _make_pipeline()
        self.engine = _make_engine()
        self.nodes = [_make_node(f"node-{i}") for i in range(5)]

    def test_finalize_empty_epoch(self):
        result = self.pipeline.finalize_epoch(100, self.nodes, self.engine)
        assert result["batch_entries"] == 0
        assert result["pending_created"] == 0
        assert result["slashes_finalized"] == 0

    def test_finalize_with_queued_slash(self):
        # Queue a slash
        audit = {"result": "FAIL", "strikes": 4, "challenged": 10, "failed": 5, "missing": 0}
        self.pipeline.handle_audit_result(
            audit,
            self.nodes[0],
            self.engine,
            epoch=100,
        )

        # Finalize epoch
        result = self.pipeline.finalize_epoch(100, self.nodes, self.engine)
        assert result["batch_entries"] == 1
        assert result["pending_created"] == 1
        # Pending slash just created — not yet past grace period
        assert result["slashes_finalized"] == 0

    def test_pending_slash_finalizes_after_grace(self):
        # Queue and finalize to create pending slash at epoch 100
        audit = {"result": "FAIL", "strikes": 4, "challenged": 10, "failed": 5, "missing": 0}
        self.pipeline.handle_audit_result(
            audit,
            self.nodes[0],
            self.engine,
            epoch=100,
        )
        self.pipeline.finalize_epoch(100, self.nodes, self.engine)

        # Now finalize well past grace period (168 epochs)
        result = self.pipeline.finalize_epoch(300, self.nodes, self.engine)
        assert result["slashes_finalized"] == 1
        assert result["stake_deducted"] > 0

    def test_eviction_on_high_offense(self):
        node = self.nodes[0]
        node.offense_count = 6  # Above default eviction threshold

        result = self.pipeline.finalize_epoch(100, self.nodes, self.engine)
        assert node.node_id in result["nodes_evicted"]
        assert node.evicted is True

    def test_commit_reveal_cleanup(self):
        # Create an expired commit-reveal entry
        self.pipeline.commit_reveal.commit(b"evidence", "submitter", 10)
        # Finalize at epoch well past reveal window
        self.pipeline.finalize_epoch(100, self.nodes, self.engine)
        # Entry should be cleaned up (no assertion needed — just verifying no crash)


# ---------------------------------------------------------------------------
# Multiple violations in single epoch (batch processing)
# ---------------------------------------------------------------------------


class TestBatchProcessing:
    def test_multiple_nodes_slashed_in_epoch(self):
        pipeline = _make_pipeline()
        engine = _make_engine()
        nodes = [_make_node(f"node-{i}") for i in range(3)]

        # All three nodes fail audit
        for node in nodes:
            audit = {"result": "FAIL", "strikes": 4, "challenged": 10, "failed": 5, "missing": 0}
            pipeline.handle_audit_result(audit, node, engine, epoch=100)

        # All queued in same epoch
        pending = pipeline.batch_accumulator.pending_for_epoch(100)
        assert len(pending) == 3

        # Finalize
        result = pipeline.finalize_epoch(100, nodes, engine)
        assert result["batch_entries"] == 3
        assert result["pending_created"] == 3


# ---------------------------------------------------------------------------
# VDF integration
# ---------------------------------------------------------------------------


class TestVDFIntegration:
    def test_vdf_challenge_in_audit(self):
        pipeline = _make_pipeline(
            vdf_enabled=True,
            vdf_config=VDFConfig(enabled=True, difficulty=5),
        )
        assert pipeline.vdf_verifier is not None

        # Generate and verify a VDF challenge
        challenge = pipeline.vdf_verifier.generate_challenge("entity-1", 0, 100)
        result = pipeline.vdf_verifier.evaluate(challenge)
        assert pipeline.vdf_verifier.verify(challenge, result) is True

    def test_commitment_network_vdf_audit(self):
        """Test VDF integration through CommitmentNetwork.audit_node_pdp()."""
        network = CommitmentNetwork()
        for i in range(5):
            network.add_node(f"node-{i}", f"region-{i % 3}")

        # Commit some data
        from src.ltp.primitives import canonical_hash

        entity_id = canonical_hash(b"test-entity")
        shards = [b"shard-" + bytes([i]) * 100 for i in range(8)]
        network.distribute_encrypted_shards(entity_id, shards)

        # Create VDF verifier
        vdf = VDFVerifier(VDFConfig(enabled=True, difficulty=5))

        # Run PDP audit with VDF
        target = None
        for n in network.nodes:
            if n.shard_count > 0:
                target = n
                break

        if target:
            result = network.audit_node_pdp(target, epoch=100, vdf_verifier=vdf)
            assert "vdf" in result
            assert result["vdf"]["verified"] is True


# ---------------------------------------------------------------------------
# Dispute integration
# ---------------------------------------------------------------------------


class TestDisputeIntegration:
    def setup_method(self):
        self.pipeline = _make_pipeline(enable_disputes=True)
        self.engine = _make_engine()
        self.target = _make_node("target", stake=1000 * WEI_PER_LTP)

    def test_create_dispute(self):
        dispute = self.pipeline.create_dispute(
            challenger="challenger-1",
            target_node=self.target,
            evidence_uri="ipfs://evidence",
            evidence_hash="abc123",
            dispute_bond=10 * WEI_PER_LTP,
            slash_amount=50 * WEI_PER_LTP,
            current_epoch=100,
        )
        assert dispute.dispute_id == "dispute-1"
        assert dispute.resolution == DisputeResolution.PENDING
        assert len(self.pipeline.dispute_registry.pending_disputes) == 1

    def test_dispute_voting_and_resolution(self):
        dispute = self.pipeline.create_dispute(
            challenger="challenger-1",
            target_node=self.target,
            evidence_uri="ipfs://evidence",
            evidence_hash="abc123",
            dispute_bond=10 * WEI_PER_LTP,
            slash_amount=50 * WEI_PER_LTP,
            current_epoch=100,
        )

        # Cast votes (>66% for = upheld)
        self.pipeline.cast_dispute_vote(dispute.dispute_id, 700, True, 150)
        self.pipeline.cast_dispute_vote(dispute.dispute_id, 300, False, 150)

        # Resolve after voting deadline (100 + 168 = 268)
        nodes = [self.target]
        result = self.pipeline.finalize_epoch(270, nodes, self.engine)
        assert result["disputes_resolved"] == 1

        resolved = self.pipeline.dispute_registry.get(dispute.dispute_id)
        assert resolved.resolution == DisputeResolution.UPHELD

    def test_dispute_bond_too_low(self):
        with pytest.raises(ValueError, match="below minimum"):
            self.pipeline.create_dispute(
                challenger="challenger-1",
                target_node=self.target,
                evidence_uri="ipfs://evidence",
                evidence_hash="abc123",
                dispute_bond=1,  # Way below 1% of stake
                slash_amount=50 * WEI_PER_LTP,
                current_epoch=100,
            )


# ---------------------------------------------------------------------------
# Governance transitions
# ---------------------------------------------------------------------------


class TestGovernanceTransitions:
    def test_bootstrap_to_growth_ready(self):
        pipeline = _make_pipeline()
        nodes = [_make_node(f"node-{i}") for i in range(10)]
        can, unmet = pipeline.check_governance_transition(
            "bootstrap",
            "growth",
            nodes,
            governance_participation=0.0,
        )
        assert can is True
        assert len(unmet) == 0

    def test_bootstrap_to_growth_not_enough_operators(self):
        pipeline = _make_pipeline()
        nodes = [_make_node(f"node-{i}") for i in range(3)]
        can, unmet = pipeline.check_governance_transition(
            "bootstrap",
            "growth",
            nodes,
        )
        assert can is False
        assert any("Operators" in u for u in unmet)

    def test_growth_to_maturity_requires_decentralization(self):
        pipeline = _make_pipeline()
        # Only 5 nodes — maturity needs 100
        nodes = [_make_node(f"node-{i}") for i in range(5)]
        can, unmet = pipeline.check_governance_transition(
            "growth",
            "maturity",
            nodes,
            governance_participation=0.20,
        )
        assert can is False
        assert any("Operators" in u for u in unmet)

    def test_execute_transition(self):
        pipeline = _make_pipeline()
        nodes = [_make_node(f"node-{i}") for i in range(10)]
        executed = pipeline.execute_governance_transition(
            "bootstrap",
            "growth",
            nodes,
        )
        assert executed is True
        assert "bootstrap_to_growth" in pipeline.governance.completed_transitions

    def test_transition_irreversible(self):
        pipeline = _make_pipeline()
        nodes = [_make_node(f"node-{i}") for i in range(10)]
        pipeline.execute_governance_transition("bootstrap", "growth", nodes)
        # Second attempt fails
        executed = pipeline.execute_governance_transition("bootstrap", "growth", nodes)
        assert executed is False


# ---------------------------------------------------------------------------
# Runtime invariant checking
# ---------------------------------------------------------------------------


class TestRuntimeInvariants:
    def test_invariants_enabled(self):
        pipeline = _make_pipeline(enable_runtime_invariants=True)
        engine = _make_engine()
        node = _make_node()

        # This should not raise (valid audit result)
        audit = {"result": "FAIL", "strikes": 4, "challenged": 10, "failed": 5, "missing": 0}
        pipeline.handle_audit_result(audit, node, engine, epoch=100)
        # If we got here, invariants held

    def test_invariants_disabled(self):
        pipeline = _make_pipeline(enable_runtime_invariants=False)
        engine = _make_engine()
        node = _make_node()

        audit = {"result": "FAIL", "strikes": 4, "challenged": 10, "failed": 5, "missing": 0}
        # Should not raise even with invariants disabled
        pipeline.handle_audit_result(audit, node, engine, epoch=100)


# ---------------------------------------------------------------------------
# Backward compatibility
# ---------------------------------------------------------------------------


class TestBackwardCompatibility:
    def test_commitment_network_without_pipeline(self):
        """CommitmentNetwork works without pipeline attached."""
        network = CommitmentNetwork()
        assert network._enforcement_pipeline is None
        for i in range(5):
            network.add_node(f"node-{i}", f"region-{i}")
        # Audit works without pipeline
        target = network.nodes[0]
        result = network.audit_node(target)
        assert result.result in ("PASS", "FAIL")

    def test_audit_node_pdp_without_vdf(self):
        """PDP audit works without VDF verifier."""
        network = CommitmentNetwork()
        for i in range(5):
            network.add_node(f"node-{i}", f"region-{i}")

        from src.ltp.primitives import canonical_hash

        entity_id = canonical_hash(b"test-entity")
        shards = [b"shard-" + bytes([i]) * 100 for i in range(8)]
        network.distribute_encrypted_shards(entity_id, shards)

        target = None
        for n in network.nodes:
            if n.shard_count > 0:
                target = n
                break

        if target:
            result = network.audit_node_pdp(target, epoch=100)
            assert "vdf" not in result
            assert result["result"] in ("PASS", "FAIL")


# ---------------------------------------------------------------------------
# Pipeline stats
# ---------------------------------------------------------------------------


class TestPipelineStats:
    def test_initial_stats(self):
        pipeline = _make_pipeline()
        stats = pipeline.stats
        assert stats["total_violations"] == 0
        assert stats["total_slashes_queued"] == 0
        assert stats["total_epochs_finalized"] == 0
        assert stats["registered_conditions"] == 4

    def test_stats_after_activity(self):
        pipeline = _make_pipeline()
        engine = _make_engine()
        node = _make_node()

        audit = {"result": "FAIL", "strikes": 4, "challenged": 10, "failed": 5, "missing": 0}
        pipeline.handle_audit_result(audit, node, engine, epoch=100)
        pipeline.finalize_epoch(100, [node], engine)

        stats = pipeline.stats
        assert stats["total_violations"] == 1
        assert stats["total_slashes_queued"] == 1
        assert stats["total_epochs_finalized"] == 1


# ---------------------------------------------------------------------------
# Ethereum backend parity
# ---------------------------------------------------------------------------


class TestEthereumBackendParity:
    def test_slash_with_correlation_penalty(self):
        from src.ltp.backends import BackendConfig, create_backend

        backend = create_backend(
            BackendConfig(
                backend_type="ethereum",
                eth_finality_mode="latest",
            )
        )
        backend.register_node("node-1", "us-east", stake_wei=1000 * WEI_PER_LTP)

        # Slash with correlation context
        amount = backend.slash_node(
            "node-1",
            b"evidence",
            concurrent_slashed_stake=500 * WEI_PER_LTP,
            total_network_stake=2000 * WEI_PER_LTP,
        )
        assert amount > 0

    def test_pending_slash_grace_period(self):
        from src.ltp.backends import BackendConfig, create_backend

        backend = create_backend(
            BackendConfig(
                backend_type="ethereum",
                eth_finality_mode="latest",
            )
        )
        backend.register_node("node-1", "us-east", stake_wei=1000 * WEI_PER_LTP)

        # Slash creates pending entry
        backend.slash_node("node-1", b"evidence")

        # Pending slashes exist
        pending = backend.finalize_pending_slashes()
        # Grace period not met yet (block 0 + 168 > current block ~1)
        assert len(pending) == 0

    def test_correlation_penalty_increases_slash(self):
        from src.ltp.backends import BackendConfig, create_backend

        backend = create_backend(
            BackendConfig(
                backend_type="ethereum",
                eth_finality_mode="latest",
            )
        )
        backend.register_node("node-a", "us-east", stake_wei=1000 * WEI_PER_LTP)
        backend.register_node("node-b", "us-west", stake_wei=1000 * WEI_PER_LTP)

        # Slash without correlation
        amount_solo = backend.slash_node("node-a", b"evidence")

        # Slash with high correlation
        amount_correlated = backend.slash_node(
            "node-b",
            b"evidence",
            concurrent_slashed_stake=1000 * WEI_PER_LTP,
            total_network_stake=2000 * WEI_PER_LTP,
        )

        assert amount_correlated > amount_solo
