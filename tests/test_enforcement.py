"""
Tests for the LTP enforcement mechanisms module.

Covers:
  1. PDP (Proof of Data Possession) — cryptographic storage verification
  2. Programmable slashing conditions — extensible enforcement rules
  3. Intersubjective disputes — social consensus for subjective faults
  4. VDF-enhanced audits — physics-based timing guarantees
  5. MEV-protected enforcement — commit-reveal + batch slashing
  6. Formal verification invariants — mathematical correctness properties
  7. Progressive decentralization — automated governance transitions
  8. Integration with economics engine — compute_slash_for_condition
  9. Integration with commitment network — PDP audit via CommitmentNetwork
"""

import json

import pytest

from src.ltp.economics import (
    WEI_PER_LTP,
    EconomicsConfig,
    EconomicsEngine,
    NodeEconomics,
    SlashingTier,
)
from src.ltp.enforcement import (
    AuditFailureCondition,
    BatchSlashingAccumulator,
    # MEV protection
    CommitRevealEnforcement,
    DataWithholdingCondition,
    # Progressive decentralization
    DecentralizationMetrics,
    DisputeRegistry,
    # Intersubjective disputes
    DisputeResolution,
    # Formal verification
    EnforcementInvariants,
    GovernanceTransition,
    IntersubjectiveDispute,
    LatencyDegradationCondition,
    PDPChallenge,
    PDPProof,
    PDPVerifier,
    ProofFailureCondition,
    SlashingCondition,
    SlashingConditionRegistry,
    # Programmable slashing
    SlashResult,
    # Storage proofs
    StorageProofStrategy,
    VDFChallenge,
    # VDF
    VDFConfig,
    VDFConstruction,
    VDFResult,
    VDFVerifier,
)
from src.ltp.primitives import canonical_hash

# ===========================================================================
# 1. PDP Storage Proofs
# ===========================================================================


class TestPDPChallenge:
    def test_generate_challenge(self):
        challenge = PDPChallenge.generate(
            entity_id="entity-1",
            total_shards=8,
            sample_size=4,
            epoch=100,
        )
        assert challenge.challenge_id
        assert len(challenge.shard_indices) == 4
        assert len(challenge.coefficients) == 4
        assert challenge.epoch == 100
        assert challenge.deadline_epoch == 101

    def test_challenge_indices_within_range(self):
        challenge = PDPChallenge.generate(
            entity_id="entity-2",
            total_shards=8,
            sample_size=4,
            epoch=42,
        )
        for idx in challenge.shard_indices:
            assert 0 <= idx < 8

    def test_challenge_indices_unique(self):
        challenge = PDPChallenge.generate(
            entity_id="entity-3",
            total_shards=8,
            sample_size=8,
            epoch=1,
        )
        assert len(set(challenge.shard_indices)) == len(challenge.shard_indices)

    def test_sample_size_capped_at_total_shards(self):
        challenge = PDPChallenge.generate(
            entity_id="entity-4",
            total_shards=3,
            sample_size=10,
            epoch=1,
        )
        assert len(challenge.shard_indices) == 3

    def test_deterministic_for_same_inputs(self):
        c1 = PDPChallenge.generate("entity-5", 8, 4, 100)
        c2 = PDPChallenge.generate("entity-5", 8, 4, 100)
        assert c1.shard_indices == c2.shard_indices
        assert c1.coefficients == c2.coefficients

    def test_different_epochs_different_challenges(self):
        c1 = PDPChallenge.generate("entity-6", 8, 4, 100)
        c2 = PDPChallenge.generate("entity-6", 8, 4, 101)
        assert c1.shard_indices != c2.shard_indices or c1.coefficients != c2.coefficients


class TestPDPVerifier:
    def _make_shards(self, count: int = 8) -> dict[int, bytes]:
        return {i: f"shard-data-{i}".encode() for i in range(count)}

    def test_valid_proof_passes(self):
        shards = self._make_shards()
        verifier = PDPVerifier()

        # Register shard hashes (verifier knows the expected hashes)
        shard_hashes = {i: canonical_hash(data) for i, data in shards.items()}
        verifier.register_commitment("entity-1", shard_hashes)

        # Generate challenge
        challenge = PDPChallenge.generate("entity-1", 8, 4, 100)

        # Node computes proof
        proof = PDPVerifier.compute_proof_from_shards(
            shards,
            challenge.shard_indices,
            challenge.coefficients,
            challenge.challenge_id,
        )

        # Verify
        assert verifier.verify_proof("entity-1", challenge, proof)

    def test_missing_shard_fails_verification(self):
        shards = self._make_shards()
        verifier = PDPVerifier()

        shard_hashes = {i: canonical_hash(data) for i, data in shards.items()}
        verifier.register_commitment("entity-2", shard_hashes)

        challenge = PDPChallenge.generate("entity-2", 8, 4, 100)

        # Remove one shard that's in the challenge
        incomplete_shards = {
            k: v for k, v in shards.items() if k not in challenge.shard_indices[:1]
        }

        proof = PDPVerifier.compute_proof_from_shards(
            incomplete_shards,
            challenge.shard_indices,
            challenge.coefficients,
            challenge.challenge_id,
        )

        assert not verifier.verify_proof("entity-2", challenge, proof)

    def test_corrupted_shard_fails_verification(self):
        shards = self._make_shards()
        verifier = PDPVerifier()

        shard_hashes = {i: canonical_hash(data) for i, data in shards.items()}
        verifier.register_commitment("entity-3", shard_hashes)

        challenge = PDPChallenge.generate("entity-3", 8, 4, 100)

        # Corrupt one shard
        corrupted = dict(shards)
        target = challenge.shard_indices[0]
        corrupted[target] = b"corrupted-data"

        proof = PDPVerifier.compute_proof_from_shards(
            corrupted,
            challenge.shard_indices,
            challenge.coefficients,
            challenge.challenge_id,
        )

        assert not verifier.verify_proof("entity-3", challenge, proof)

    def test_wrong_challenge_id_fails(self):
        shards = self._make_shards()
        verifier = PDPVerifier()
        shard_hashes = {i: canonical_hash(data) for i, data in shards.items()}
        verifier.register_commitment("entity-4", shard_hashes)

        challenge = PDPChallenge.generate("entity-4", 8, 4, 100)

        proof = PDPVerifier.compute_proof_from_shards(
            shards,
            challenge.shard_indices,
            challenge.coefficients,
            "wrong-challenge-id",
        )
        assert not verifier.verify_proof("entity-4", challenge, proof)

    def test_proof_size_is_compact(self):
        shards = self._make_shards()
        challenge = PDPChallenge.generate("entity-5", 8, 4, 100)

        proof = PDPVerifier.compute_proof_from_shards(
            shards,
            challenge.shard_indices,
            challenge.coefficients,
            challenge.challenge_id,
        )

        # PDP proof should be ≤ 160 bytes (20 bytes aggregate tag)
        assert proof.proof_size_bytes <= 160

    def test_unknown_entity_returns_none(self):
        verifier = PDPVerifier()
        result = verifier.generate_expected_tag("unknown", [0], [b"\x00" * 16])
        assert result is None


class TestStorageProofStrategy:
    def test_enum_values(self):
        assert StorageProofStrategy.BURST_CHALLENGE.value == "burst_challenge"
        assert StorageProofStrategy.PDP.value == "pdp"
        assert StorageProofStrategy.HYBRID.value == "hybrid"


# ===========================================================================
# 2. Programmable Slashing Conditions
# ===========================================================================


class TestAuditFailureCondition:
    def test_below_threshold_not_violated(self):
        condition = AuditFailureCondition()
        evidence = json.dumps({"consecutive_failures": 2}).encode()
        result = condition.evaluate(evidence)
        assert not result.violated
        assert result.condition_id == "audit_failure"

    def test_at_threshold_violated(self):
        condition = AuditFailureCondition()
        evidence = json.dumps({"consecutive_failures": 3}).encode()
        result = condition.evaluate(evidence)
        assert result.violated
        assert result.severity == "minor"

    def test_critical_severity(self):
        condition = AuditFailureCondition()
        evidence = json.dumps({"consecutive_failures": 6}).encode()
        result = condition.evaluate(evidence)
        assert result.violated
        assert result.severity == "critical"

    def test_invalid_evidence_not_violated(self):
        condition = AuditFailureCondition()
        result = condition.evaluate(b"not-json")
        assert not result.violated

    def test_stake_allocation(self):
        condition = AuditFailureCondition(stake_allocation_bps=3000)
        assert condition.stake_allocation_bps == 3000


class TestDataWithholdingCondition:
    def test_withholding_detected(self):
        condition = DataWithholdingCondition()
        evidence = json.dumps(
            {
                "refused_fetches": 5,
                "corroborating_nodes": 3,
            }
        ).encode()
        result = condition.evaluate(evidence)
        assert result.violated
        assert result.severity == "major"

    def test_insufficient_corroboration(self):
        condition = DataWithholdingCondition()
        evidence = json.dumps(
            {
                "refused_fetches": 5,
                "corroborating_nodes": 1,
            }
        ).encode()
        result = condition.evaluate(evidence)
        assert not result.violated

    def test_few_refused_fetches(self):
        condition = DataWithholdingCondition()
        evidence = json.dumps(
            {
                "refused_fetches": 2,
                "corroborating_nodes": 5,
            }
        ).encode()
        result = condition.evaluate(evidence)
        assert not result.violated


class TestLatencyDegradationCondition:
    def test_high_latency_violated(self):
        condition = LatencyDegradationCondition(max_avg_latency_ms=50.0)
        evidence = json.dumps(
            {
                "avg_latency_ms": 75.0,
                "sample_count": 20,
            }
        ).encode()
        result = condition.evaluate(evidence)
        assert result.violated

    def test_low_latency_not_violated(self):
        condition = LatencyDegradationCondition(max_avg_latency_ms=100.0)
        evidence = json.dumps(
            {
                "avg_latency_ms": 30.0,
                "sample_count": 20,
            }
        ).encode()
        result = condition.evaluate(evidence)
        assert not result.violated

    def test_insufficient_samples(self):
        condition = LatencyDegradationCondition(min_samples=10)
        evidence = json.dumps(
            {
                "avg_latency_ms": 200.0,
                "sample_count": 5,
            }
        ).encode()
        result = condition.evaluate(evidence)
        assert not result.violated


class TestProofFailureCondition:
    def test_proof_failure_violated(self):
        condition = ProofFailureCondition()
        evidence = json.dumps(
            {
                "proof_failures": 3,
                "total_challenges": 10,
            }
        ).encode()
        result = condition.evaluate(evidence)
        assert result.violated
        assert result.severity == "major"

    def test_high_failure_rate_critical(self):
        condition = ProofFailureCondition()
        evidence = json.dumps(
            {
                "proof_failures": 8,
                "total_challenges": 10,
            }
        ).encode()
        result = condition.evaluate(evidence)
        assert result.violated
        assert result.severity == "critical"

    def test_no_failures_not_violated(self):
        condition = ProofFailureCondition()
        evidence = json.dumps(
            {
                "proof_failures": 0,
                "total_challenges": 10,
            }
        ).encode()
        result = condition.evaluate(evidence)
        assert not result.violated


class TestSlashingConditionRegistry:
    def test_register_and_evaluate(self):
        registry = SlashingConditionRegistry()
        registry.register(AuditFailureCondition(stake_allocation_bps=5000))

        evidence = json.dumps({"consecutive_failures": 4}).encode()
        result = registry.evaluate("audit_failure", evidence)
        assert result.violated

    def test_duplicate_registration_raises(self):
        registry = SlashingConditionRegistry()
        registry.register(AuditFailureCondition())
        with pytest.raises(ValueError, match="already registered"):
            registry.register(AuditFailureCondition())

    def test_allocation_overflow_raises(self):
        registry = SlashingConditionRegistry(max_total_allocation_bps=10_000)
        registry.register(AuditFailureCondition(stake_allocation_bps=8000))
        with pytest.raises(ValueError, match="exceed"):
            registry.register(DataWithholdingCondition(stake_allocation_bps=3000))

    def test_unknown_condition_not_violated(self):
        registry = SlashingConditionRegistry()
        result = registry.evaluate("nonexistent", b"evidence")
        assert not result.violated

    def test_unregister(self):
        registry = SlashingConditionRegistry()
        registry.register(AuditFailureCondition())
        assert registry.unregister("audit_failure")
        assert not registry.unregister("audit_failure")

    def test_total_allocation(self):
        registry = SlashingConditionRegistry()
        registry.register(AuditFailureCondition(stake_allocation_bps=5000))
        registry.register(DataWithholdingCondition(stake_allocation_bps=3000))
        assert registry.total_allocation_bps == 8000

    def test_evaluate_all(self):
        registry = SlashingConditionRegistry()
        registry.register(AuditFailureCondition(stake_allocation_bps=5000))
        registry.register(DataWithholdingCondition(stake_allocation_bps=3000))

        evidence = json.dumps(
            {
                "consecutive_failures": 4,
                "refused_fetches": 0,
                "corroborating_nodes": 0,
            }
        ).encode()

        results = registry.evaluate_all(evidence)
        assert len(results) == 2


# ===========================================================================
# 3. Intersubjective Disputes
# ===========================================================================


class TestDisputeRegistry:
    def test_create_dispute(self):
        registry = DisputeRegistry()
        dispute = registry.create_dispute(
            challenger="node-A",
            target="node-B",
            target_stake=100_000,
            evidence_uri="ipfs://evidence-hash",
            evidence_hash="abc123",
            dispute_bond=1_500,
            slash_amount=10_000,
            current_epoch=100,
        )
        assert dispute.resolution == DisputeResolution.PENDING
        assert dispute.voting_deadline_epoch == 100 + 168
        assert dispute.challenger == "node-A"
        assert dispute.target == "node-B"

    def test_bond_too_low_raises(self):
        registry = DisputeRegistry()
        with pytest.raises(ValueError, match="below minimum"):
            registry.create_dispute(
                challenger="node-A",
                target="node-B",
                target_stake=100_000,
                evidence_uri="ipfs://evidence",
                evidence_hash="abc",
                dispute_bond=500,  # < 1% of 100_000
                slash_amount=10_000,
                current_epoch=100,
            )

    def test_voting_and_resolution_upheld(self):
        registry = DisputeRegistry()
        dispute = registry.create_dispute(
            challenger="node-A",
            target="node-B",
            target_stake=100_000,
            evidence_uri="ipfs://evidence",
            evidence_hash="abc",
            dispute_bond=2_000,
            slash_amount=10_000,
            current_epoch=100,
        )

        # Cast votes (>66% for upheld)
        registry.cast_vote(dispute.dispute_id, 70_000, True, 150)
        registry.cast_vote(dispute.dispute_id, 30_000, False, 150)

        # Cannot resolve during voting
        assert registry.resolve(dispute.dispute_id, 150) is None

        # Resolve after deadline
        result = registry.resolve(dispute.dispute_id, 269)
        assert result == DisputeResolution.UPHELD

    def test_voting_and_resolution_rejected(self):
        registry = DisputeRegistry()
        dispute = registry.create_dispute(
            challenger="node-A",
            target="node-B",
            target_stake=100_000,
            evidence_uri="ipfs://evidence",
            evidence_hash="abc",
            dispute_bond=2_000,
            slash_amount=10_000,
            current_epoch=100,
        )

        # Cast votes (<66% for rejected)
        registry.cast_vote(dispute.dispute_id, 40_000, True, 150)
        registry.cast_vote(dispute.dispute_id, 60_000, False, 150)

        result = registry.resolve(dispute.dispute_id, 269)
        assert result == DisputeResolution.REJECTED

    def test_voting_closed_after_deadline(self):
        registry = DisputeRegistry()
        dispute = registry.create_dispute(
            challenger="A",
            target="B",
            target_stake=100_000,
            evidence_uri="x",
            evidence_hash="h",
            dispute_bond=1_500,
            slash_amount=1_000,
            current_epoch=100,
        )

        # Vote after deadline fails
        assert not registry.cast_vote(dispute.dispute_id, 50_000, True, 300)

    def test_pending_disputes(self):
        registry = DisputeRegistry()
        registry.create_dispute(
            challenger="A",
            target="B",
            target_stake=100_000,
            evidence_uri="x",
            evidence_hash="h",
            dispute_bond=1_500,
            slash_amount=1_000,
            current_epoch=100,
        )
        assert len(registry.pending_disputes) == 1


class TestIntersubjectiveDispute:
    def test_approval_ratio(self):
        dispute = IntersubjectiveDispute(
            dispute_id="d1",
            challenger="A",
            target="B",
            evidence_uri="x",
            evidence_hash="h",
            dispute_bond=100,
            slash_amount=1000,
            votes_for=70,
            votes_against=30,
        )
        assert dispute.approval_ratio == pytest.approx(0.7)

    def test_zero_votes_ratio(self):
        dispute = IntersubjectiveDispute(
            dispute_id="d2",
            challenger="A",
            target="B",
            evidence_uri="x",
            evidence_hash="h",
            dispute_bond=100,
            slash_amount=1000,
        )
        assert dispute.approval_ratio == 0.0


# ===========================================================================
# 4. VDF-Enhanced Audits
# ===========================================================================


class TestVDFVerifier:
    def test_evaluate_and_verify(self):
        config = VDFConfig(
            enabled=True,
            construction=VDFConstruction.WESOLOWSKI,
            difficulty=10,  # Low for testing
            group_bits=512,  # Smaller for test speed
        )
        verifier = VDFVerifier(config)

        challenge = verifier.generate_challenge("entity-1", 0, 100)
        result = verifier.evaluate(challenge)

        assert result.challenge_id == challenge.challenge_id
        assert result.vdf_output
        assert result.vdf_proof
        assert result.computation_time_ms >= 0

        # Verification should pass
        assert verifier.verify(challenge, result)

    def test_wrong_challenge_fails_verification(self):
        config = VDFConfig(enabled=True, difficulty=10)
        verifier = VDFVerifier(config)

        c1 = verifier.generate_challenge("entity-1", 0, 100)
        c2 = verifier.generate_challenge("entity-2", 0, 100)

        result = verifier.evaluate(c1)
        assert not verifier.verify(c2, result)

    def test_tampered_output_fails(self):
        config = VDFConfig(enabled=True, difficulty=10)
        verifier = VDFVerifier(config)

        challenge = verifier.generate_challenge("entity-1", 0, 100)
        result = verifier.evaluate(challenge)

        # Tamper with output
        tampered = VDFResult(
            challenge_id=result.challenge_id,
            vdf_output=b"\x00" * 32,
            vdf_proof=result.vdf_proof,
            shard_proof=result.shard_proof,
            computation_time_ms=result.computation_time_ms,
        )
        assert not verifier.verify(challenge, tampered)


# ===========================================================================
# 5. MEV-Protected Enforcement
# ===========================================================================


class TestCommitRevealEnforcement:
    def test_commit_and_reveal(self):
        cr = CommitRevealEnforcement()
        evidence = b"slashing-evidence-data"

        commitment_hash = cr.commit(evidence, "submitter-1", 100)
        assert commitment_hash

        entry = cr.get(commitment_hash)
        assert entry is not None
        assert not entry.revealed

        # Reveal in next epoch
        revealed = cr.reveal(commitment_hash, entry.evidence, entry.salt, 101)
        assert revealed == evidence
        assert cr.get(commitment_hash).revealed

    def test_cannot_reveal_same_epoch(self):
        cr = CommitRevealEnforcement()
        evidence = b"evidence"
        commitment_hash = cr.commit(evidence, "submitter", 100)
        entry = cr.get(commitment_hash)

        result = cr.reveal(commitment_hash, entry.evidence, entry.salt, 100)
        assert result is None

    def test_cannot_reveal_after_window(self):
        cr = CommitRevealEnforcement()
        evidence = b"evidence"
        commitment_hash = cr.commit(evidence, "submitter", 100)
        entry = cr.get(commitment_hash)

        result = cr.reveal(commitment_hash, entry.evidence, entry.salt, 200)
        assert result is None

    def test_wrong_evidence_fails_reveal(self):
        cr = CommitRevealEnforcement()
        evidence = b"evidence"
        commitment_hash = cr.commit(evidence, "submitter", 100)
        entry = cr.get(commitment_hash)

        result = cr.reveal(commitment_hash, b"wrong", entry.salt, 101)
        assert result is None

    def test_cleanup_expired(self):
        cr = CommitRevealEnforcement()
        cr.commit(b"e1", "s1", 1)
        cr.commit(b"e2", "s2", 2)

        removed = cr.cleanup_expired(100)
        assert removed == 2

    def test_double_reveal_fails(self):
        cr = CommitRevealEnforcement()
        evidence = b"evidence"
        commitment_hash = cr.commit(evidence, "submitter", 100)
        entry = cr.get(commitment_hash)

        cr.reveal(commitment_hash, entry.evidence, entry.salt, 101)
        result = cr.reveal(commitment_hash, entry.evidence, entry.salt, 102)
        assert result is None


class TestBatchSlashingAccumulator:
    def test_add_and_finalize(self):
        acc = BatchSlashingAccumulator()
        acc.add(
            epoch=10,
            node_id="node-1",
            condition_id="audit_failure",
            evidence_hash="h1",
            slash_amount=1000,
            severity="minor",
        )
        acc.add(
            epoch=10,
            node_id="node-2",
            condition_id="data_withholding",
            evidence_hash="h2",
            slash_amount=2000,
            severity="major",
        )

        batch = acc.finalize_epoch(10)
        assert len(batch) == 2
        assert batch[0].node_id == "node-1"
        assert batch[1].node_id == "node-2"

        # Finalize again returns empty (already processed)
        assert len(acc.finalize_epoch(10)) == 0

    def test_pending_epochs(self):
        acc = BatchSlashingAccumulator()
        acc.add(
            epoch=5,
            node_id="n1",
            condition_id="c1",
            evidence_hash="h",
            slash_amount=100,
            severity="minor",
        )
        acc.add(
            epoch=10,
            node_id="n2",
            condition_id="c2",
            evidence_hash="h",
            slash_amount=200,
            severity="major",
        )

        assert acc.pending_epochs == [5, 10]

    def test_pending_for_epoch_non_destructive(self):
        acc = BatchSlashingAccumulator()
        acc.add(
            epoch=5,
            node_id="n1",
            condition_id="c1",
            evidence_hash="h",
            slash_amount=100,
            severity="minor",
        )

        pending = acc.pending_for_epoch(5)
        assert len(pending) == 1

        # Still there after viewing
        assert len(acc.pending_for_epoch(5)) == 1


# ===========================================================================
# 6. Formal Verification Invariants
# ===========================================================================


class TestEnforcementInvariants:
    def test_safety_s1_slashed_requires_violation(self):
        result = SlashResult(
            violated=False,
            severity="none",
            evidence_hash="h",
            explanation="no violation",
            condition_id="test",
        )
        # Slashed when not violated = invariant violation
        assert not EnforcementInvariants.check_safety_s1(result, node_was_slashed=True)
        # Not slashed = always safe
        assert EnforcementInvariants.check_safety_s1(result, node_was_slashed=False)
        # Slashed when violated = correct
        result.violated = True
        assert EnforcementInvariants.check_safety_s1(result, node_was_slashed=True)

    def test_safety_s2_clean_node_no_offense(self):
        # All passed, offense incremented = violation
        assert not EnforcementInvariants.check_safety_s2(True, True, True)
        # All passed, no increment = correct
        assert EnforcementInvariants.check_safety_s2(True, True, False)
        # Failed audit, increment = correct
        assert EnforcementInvariants.check_safety_s2(False, True, True)

    def test_safety_s3_reversed_no_deduction(self):
        assert not EnforcementInvariants.check_safety_s3(True, True)
        assert EnforcementInvariants.check_safety_s3(True, False)
        assert EnforcementInvariants.check_safety_s3(False, True)

    def test_safety_s4_slash_within_stake(self):
        assert EnforcementInvariants.check_safety_s4(500, 1000)
        assert EnforcementInvariants.check_safety_s4(1000, 1000)
        assert not EnforcementInvariants.check_safety_s4(1001, 1000)

    def test_liveness_l1_eviction(self):
        assert EnforcementInvariants.check_liveness_l1(6, 6, True)
        assert not EnforcementInvariants.check_liveness_l1(6, 6, False)
        assert EnforcementInvariants.check_liveness_l1(3, 6, False)

    def test_liveness_l3_non_negative_offenses(self):
        assert EnforcementInvariants.check_liveness_l3(0)
        assert EnforcementInvariants.check_liveness_l3(5)
        assert not EnforcementInvariants.check_liveness_l3(-1)

    def test_correlation_c1_bounds(self):
        assert EnforcementInvariants.check_correlation_c1(1.0, 3.0)
        assert EnforcementInvariants.check_correlation_c1(2.5, 3.0)
        assert EnforcementInvariants.check_correlation_c1(3.0, 3.0)
        assert not EnforcementInvariants.check_correlation_c1(0.5, 3.0)
        assert not EnforcementInvariants.check_correlation_c1(3.5, 3.0)

    def test_correlation_c2_isolated(self):
        assert EnforcementInvariants.check_correlation_c2(0, 1.0)
        assert not EnforcementInvariants.check_correlation_c2(0, 1.5)
        # Non-zero concurrent stake → any multiplier ok
        assert EnforcementInvariants.check_correlation_c2(100, 2.0)

    def test_economic_e1_fee_split(self):
        assert EnforcementInvariants.check_economic_e1(1000, 600, 150, 100, 150)
        assert EnforcementInvariants.check_economic_e1(1000, 600, 150, 100, 149)
        assert not EnforcementInvariants.check_economic_e1(1000, 600, 150, 100, 100)

    def test_economic_e2_monotonic_vesting(self):
        assert EnforcementInvariants.check_economic_e2(100, 150)
        assert EnforcementInvariants.check_economic_e2(100, 100)
        assert not EnforcementInvariants.check_economic_e2(150, 100)


# ===========================================================================
# 7. Progressive Decentralization
# ===========================================================================


class TestDecentralizationMetrics:
    def test_hhi_equal_distribution(self):
        # 4 operators with equal stake → HHI = 2500
        shares = [0.25, 0.25, 0.25, 0.25]
        hhi = DecentralizationMetrics.compute_hhi(shares)
        assert hhi == pytest.approx(2500.0)

    def test_hhi_monopoly(self):
        shares = [1.0]
        hhi = DecentralizationMetrics.compute_hhi(shares)
        assert hhi == pytest.approx(10_000.0)

    def test_hhi_highly_distributed(self):
        shares = [1.0 / 100] * 100  # 100 equal operators
        hhi = DecentralizationMetrics.compute_hhi(shares)
        assert hhi == pytest.approx(100.0)

    def test_hhi_empty(self):
        assert DecentralizationMetrics.compute_hhi([]) == 10_000.0

    def test_gini_equal(self):
        gini = DecentralizationMetrics.compute_gini([100, 100, 100, 100])
        assert gini == pytest.approx(0.0)

    def test_gini_inequality(self):
        gini = DecentralizationMetrics.compute_gini([1, 1, 1, 97])
        assert gini > 0.5

    def test_gini_empty(self):
        assert DecentralizationMetrics.compute_gini([]) == 0.0


class TestGovernanceTransition:
    def test_bootstrap_to_growth_can_transition(self):
        gov = GovernanceTransition()
        metrics = DecentralizationMetrics(
            active_operators=10,
            hhi=5000.0,
            gini_coefficient=0.8,
            governance_participation=0.0,
            foundation_veto_active=True,
        )
        can, unmet = gov.can_transition("bootstrap", "growth", metrics)
        assert can
        assert len(unmet) == 0

    def test_bootstrap_to_growth_insufficient_operators(self):
        gov = GovernanceTransition()
        metrics = DecentralizationMetrics(
            active_operators=3,
            hhi=5000.0,
            gini_coefficient=0.8,
            governance_participation=0.0,
            foundation_veto_active=True,
        )
        can, unmet = gov.can_transition("bootstrap", "growth", metrics)
        assert not can
        assert any("Operators" in u for u in unmet)

    def test_growth_to_maturity_full_requirements(self):
        gov = GovernanceTransition()
        metrics = DecentralizationMetrics(
            active_operators=150,
            hhi=1500.0,
            gini_coefficient=0.55,
            governance_participation=0.20,
            foundation_veto_active=True,
        )
        can, unmet = gov.can_transition("growth", "maturity", metrics)
        assert can

    def test_growth_to_maturity_too_concentrated(self):
        gov = GovernanceTransition()
        metrics = DecentralizationMetrics(
            active_operators=150,
            hhi=3000.0,  # Too concentrated
            gini_coefficient=0.55,
            governance_participation=0.20,
            foundation_veto_active=True,
        )
        can, unmet = gov.can_transition("growth", "maturity", metrics)
        assert not can
        assert any("HHI" in u for u in unmet)

    def test_execute_transition_irreversible(self):
        gov = GovernanceTransition()
        metrics = DecentralizationMetrics(
            active_operators=10,
            hhi=5000.0,
            gini_coefficient=0.8,
            governance_participation=0.0,
            foundation_veto_active=True,
        )
        assert gov.execute_transition("bootstrap", "growth", metrics)
        # Cannot re-execute
        can, unmet = gov.can_transition("bootstrap", "growth", metrics)
        assert not can

    def test_maturity_revokes_veto(self):
        gov = GovernanceTransition()
        metrics = DecentralizationMetrics(
            active_operators=150,
            hhi=1500.0,
            gini_coefficient=0.55,
            governance_participation=0.20,
            foundation_veto_active=True,
        )
        gov.execute_transition("growth", "maturity", metrics)
        assert not metrics.foundation_veto_active

    def test_unknown_transition(self):
        gov = GovernanceTransition()
        metrics = DecentralizationMetrics(
            active_operators=10,
            hhi=5000.0,
            gini_coefficient=0.5,
            governance_participation=0.1,
            foundation_veto_active=True,
        )
        can, unmet = gov.can_transition("maturity", "ultra", metrics)
        assert not can


# ===========================================================================
# 8. Economics Integration — compute_slash_for_condition
# ===========================================================================


class TestComputeSlashForCondition:
    def test_basic_condition_slash(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n1", stake=100_000 * WEI_PER_LTP)

        slash_amount, tier = engine.compute_slash_for_condition(
            node,
            condition_allocation_bps=5000,  # 50% of stake at risk
            severity="minor",
        )

        # at_risk = 50% of 100,000 LTP = 50,000 LTP
        # minor = 5% = 2,500 LTP
        expected = 50_000 * WEI_PER_LTP * 500 // 10_000
        assert slash_amount == expected
        assert tier == SlashingTier.MINOR

    def test_critical_severity(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n1", stake=100_000 * WEI_PER_LTP)

        slash_amount, tier = engine.compute_slash_for_condition(
            node,
            condition_allocation_bps=10_000,  # 100% at risk
            severity="critical",
        )
        assert tier == SlashingTier.CRITICAL
        # 30% of full stake
        expected = 100_000 * WEI_PER_LTP * 3000 // 10_000
        assert slash_amount == expected

    def test_correlation_penalty_applied(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n1", stake=100_000 * WEI_PER_LTP)

        slash_no_corr, _ = engine.compute_slash_for_condition(
            node,
            condition_allocation_bps=5000,
            severity="minor",
        )

        slash_with_corr, _ = engine.compute_slash_for_condition(
            node,
            condition_allocation_bps=5000,
            severity="minor",
            concurrent_slashed_stake=500_000 * WEI_PER_LTP,
            total_network_stake=1_000_000 * WEI_PER_LTP,
        )

        assert slash_with_corr > slash_no_corr

    def test_slash_capped_at_risk(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n1", stake=100 * WEI_PER_LTP)

        slash_amount, _ = engine.compute_slash_for_condition(
            node,
            condition_allocation_bps=1000,  # 10% at risk = 10 LTP
            severity="critical",
            concurrent_slashed_stake=900_000 * WEI_PER_LTP,
            total_network_stake=1_000_000 * WEI_PER_LTP,
        )

        # Should never exceed at-risk stake (10 LTP)
        at_risk = 100 * WEI_PER_LTP * 1000 // 10_000
        assert slash_amount <= at_risk

    def test_unknown_severity_defaults_to_warning(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n1", stake=100_000 * WEI_PER_LTP)

        _, tier = engine.compute_slash_for_condition(
            node,
            condition_allocation_bps=5000,
            severity="unknown",
        )
        assert tier == SlashingTier.WARNING


# ===========================================================================
# 9. CommitmentNetwork PDP Integration
# ===========================================================================


class TestCommitmentNetworkPDP:
    def _setup_network(self):
        from src.ltp.commitment import CommitmentNetwork

        network = CommitmentNetwork()
        for i in range(4):
            region = ["us-east", "us-west", "eu-west", "ap-east"][i]
            network.add_node(f"node-{i}", region)
        return network

    def test_pdp_audit_passes_for_honest_node(self):
        network = self._setup_network()

        # Distribute some shards
        shards = [f"shard-{i}".encode() for i in range(8)]
        network.distribute_encrypted_shards("entity-1", shards, replicas=2)

        # PDP audit on a node that has shards
        node = network.nodes[0]
        result = network.audit_node_pdp(node, epoch=1, sample_size=4)

        assert result["result"] == "PASS"
        assert result["entities_challenged"] >= 0

    def test_pdp_audit_node_with_no_shards(self):
        network = self._setup_network()
        # Node with no shards should pass trivially
        node = network.nodes[3]
        result = network.audit_node_pdp(node, epoch=1)
        assert result["result"] == "PASS"
        assert result["entities_challenged"] == 0

    def test_pdp_audit_proof_size_compact(self):
        network = self._setup_network()
        shards = [f"shard-{i}".encode() for i in range(8)]
        network.distribute_encrypted_shards("entity-1", shards, replicas=2)

        node = network.nodes[0]
        result = network.audit_node_pdp(node, epoch=1, sample_size=4)

        # PDP proofs should be compact (≤ 160 bytes per entity)
        if result["entities_challenged"] > 0:
            avg_proof_size = result["proof_size_bytes"] / result["entities_challenged"]
            assert avg_proof_size <= 160
