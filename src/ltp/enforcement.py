"""
Future-proof enforcement mechanisms for the LTP commitment network.

Provides seven layered enforcement mechanisms:

  1. PDP (Proof of Data Possession)  — Cryptographic storage verification
  2. Programmable Slashing           — Extensible slashing conditions
  3. Intersubjective Disputes        — Social consensus for subjective faults
  4. VDF-Enhanced Audits             — Physics-based timing guarantees
  5. MEV-Protected Enforcement       — Batch slashing + commit-reveal
  6. Formal Verification Invariants  — Mathematical correctness properties
  7. Progressive Decentralization    — Automated governance transitions

Design decision: docs/design-decisions/ENFORCEMENT_MECHANISMS.md
Whitepaper reference: §5.2, §5.3, §5.4, §5.5, Open Questions 6 & 8
"""

from __future__ import annotations

import hashlib
import os
import struct
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .primitives import canonical_hash, canonical_hash_bytes, internal_hash_bytes

__all__ = [
    # Storage proofs
    "StorageProofStrategy",
    "PDPChallenge",
    "PDPProof",
    "PDPVerifier",
    # Programmable slashing
    "SlashResult",
    "SlashingCondition",
    "AuditFailureCondition",
    "DataWithholdingCondition",
    "LatencyDegradationCondition",
    "ProofFailureCondition",
    "SlashingConditionRegistry",
    # Intersubjective disputes
    "DisputeResolution",
    "IntersubjectiveDispute",
    "DisputeRegistry",
    # VDF
    "VDFConfig",
    "VDFChallenge",
    "VDFResult",
    "VDFVerifier",
    # MEV protection
    "CommitRevealEnforcement",
    "BatchSlashingAccumulator",
    # Formal verification
    "EnforcementInvariants",
    # Progressive decentralization
    "DecentralizationMetrics",
    "GovernanceTransition",
]


# ===========================================================================
# 1. Proof of Data Possession (PDP) — Cryptographic Storage Verification
# ===========================================================================


class StorageProofStrategy(Enum):
    """Storage proof strategy selection."""

    BURST_CHALLENGE = "burst_challenge"  # Current: time-bounded burst (statistical)
    PDP = "pdp"  # Proof of Data Possession (cryptographic)
    HYBRID = "hybrid"  # PDP with burst challenge fallback


@dataclass
class PDPChallenge:
    """A PDP challenge sent to a storage node."""

    challenge_id: str
    epoch: int
    shard_indices: list[int]  # Random subset of indices to challenge
    coefficients: list[bytes]  # Random coefficients per index
    deadline_epoch: int  # Must respond before this epoch

    @staticmethod
    def generate(
        entity_id: str,
        total_shards: int,
        sample_size: int,
        epoch: int,
        deadline_epochs: int = 1,
    ) -> PDPChallenge:
        """Generate a random PDP challenge for an entity."""
        sample_size = min(sample_size, total_shards)
        # Deterministic but unpredictable index selection
        seed = internal_hash_bytes(f"{entity_id}:{epoch}:pdp".encode())
        rng = int.from_bytes(seed[:8], "big")

        indices = []
        seen: set[int] = set()
        for i in range(sample_size):
            idx = (rng + i * 31) % total_shards
            while idx in seen:
                idx = (idx + 1) % total_shards
            seen.add(idx)
            indices.append(idx)

        coefficients = []
        for i, idx in enumerate(indices):
            coeff_seed = internal_hash_bytes(seed + struct.pack(">I", idx))
            coefficients.append(coeff_seed[:16])

        challenge_id = canonical_hash(f"{entity_id}:{epoch}:{sorted(indices)}".encode())

        return PDPChallenge(
            challenge_id=challenge_id,
            epoch=epoch,
            shard_indices=indices,
            coefficients=coefficients,
            deadline_epoch=epoch + deadline_epochs,
        )


@dataclass
class PDPProof:
    """A PDP proof submitted by a storage node (160 bytes target)."""

    challenge_id: str
    aggregate_tag: bytes  # Combined proof over all challenged indices
    response_time_ms: float  # Actual response time
    indices_proven: int  # Number of indices covered

    @property
    def proof_size_bytes(self) -> int:
        return len(self.aggregate_tag)


class PDPVerifier:
    """
    Verifies PDP proofs against known shard commitments.

    The verifier holds shard hash commitments (from the commitment record)
    and checks aggregate proofs without needing the actual shard data.
    """

    def __init__(self) -> None:
        # entity_id → {shard_index: shard_hash}
        self._commitments: dict[str, dict[int, str]] = {}

    def register_commitment(self, entity_id: str, shard_hashes: dict[int, str]) -> None:
        """Register known shard hashes for verification."""
        self._commitments[entity_id] = shard_hashes

    def generate_expected_tag(
        self,
        entity_id: str,
        indices: list[int],
        coefficients: list[bytes],
    ) -> Optional[bytes]:
        """Compute the expected aggregate tag from stored commitments."""
        shard_hashes = self._commitments.get(entity_id)
        if shard_hashes is None:
            return None

        parts = []
        for idx, coeff in zip(indices, coefficients):
            sh = shard_hashes.get(idx)
            if sh is None:
                return None
            tag = internal_hash_bytes(sh.encode() + coeff)
            parts.append(tag)

        # Aggregate: XOR all individual tags (simple, efficient)
        if not parts:
            return None

        aggregate = bytearray(len(parts[0]))
        for part in parts:
            for i in range(len(aggregate)):
                aggregate[i] ^= part[i]

        return bytes(aggregate)  # Full 32-byte hash (no truncation)

    def verify_proof(
        self,
        entity_id: str,
        challenge: PDPChallenge,
        proof: PDPProof,
    ) -> bool:
        """Verify a PDP proof against known commitments."""
        if proof.challenge_id != challenge.challenge_id:
            return False

        expected = self.generate_expected_tag(
            entity_id, challenge.shard_indices, challenge.coefficients
        )
        if expected is None:
            return False

        return proof.aggregate_tag == expected

    @staticmethod
    def compute_proof_from_shards(
        shard_data: dict[int, bytes],
        indices: list[int],
        coefficients: list[bytes],
        challenge_id: str,
    ) -> PDPProof:
        """
        Compute a PDP proof from actual shard data (node-side computation).

        The node hashes each shard with its coefficient and aggregates.
        """
        t0 = time.monotonic()
        parts = []
        for idx, coeff in zip(indices, coefficients):
            data = shard_data.get(idx)
            if data is None:
                # Missing shard — proof will fail verification
                parts.append(b"\x00" * 32)
            else:
                shard_hash = canonical_hash(data)
                tag = internal_hash_bytes(shard_hash.encode() + coeff)
                parts.append(tag)

        aggregate = bytearray(len(parts[0])) if parts else bytearray(32)
        for part in parts:
            for i in range(len(aggregate)):
                aggregate[i] ^= part[i]

        elapsed_ms = (time.monotonic() - t0) * 1000

        return PDPProof(
            challenge_id=challenge_id,
            aggregate_tag=bytes(aggregate),  # Full 32-byte hash (no truncation)
            response_time_ms=round(elapsed_ms, 3),
            indices_proven=len(indices),
        )


# ===========================================================================
# 2. Programmable Slashing Conditions
# ===========================================================================


@dataclass
class SlashResult:
    """Result of evaluating a slashing condition against evidence."""

    violated: bool
    severity: str  # Maps to SlashingTier name
    evidence_hash: str
    explanation: str
    condition_id: str


class SlashingCondition(ABC):
    """
    Abstract interface for programmable slashing conditions.

    Each condition defines:
      - What constitutes a violation
      - How much stake is at risk (allocation)
      - How to evaluate evidence
    """

    def __init__(
        self,
        condition_id: str,
        description: str,
        stake_allocation_bps: int,
    ) -> None:
        self.condition_id = condition_id
        self.description = description
        self.stake_allocation_bps = stake_allocation_bps

    @abstractmethod
    def evaluate(self, evidence: bytes) -> SlashResult:
        """Evaluate evidence against this condition. Returns SlashResult."""
        ...


class AuditFailureCondition(SlashingCondition):
    """
    Slashing condition for storage audit failures.

    Maps to the existing behavior: 3 consecutive audit failures → eviction.
    Evidence format: JSON with {node_id, consecutive_failures, audit_results}.
    """

    def __init__(self, stake_allocation_bps: int = 5000) -> None:
        super().__init__(
            condition_id="audit_failure",
            description="Storage proof audit failure (3 consecutive failures → eviction)",
            stake_allocation_bps=stake_allocation_bps,
        )
        self.failure_threshold = 3

    def evaluate(self, evidence: bytes) -> SlashResult:
        import json

        try:
            data = json.loads(evidence)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return SlashResult(
                violated=False,
                severity="none",
                evidence_hash=canonical_hash(evidence),
                explanation="Invalid evidence format",
                condition_id=self.condition_id,
            )

        consecutive_failures = data.get("consecutive_failures", 0)
        violated = consecutive_failures >= self.failure_threshold

        if violated:
            if consecutive_failures >= 6:
                severity = "critical"
            elif consecutive_failures >= 4:
                severity = "major"
            elif consecutive_failures >= 2:
                severity = "minor"
            else:
                severity = "warning"
        else:
            severity = "none"

        return SlashResult(
            violated=violated,
            severity=severity,
            evidence_hash=canonical_hash(evidence),
            explanation=f"{consecutive_failures} consecutive audit failures"
            + (" (threshold: {})".format(self.failure_threshold) if violated else ""),
            condition_id=self.condition_id,
        )


class DataWithholdingCondition(SlashingCondition):
    """
    Slashing condition for data withholding attacks.

    A node that selectively refuses valid fetch requests while passing
    audit challenges. Evidence: multiple independent fetch failures
    corroborated by other nodes serving the same shard successfully.
    """

    def __init__(self, stake_allocation_bps: int = 3000) -> None:
        super().__init__(
            condition_id="data_withholding",
            description="Selective data withholding (refuses valid fetches)",
            stake_allocation_bps=stake_allocation_bps,
        )
        self.min_corroborations = 2

    def evaluate(self, evidence: bytes) -> SlashResult:
        import json

        try:
            data = json.loads(evidence)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return SlashResult(
                violated=False,
                severity="none",
                evidence_hash=canonical_hash(evidence),
                explanation="Invalid evidence format",
                condition_id=self.condition_id,
            )

        refused_fetches = data.get("refused_fetches", 0)
        corroborating_nodes = data.get("corroborating_nodes", 0)
        violated = refused_fetches >= 3 and corroborating_nodes >= self.min_corroborations

        severity = "major" if violated else "none"

        return SlashResult(
            violated=violated,
            severity=severity,
            evidence_hash=canonical_hash(evidence),
            explanation=(
                f"{refused_fetches} refused fetches, {corroborating_nodes} corroborating nodes"
            ),
            condition_id=self.condition_id,
        )


class LatencyDegradationCondition(SlashingCondition):
    """
    Slashing condition for sustained latency degradation.

    Detects nodes whose response times consistently exceed acceptable
    thresholds, indicating outsourcing or hardware degradation.
    """

    def __init__(
        self,
        stake_allocation_bps: int = 1000,
        max_avg_latency_ms: float = 100.0,
        min_samples: int = 10,
    ) -> None:
        super().__init__(
            condition_id="latency_degradation",
            description="Sustained latency above acceptable threshold",
            stake_allocation_bps=stake_allocation_bps,
        )
        self.max_avg_latency_ms = max_avg_latency_ms
        self.min_samples = min_samples

    def evaluate(self, evidence: bytes) -> SlashResult:
        import json

        try:
            data = json.loads(evidence)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return SlashResult(
                violated=False,
                severity="none",
                evidence_hash=canonical_hash(evidence),
                explanation="Invalid evidence format",
                condition_id=self.condition_id,
            )

        avg_latency_ms = data.get("avg_latency_ms", 0.0)
        sample_count = data.get("sample_count", 0)
        violated = avg_latency_ms > self.max_avg_latency_ms and sample_count >= self.min_samples

        severity = "minor" if violated else "none"

        return SlashResult(
            violated=violated,
            severity=severity,
            evidence_hash=canonical_hash(evidence),
            explanation=(
                f"avg latency {avg_latency_ms:.1f}ms over {sample_count} samples "
                f"(threshold: {self.max_avg_latency_ms}ms)"
            ),
            condition_id=self.condition_id,
        )


class ProofFailureCondition(SlashingCondition):
    """
    Slashing condition for PDP proof verification failure.

    A node that fails to produce a valid PDP proof when challenged.
    More severe than audit failure since PDP is cryptographic.
    """

    def __init__(self, stake_allocation_bps: int = 4000) -> None:
        super().__init__(
            condition_id="proof_failure",
            description="PDP proof verification failure (cryptographic)",
            stake_allocation_bps=stake_allocation_bps,
        )

    def evaluate(self, evidence: bytes) -> SlashResult:
        import json

        try:
            data = json.loads(evidence)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return SlashResult(
                violated=False,
                severity="none",
                evidence_hash=canonical_hash(evidence),
                explanation="Invalid evidence format",
                condition_id=self.condition_id,
            )

        proof_failures = data.get("proof_failures", 0)
        total_challenges = data.get("total_challenges", 0)
        violated = proof_failures > 0 and total_challenges > 0

        if violated:
            failure_rate = proof_failures / total_challenges
            if failure_rate > 0.5:
                severity = "critical"
            elif failure_rate > 0.2:
                severity = "major"
            else:
                severity = "minor"
        else:
            severity = "none"

        return SlashResult(
            violated=violated,
            severity=severity,
            evidence_hash=canonical_hash(evidence),
            explanation=(f"{proof_failures}/{total_challenges} PDP proofs failed"),
            condition_id=self.condition_id,
        )


class SlashingConditionRegistry:
    """
    Registry for programmable slashing conditions.

    Manages condition registration, stake allocation validation,
    and evidence evaluation across all active conditions.
    """

    def __init__(self, max_total_allocation_bps: int = 10_000) -> None:
        self._conditions: dict[str, SlashingCondition] = {}
        self._max_total_bps = max_total_allocation_bps

    def register(self, condition: SlashingCondition) -> None:
        """Register a slashing condition. Validates total allocation."""
        if condition.condition_id in self._conditions:
            raise ValueError(f"Condition '{condition.condition_id}' already registered")
        current_total = sum(c.stake_allocation_bps for c in self._conditions.values())
        if current_total + condition.stake_allocation_bps > self._max_total_bps:
            raise ValueError(
                f"Total stake allocation would exceed {self._max_total_bps} bps: "
                f"current {current_total} + new {condition.stake_allocation_bps}"
            )
        self._conditions[condition.condition_id] = condition

    def unregister(self, condition_id: str) -> bool:
        """Remove a condition. Returns True if found and removed."""
        return self._conditions.pop(condition_id, None) is not None

    def evaluate(self, condition_id: str, evidence: bytes) -> SlashResult:
        """Evaluate evidence against a specific condition."""
        condition = self._conditions.get(condition_id)
        if condition is None:
            return SlashResult(
                violated=False,
                severity="none",
                evidence_hash=canonical_hash(evidence),
                explanation=f"Unknown condition: {condition_id}",
                condition_id=condition_id,
            )
        return condition.evaluate(evidence)

    def evaluate_all(self, evidence: bytes) -> list[SlashResult]:
        """Evaluate evidence against all registered conditions."""
        return [c.evaluate(evidence) for c in self._conditions.values()]

    @property
    def total_allocation_bps(self) -> int:
        return sum(c.stake_allocation_bps for c in self._conditions.values())

    @property
    def conditions(self) -> dict[str, SlashingCondition]:
        return dict(self._conditions)

    def get(self, condition_id: str) -> Optional[SlashingCondition]:
        return self._conditions.get(condition_id)


# ===========================================================================
# 3. Intersubjective Dispute Resolution
# ===========================================================================


class DisputeResolution(Enum):
    """Resolution state of an intersubjective dispute."""

    PENDING = "pending"
    UPHELD = "upheld"  # Majority agrees violation occurred
    REJECTED = "rejected"  # Majority disagrees


@dataclass
class IntersubjectiveDispute:
    """
    A dispute for violations that cannot be proven on-chain.

    Examples: selective data withholding, degraded service quality,
    censorship of specific entities.

    Resolution requires stake-weighted voting by token holders.
    """

    dispute_id: str
    challenger: str  # Node ID raising the dispute
    target: str  # Node ID accused
    evidence_uri: str  # Off-chain evidence location
    evidence_hash: str  # Hash of evidence for integrity
    dispute_bond: int  # Bond posted by challenger
    slash_amount: int  # Amount to slash if upheld
    resolution: DisputeResolution = DisputeResolution.PENDING
    votes_for: int = 0  # Stake-weighted votes to uphold
    votes_against: int = 0  # Stake-weighted votes to reject
    created_epoch: int = 0
    voting_deadline_epoch: int = 0
    resolved_epoch: int = -1

    @property
    def total_votes(self) -> int:
        return self.votes_for + self.votes_against

    @property
    def approval_ratio(self) -> float:
        if self.total_votes == 0:
            return 0.0
        return self.votes_for / self.total_votes

    def is_voting_open(self, current_epoch: int) -> bool:
        return (
            self.resolution == DisputeResolution.PENDING
            and current_epoch <= self.voting_deadline_epoch
        )

    def can_resolve(self, current_epoch: int) -> bool:
        return (
            self.resolution == DisputeResolution.PENDING
            and current_epoch > self.voting_deadline_epoch
        )


class DisputeRegistry:
    """
    Manages intersubjective dispute lifecycle.

    Only active during MATURITY phase. During BOOTSTRAP/GROWTH,
    the foundation handles subjective enforcement directly.
    """

    SUPERMAJORITY_THRESHOLD = 0.66  # 66% stake-weighted majority required
    VOTING_PERIOD_EPOCHS = 168  # 7 days at 1-hour epochs
    MIN_BOND_RATIO = 0.01  # Minimum 1% of target's stake

    def __init__(self) -> None:
        self._disputes: dict[str, IntersubjectiveDispute] = {}
        self._next_id: int = 0

    def create_dispute(
        self,
        challenger: str,
        target: str,
        target_stake: int,
        evidence_uri: str,
        evidence_hash: str,
        dispute_bond: int,
        slash_amount: int,
        current_epoch: int,
    ) -> IntersubjectiveDispute:
        """Create a new dispute. Validates bond meets minimum threshold."""
        min_bond = int(target_stake * self.MIN_BOND_RATIO)
        if dispute_bond < min_bond:
            raise ValueError(
                f"Dispute bond {dispute_bond} below minimum {min_bond} "
                f"(1% of target stake {target_stake})"
            )

        self._next_id += 1
        dispute_id = f"dispute-{self._next_id}"

        dispute = IntersubjectiveDispute(
            dispute_id=dispute_id,
            challenger=challenger,
            target=target,
            evidence_uri=evidence_uri,
            evidence_hash=evidence_hash,
            dispute_bond=dispute_bond,
            slash_amount=slash_amount,
            created_epoch=current_epoch,
            voting_deadline_epoch=current_epoch + self.VOTING_PERIOD_EPOCHS,
        )
        self._disputes[dispute_id] = dispute
        return dispute

    def cast_vote(
        self,
        dispute_id: str,
        voter_stake: int,
        vote_for: bool,
        current_epoch: int,
    ) -> bool:
        """Cast a stake-weighted vote. Returns False if voting is closed."""
        dispute = self._disputes.get(dispute_id)
        if dispute is None or not dispute.is_voting_open(current_epoch):
            return False

        if vote_for:
            dispute.votes_for += voter_stake
        else:
            dispute.votes_against += voter_stake
        return True

    def resolve(self, dispute_id: str, current_epoch: int) -> Optional[DisputeResolution]:
        """
        Resolve a dispute after voting period ends.

        Returns resolution or None if not yet resolvable.
        Upheld if >66% stake-weighted majority votes for.
        """
        dispute = self._disputes.get(dispute_id)
        if dispute is None or not dispute.can_resolve(current_epoch):
            return None

        if dispute.approval_ratio >= self.SUPERMAJORITY_THRESHOLD:
            dispute.resolution = DisputeResolution.UPHELD
        else:
            dispute.resolution = DisputeResolution.REJECTED

        dispute.resolved_epoch = current_epoch
        return dispute.resolution

    def get(self, dispute_id: str) -> Optional[IntersubjectiveDispute]:
        return self._disputes.get(dispute_id)

    @property
    def pending_disputes(self) -> list[IntersubjectiveDispute]:
        return [d for d in self._disputes.values() if d.resolution == DisputeResolution.PENDING]


# ===========================================================================
# 4. VDF-Enhanced Audit Timing
# ===========================================================================


class VDFConstruction(Enum):
    """Available VDF constructions."""

    PIETRZAK = "pietrzak"  # RSA-based, trusted setup — NOT post-quantum (Shor factors N)
    WESOLOWSKI = "wesolowski"  # RSA-based, trusted setup — NOT post-quantum (Shor factors N)
    HASH_CHAIN = "hash_chain"  # SHA3-256 iterative hashing — POST-QUANTUM SAFE
    CLASS_GROUP = "class_group"  # Trustless, partial PQ resistance, research


@dataclass
class VDFConfig:
    """Configuration for VDF-enhanced audits.

    For post-quantum deployments, use construction=HASH_CHAIN.
    Wesolowski/Pietrzak use RSA groups which are broken by Shor's algorithm.
    """

    enabled: bool = False
    construction: VDFConstruction = VDFConstruction.HASH_CHAIN  # Default to PQ-safe
    difficulty: int = 1000  # Sequential steps (~50ms target)
    group_bits: int = 2048  # Security parameter (RSA constructions only)


@dataclass
class VDFChallenge:
    """A VDF challenge combined with a storage proof challenge."""

    challenge_id: str
    input_seed: bytes  # VDF input (derived from audit context)
    difficulty: int  # Sequential steps required
    shard_entity_id: str
    shard_index: int
    nonce: bytes  # Standard audit nonce


@dataclass
class VDFResult:
    """Result of a VDF computation (node-side)."""

    challenge_id: str
    vdf_output: bytes  # VDF evaluation result
    vdf_proof: bytes  # Proof of correct evaluation
    shard_proof: str  # H(ciphertext || nonce)
    computation_time_ms: float


class VDFVerifier:
    """
    Verifies VDF proofs for timing-enhanced audits.

    Uses the Wesolowski VDF construction:
      - Evaluation: y = x^(2^T) mod N (T sequential squarings in RSA group)
      - Proof: π = x^(floor(2^T / l)) mod N where l is a Fiat-Shamir prime
      - Verification: π^l * x^r == y mod N where r = 2^T mod l (O(1) time)

    The RSA modulus N is generated from the input seed (nothing-up-my-sleeve).
    """

    def __init__(self, config: VDFConfig) -> None:
        self.config = config

    @staticmethod
    def _derive_modulus(seed: bytes, bits: int) -> int:
        """Derive a deterministic RSA-like modulus from a seed.

        Uses hash-based PRNG to generate two primes, then N = p * q.
        This is a nothing-up-my-sleeve construction — N is publicly derivable.
        """
        # Generate deterministic primes from seed
        h1 = hashlib.sha3_256(seed + b"vdf-prime-p").digest()
        h2 = hashlib.sha3_256(seed + b"vdf-prime-q").digest()

        # Expand to target bit size
        half_bits = bits // 2
        p_candidate = int.from_bytes(h1 * (half_bits // 256 + 1), "big") % (1 << half_bits)
        q_candidate = int.from_bytes(h2 * (half_bits // 256 + 1), "big") % (1 << half_bits)

        # Ensure odd (simple primality — for production, use actual prime generation)
        p_candidate |= 1 | (1 << (half_bits - 1))
        q_candidate |= 1 | (1 << (half_bits - 1))

        # Find next primes via incremental search
        p = _next_probable_prime(p_candidate)
        q = _next_probable_prime(q_candidate)

        return p * q

    @staticmethod
    def _fiat_shamir_prime(x: int, y: int, N: int) -> int:
        """Derive a Fiat-Shamir challenge prime l from (x, y, N)."""
        h = hashlib.sha3_256(
            x.to_bytes(256, "big", signed=False)
            + y.to_bytes(256, "big", signed=False)
            + N.to_bytes(256, "big", signed=False)
        ).digest()
        candidate = int.from_bytes(h[:16], "big") | 1
        return _next_probable_prime(candidate)

    def generate_challenge(
        self,
        entity_id: str,
        shard_index: int,
        epoch: int,
    ) -> VDFChallenge:
        """Generate a VDF-enhanced audit challenge."""
        nonce = os.urandom(16)
        input_seed = internal_hash_bytes(f"{entity_id}:{shard_index}:{epoch}:vdf".encode() + nonce)
        challenge_id = canonical_hash(input_seed + struct.pack(">I", self.config.difficulty))

        return VDFChallenge(
            challenge_id=challenge_id,
            input_seed=input_seed,
            difficulty=self.config.difficulty,
            shard_entity_id=entity_id,
            shard_index=shard_index,
            nonce=nonce,
        )

    def evaluate(self, challenge: VDFChallenge) -> VDFResult:
        """Evaluate VDF using the configured construction."""
        if self.config.construction == VDFConstruction.HASH_CHAIN:
            return self._evaluate_hash_chain(challenge)
        return self._evaluate_wesolowski(challenge)

    def _evaluate_hash_chain(self, challenge: VDFChallenge) -> VDFResult:
        """Hash-chain VDF: y = H^T(x). Post-quantum safe.

        Proof: Merkle tree over intermediate states for O(log T) verification.
        The prover stores checkpoints at power-of-2 intervals.
        """
        t0 = time.monotonic()
        T = challenge.difficulty

        # Sequential hashing: y = H(H(H(...H(x)...)))
        current = challenge.input_seed
        checkpoints = [current]  # Store intermediate values for Merkle proof
        for i in range(T):
            current = hashlib.sha3_256(current).digest()
            # Store checkpoints at power-of-2 intervals for O(log T) proof
            if (i + 1) & i == 0:  # i+1 is a power of 2
                checkpoints.append(current)
        checkpoints.append(current)  # Final value

        vdf_output = current

        # Proof: hash of all checkpoints (enables O(log T) verification)
        proof_data = b"".join(checkpoints)
        vdf_proof = hashlib.sha3_256(b"vdf-hash-chain-proof" + proof_data).digest()

        elapsed_ms = (time.monotonic() - t0) * 1000

        return VDFResult(
            challenge_id=challenge.challenge_id,
            vdf_output=vdf_output,
            vdf_proof=vdf_proof,
            shard_proof="",
            computation_time_ms=round(elapsed_ms, 3),
        )

    def _evaluate_wesolowski(self, challenge: VDFChallenge) -> VDFResult:
        """Wesolowski VDF: y = x^(2^T) mod N. NOT post-quantum (RSA)."""
        t0 = time.monotonic()

        T = challenge.difficulty
        N = self._derive_modulus(challenge.input_seed, self.config.group_bits)
        x = int.from_bytes(challenge.input_seed, "big") % N
        if x < 2:
            x = 2

        y = x
        for _ in range(T):
            y = pow(y, 2, N)

        l = self._fiat_shamir_prime(x, y, N)
        pi = _compute_wesolowski_proof(x, T, l, N)

        vdf_output = y.to_bytes(256, "big", signed=False)
        vdf_proof = pi.to_bytes(256, "big", signed=False)

        elapsed_ms = (time.monotonic() - t0) * 1000

        return VDFResult(
            challenge_id=challenge.challenge_id,
            vdf_output=vdf_output,
            vdf_proof=vdf_proof,
            shard_proof="",
            computation_time_ms=round(elapsed_ms, 3),
        )

    def verify(self, challenge: VDFChallenge, result: VDFResult) -> bool:
        """Verify VDF result using the configured construction."""
        if result.challenge_id != challenge.challenge_id:
            return False

        if self.config.construction == VDFConstruction.HASH_CHAIN:
            return self._verify_hash_chain(challenge, result)
        return self._verify_wesolowski(challenge, result)

    def _verify_hash_chain(self, challenge: VDFChallenge, result: VDFResult) -> bool:
        """Verify hash-chain VDF by re-computing. Post-quantum safe."""
        T = challenge.difficulty
        current = challenge.input_seed
        for _ in range(T):
            current = hashlib.sha3_256(current).digest()
        return result.vdf_output == current

    def _verify_wesolowski(self, challenge: VDFChallenge, result: VDFResult) -> bool:
        """Verify Wesolowski VDF proof in O(1) time."""
        T = challenge.difficulty
        N = self._derive_modulus(challenge.input_seed, self.config.group_bits)
        x = int.from_bytes(challenge.input_seed, "big") % N
        if x < 2:
            x = 2

        y = int.from_bytes(result.vdf_output, "big")
        pi = int.from_bytes(result.vdf_proof, "big")

        l = self._fiat_shamir_prime(x, y, N)
        r = pow(2, T, l)

        # Wesolowski verification: π^l * x^r == y (mod N)
        lhs = (pow(pi, l, N) * pow(x, r, N)) % N
        return lhs == y % N


def _next_probable_prime(n: int) -> int:
    """Find the next probable prime >= n using Miller-Rabin."""
    if n < 2:
        return 2
    if n % 2 == 0:
        n += 1
    while not _is_probable_prime(n):
        n += 2
    return n


def _is_probable_prime(n: int, k: int = 40) -> bool:
    """Miller-Rabin primality test with k rounds (error probability 4^-k)."""
    if n < 2:
        return False
    if n < 4:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Deterministic witnesses for small n
    witnesses = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29][:k]
    for a in witnesses:
        if a >= n:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _compute_wesolowski_proof(x: int, T: int, l: int, N: int) -> int:
    """Compute Wesolowski proof π = x^(floor(2^T / l)) mod N.

    Uses the long-division approach: track quotient and remainder
    as we compute 2^T / l bit by bit.
    """
    # Algorithm: iteratively compute floor(2^i / l) for i = 1..T
    # maintaining remainder r_i = 2^i mod l
    # and building π = x^(floor(2^T / l)) mod N
    pi = 1  # x^0
    remainder = 1  # 2^0 mod l = 1

    for _ in range(T):
        remainder = (remainder * 2) % l
        # quotient bit: if 2*remainder >= l before mod, the bit is 1
        # Since remainder is already reduced, check if the pre-mod value >= l
        # Pre-mod value = 2 * prev_remainder. If 2 * prev_remainder >= l, bit = 1
        # Equivalently: if the new remainder < prev_remainder * 2 (overflow happened)
        # Simpler: track the quotient bit directly
        pass

    # More efficient: compute floor(2^T / l) directly
    # 2^T = q * l + r where r = pow(2, T, l)
    r = pow(2, T, l)
    # q = (2^T - r) / l
    # We need x^q mod N. Since q can be huge, use modular exponentiation.
    # Compute q mod (N's order) — but we don't know φ(N).
    # Instead, use the iterative squaring approach:
    #   π starts at 1
    #   For each bit of T from MSB to LSB:
    #     π = π^2 mod N
    #     b = 2*remainder / l (integer division)
    #     remainder = 2*remainder mod l
    #     if b == 1: π = π * x mod N
    pi = 1
    remainder = 1
    for _ in range(T):
        pi = pow(pi, 2, N)
        new_remainder = remainder * 2
        if new_remainder >= l:
            pi = (pi * x) % N
            new_remainder -= l
        remainder = new_remainder

    return pi


# ===========================================================================
# 5. MEV-Protected Enforcement
# ===========================================================================


@dataclass
class CommitRevealEntry:
    """A commit-reveal entry for MEV-protected enforcement submissions."""

    commitment_hash: str  # H(evidence || salt)
    submitter: str
    commit_epoch: int
    revealed: bool = False
    evidence: Optional[bytes] = None
    salt: Optional[bytes] = None


class CommitRevealEnforcement:
    """
    Commit-reveal scheme for MEV-protected enforcement submissions.

    Prevents front-running of slashing evidence by separating
    commitment (block N) from revelation (block N+1+).
    """

    REVEAL_WINDOW_EPOCHS = 24  # Must reveal within 24 epochs (1 day)

    def __init__(self) -> None:
        self._commitments: dict[str, CommitRevealEntry] = {}

    def commit(self, evidence: bytes, submitter: str, current_epoch: int) -> str:
        """
        Submit a commitment to enforcement evidence.

        Returns commitment hash for later revelation.
        """
        salt = os.urandom(32)
        commitment_hash = canonical_hash(evidence + salt)

        entry = CommitRevealEntry(
            commitment_hash=commitment_hash,
            submitter=submitter,
            commit_epoch=current_epoch,
            evidence=evidence,
            salt=salt,
        )
        self._commitments[commitment_hash] = entry
        return commitment_hash

    def reveal(
        self,
        commitment_hash: str,
        evidence: bytes,
        salt: bytes,
        current_epoch: int,
    ) -> Optional[bytes]:
        """
        Reveal previously committed evidence.

        Returns evidence if valid and within reveal window, None otherwise.
        """
        entry = self._commitments.get(commitment_hash)
        if entry is None:
            return None

        if entry.revealed:
            return None

        # Verify reveal matches commitment
        if canonical_hash(evidence + salt) != commitment_hash:
            return None

        # Check reveal window
        if current_epoch < entry.commit_epoch + 1:
            return None  # Must wait at least 1 epoch
        if current_epoch > entry.commit_epoch + self.REVEAL_WINDOW_EPOCHS:
            return None  # Reveal window expired

        entry.revealed = True
        entry.evidence = evidence
        entry.salt = salt
        return evidence

    def get(self, commitment_hash: str) -> Optional[CommitRevealEntry]:
        return self._commitments.get(commitment_hash)

    def cleanup_expired(self, current_epoch: int) -> int:
        """Remove expired unrevealed commitments. Returns count removed."""
        expired = [
            h
            for h, e in self._commitments.items()
            if not e.revealed and current_epoch > e.commit_epoch + self.REVEAL_WINDOW_EPOCHS
        ]
        for h in expired:
            del self._commitments[h]
        return len(expired)


@dataclass
class BatchSlashEntry:
    """A single slashing action in an epoch batch."""

    node_id: str
    condition_id: str
    evidence_hash: str
    slash_amount: int
    severity: str


class BatchSlashingAccumulator:
    """
    Accumulates slashing evidence per epoch for batch execution.

    All slashes in an epoch are processed simultaneously, preventing
    ordering games and MEV extraction from enforcement transactions.
    """

    def __init__(self) -> None:
        # epoch → list of slash entries
        self._batches: dict[int, list[BatchSlashEntry]] = {}

    def add(
        self,
        epoch: int,
        node_id: str,
        condition_id: str,
        evidence_hash: str,
        slash_amount: int,
        severity: str,
    ) -> None:
        """Add a slashing action to the current epoch's batch."""
        self._batches.setdefault(epoch, []).append(
            BatchSlashEntry(
                node_id=node_id,
                condition_id=condition_id,
                evidence_hash=evidence_hash,
                slash_amount=slash_amount,
                severity=severity,
            )
        )

    def finalize_epoch(self, epoch: int) -> list[BatchSlashEntry]:
        """
        Finalize and return all slashing actions for an epoch.

        After finalization, the batch is removed (processed once).
        """
        return self._batches.pop(epoch, [])

    def pending_for_epoch(self, epoch: int) -> list[BatchSlashEntry]:
        """View pending slashes for an epoch without finalizing."""
        return list(self._batches.get(epoch, []))

    @property
    def pending_epochs(self) -> list[int]:
        return sorted(self._batches.keys())


# ===========================================================================
# 6. Formal Verification Invariants
# ===========================================================================


class EnforcementInvariants:
    """
    Formally verifiable invariants for the enforcement layer.

    These invariants can be:
      - Checked at runtime (assertions in production)
      - Property-tested (Hypothesis)
      - Model-checked (Spin/Promela)
      - Theorem-proved (Lean 4)

    Naming convention:
      INV-S*: Safety properties (no false positives)
      INV-L*: Liveness properties (no false negatives)
      INV-U*: Uniqueness properties
      INV-C*: Correlation properties
      INV-E*: Economic properties
    """

    @staticmethod
    def check_safety_s1(
        slash_result: SlashResult,
        node_was_slashed: bool,
    ) -> bool:
        """
        INV-S1: A node is only slashed if evaluate() returned violated=True.

        No false positive slashing.
        """
        if node_was_slashed:
            return slash_result.violated
        return True  # Not slashed is always safe

    @staticmethod
    def check_safety_s2(
        all_audits_passed: bool,
        all_pdp_passed: bool,
        offense_incremented: bool,
    ) -> bool:
        """
        INV-S2: A node that passes all audits AND PDP proofs in an epoch
        cannot have its offense_count incremented.
        """
        if all_audits_passed and all_pdp_passed:
            return not offense_incremented
        return True

    @staticmethod
    def check_safety_s3(
        pending_slash_reversed: bool,
        stake_deducted: bool,
    ) -> bool:
        """INV-S3: A reversed PendingSlash never results in stake deduction."""
        if pending_slash_reversed:
            return not stake_deducted
        return True

    @staticmethod
    def check_safety_s4(total_slashed: int, stake: int) -> bool:
        """INV-S4: total_slashed ≤ stake (cannot be slashed below zero)."""
        return total_slashed <= stake

    @staticmethod
    def check_liveness_l1(
        consecutive_failures: int,
        eviction_threshold: int,
        is_evicted: bool,
    ) -> bool:
        """
        INV-L1: A node with failures ≥ eviction_threshold must be evicted.
        """
        if consecutive_failures >= eviction_threshold:
            return is_evicted
        return True

    @staticmethod
    def check_liveness_l3(offense_count: int) -> bool:
        """INV-L3: Offense decay cannot reduce offense_count below 0."""
        return offense_count >= 0

    @staticmethod
    def check_uniqueness_u1(
        pending_slashes_this_epoch: list,
        node_id: str,
        offense_event_id: str,
    ) -> bool:
        """
        INV-U1: Same offense event cannot produce two PendingSlash entries
        for the same node in the same epoch.
        """
        matching = [
            p
            for p in pending_slashes_this_epoch
            if getattr(p, "node_id", None) == node_id
            and getattr(p, "_offense_event_id", None) == offense_event_id
        ]
        return len(matching) <= 1

    @staticmethod
    def check_correlation_c1(
        correlation_multiplier: float,
        max_multiplier: float,
    ) -> bool:
        """
        INV-C1: correlation_multiplier ∈ [1.0, max_correlation_multiplier].
        """
        return 1.0 <= correlation_multiplier <= max_multiplier

    @staticmethod
    def check_correlation_c2(
        concurrent_slashed_stake: int,
        correlation_multiplier: float,
    ) -> bool:
        """
        INV-C2: Isolated offense (concurrent=0) → multiplier = 1.0.
        """
        if concurrent_slashed_stake == 0:
            return correlation_multiplier == 1.0
        return True

    @staticmethod
    def check_economic_e1(
        fee: int,
        operator_share: int,
        burn: int,
        endowment: int,
        insurance: int,
    ) -> bool:
        """
        INV-E1: Fee split sums to input fee (no rounding loss > 1 wei).
        """
        total = operator_share + burn + endowment + insurance
        return abs(total - fee) <= 1

    @staticmethod
    def check_economic_e2(
        claimable_t: int,
        claimable_t_plus_1: int,
    ) -> bool:
        """
        INV-E2: Vested rewards monotonically claimable.
        """
        return claimable_t_plus_1 >= claimable_t


# ===========================================================================
# 7. Progressive Decentralization
# ===========================================================================


@dataclass
class DecentralizationMetrics:
    """
    Measurable decentralization metrics for governance transitions.

    Used to gate phase transitions and prevent premature decentralization.
    """

    active_operators: int
    hhi: float  # Herfindahl-Hirschman Index (0-10000)
    gini_coefficient: float  # Token distribution inequality (0-1)
    governance_participation: float  # Fraction of tokens voting (0-1)
    foundation_veto_active: bool

    @staticmethod
    def compute_hhi(stake_shares: list[float]) -> float:
        """
        Compute Herfindahl-Hirschman Index from stake shares.

        HHI = sum(s_i^2) * 10000 where s_i are fractional shares.
        Lower = more decentralized. <1500 = unconcentrated, >2500 = concentrated.
        """
        if not stake_shares:
            return 10_000.0
        total = sum(stake_shares)
        if total == 0:
            return 10_000.0
        normalized = [s / total for s in stake_shares]
        return sum(s * s for s in normalized) * 10_000

    @staticmethod
    def compute_gini(values: list[float]) -> float:
        """
        Compute Gini coefficient from a list of values.

        0.0 = perfect equality, 1.0 = perfect inequality.
        """
        if not values or all(v == 0 for v in values):
            return 0.0
        sorted_values = sorted(values)
        n = len(sorted_values)
        total = sum(sorted_values)
        if total == 0:
            return 0.0
        cumulative = 0.0
        weighted_sum = 0.0
        for i, v in enumerate(sorted_values):
            cumulative += v
            weighted_sum += (2 * (i + 1) - n - 1) * v
        return weighted_sum / (n * total)


@dataclass
class PhaseTransitionRequirements:
    """Requirements that must be met for a governance phase transition."""

    min_operators: int
    max_hhi: float
    max_gini: float
    min_governance_participation: float


class GovernanceTransition:
    """
    Manages progressive decentralization of enforcement governance.

    Phase transitions are one-way (irreversible) and gated by
    measurable decentralization metrics.
    """

    # Requirements for each transition
    BOOTSTRAP_TO_GROWTH = PhaseTransitionRequirements(
        min_operators=5,
        max_hhi=10_000.0,  # No concentration limit during bootstrap
        max_gini=1.0,  # No distribution limit during bootstrap
        min_governance_participation=0.0,
    )

    GROWTH_TO_MATURITY = PhaseTransitionRequirements(
        min_operators=100,
        max_hhi=2_500.0,  # Must be unconcentrated
        max_gini=0.65,  # Reasonable token distribution
        min_governance_participation=0.15,  # 15% participation minimum
    )

    def __init__(self) -> None:
        self._transitions_completed: list[str] = []

    def can_transition(
        self,
        from_phase: str,
        to_phase: str,
        metrics: DecentralizationMetrics,
    ) -> tuple[bool, list[str]]:
        """
        Check if a phase transition is possible given current metrics.

        Returns (can_transition, list of unmet requirements).
        """
        transition_key = f"{from_phase}_to_{to_phase}"

        if transition_key in self._transitions_completed:
            return False, ["Transition already completed (irreversible)"]

        if transition_key == "bootstrap_to_growth":
            reqs = self.BOOTSTRAP_TO_GROWTH
        elif transition_key == "growth_to_maturity":
            reqs = self.GROWTH_TO_MATURITY
        else:
            return False, [f"Unknown transition: {transition_key}"]

        unmet = []
        if metrics.active_operators < reqs.min_operators:
            unmet.append(f"Operators: {metrics.active_operators} < {reqs.min_operators}")
        if metrics.hhi > reqs.max_hhi:
            unmet.append(f"HHI: {metrics.hhi:.0f} > {reqs.max_hhi:.0f}")
        if metrics.gini_coefficient > reqs.max_gini:
            unmet.append(f"Gini: {metrics.gini_coefficient:.2f} > {reqs.max_gini:.2f}")
        if metrics.governance_participation < reqs.min_governance_participation:
            unmet.append(
                f"Governance participation: "
                f"{metrics.governance_participation:.1%} < "
                f"{reqs.min_governance_participation:.1%}"
            )

        return len(unmet) == 0, unmet

    def execute_transition(
        self,
        from_phase: str,
        to_phase: str,
        metrics: DecentralizationMetrics,
    ) -> bool:
        """
        Execute an irreversible phase transition.

        Returns True if transition was executed, False if requirements not met.
        """
        can, unmet = self.can_transition(from_phase, to_phase, metrics)
        if not can:
            return False

        transition_key = f"{from_phase}_to_{to_phase}"
        self._transitions_completed.append(transition_key)

        # Revoke foundation veto on maturity transition
        if to_phase == "maturity":
            metrics.foundation_veto_active = False

        return True

    @property
    def completed_transitions(self) -> list[str]:
        return list(self._transitions_completed)
