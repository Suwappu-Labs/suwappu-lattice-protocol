"""
ZK Transfer Mode for the Lattice Transfer Protocol.

Provides privacy-preserving transfers where the commitment log does not
reveal which entity was committed. Uses hiding commitments and
zero-knowledge proofs.

When py_ecc is installed ([zk] extras), the GROTH16 backend uses real
Pedersen commitments (C = m*G + r*H on BLS12-381 G1) with Sigma protocol
ZK proofs. Without py_ecc, GROTH16 falls back to hash-based simulation.

The SIMULATED backend always uses hash-based PoC (no real crypto).
The STARK backend is hash-based (real STARK deferred to Sub-phase B).

Whitepaper reference: §3.2, Open Question 8

⚠ WARNING: The GROTH16 backend (BLS12-381) is NOT post-quantum safe.
Shor's algorithm breaks the DLP assumption. Standard LTP mode is fully
post-quantum. The STARK backend will provide PQ-safe ZK in Sub-phase B.

Design decision: docs/design-decisions/ZK_TRANSFER_MODE.md
"""

from __future__ import annotations

import hmac
import os
import warnings
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .primitives import canonical_hash, canonical_hash_bytes

__all__ = [
    "ZKProofSystem",
    "ZKConfig",
    "ZKCommitment",
    "ZKProof",
    "ZKTransferMode",
]


class ZKProofSystem(Enum):
    """Available ZK proof systems."""

    SIMULATED = "simulated"  # Uses real Pedersen+Sigma (BLS12-381) when py_ecc available
    GROTH16 = "groth16"  # BLS12-381 Sigma protocol — NOT post-quantum (Shor breaks DLP)
    STARK = "stark"  # Post-quantum safe (FRI + Goldilocks field, hash-only)


@dataclass
class ZKConfig:
    """Configuration for ZK transfer mode.

    For post-quantum deployments, use proof_system=STARK.
    GROTH16/SIMULATED use BLS12-381 which is broken by Shor's algorithm.
    """

    enabled: bool = False
    proof_system: ZKProofSystem = ZKProofSystem.STARK  # Default to PQ-safe STARK
    curve: str = "bls12_381"  # Only relevant for Groth16
    hiding_commitment: bool = True  # Use hiding commitment for entity_id


@dataclass
class ZKCommitment:
    """
    A hiding commitment to an entity_id.

    In production (Groth16): C = g^{entity_id} · h^r over BLS12-381
    In simulation: C = H(entity_id || blinding_factor)

    The commitment hides entity_id from the commitment log while
    allowing ZK proof of knowledge.
    """

    commitment_value: str  # The commitment C (hex string)
    blinding_factor: bytes  # Random blinding factor r
    entity_id: str  # The hidden entity_id (known to creator only)

    @property
    def is_hiding(self) -> bool:
        """A commitment is hiding if it has a non-zero blinding factor."""
        return len(self.blinding_factor) > 0 and any(b != 0 for b in self.blinding_factor)


@dataclass
class ZKProof:
    """
    A zero-knowledge proof of knowledge of entity_id.

    Proves: "I know entity_id such that C = Commit(entity_id, r)"
    without revealing entity_id.

    In simulation: proof = H(entity_id || blinding_factor || "proof")
    In production: Groth16 proof (~192 bytes) or STARK proof (~45 KB)
    """

    proof_bytes: bytes
    proof_system: ZKProofSystem
    public_inputs: dict = field(default_factory=dict)

    @property
    def proof_size_bytes(self) -> int:
        return len(self.proof_bytes)


class ZKTransferMode:
    """
    Zero-knowledge transfer mode for entity_id privacy.

    Allows commits to the log without revealing which entity was committed.
    The commitment log sees only C (a hiding commitment) and a ZK proof
    that the committer knows the opening.

    PoC uses simulated commitments and proofs. Production requires
    Groth16 (BLS12-381) or STARK circuit implementations.
    """

    # Cache for STARK proof objects (keyed by proof_bytes hash)
    _stark_proof_cache: dict[bytes, object] = {}

    def __init__(self, config: ZKConfig | None = None) -> None:
        self.config = config or ZKConfig()
        if self.config.proof_system == ZKProofSystem.GROTH16:
            warnings.warn(
                "GROTH16 (BLS12-381) is NOT post-quantum safe. "
                "Shor's algorithm breaks the DLP assumption. "
                "Use proof_system=STARK for post-quantum security.",
                stacklevel=2,
            )

    def _use_real_ec_backend(self) -> bool:
        """True when py_ecc is available AND config selects GROTH16 or SIMULATED."""
        if self.config.proof_system not in (ZKProofSystem.GROTH16, ZKProofSystem.SIMULATED):
            return False
        from .zk.ec_backend import bls12_381_available

        return bls12_381_available()

    def _verify_stark_proof(self, commitment: "ZKCommitment", proof: "ZKProof") -> bool:
        """Verify a STARK proof by looking up the cached StarkProof object."""
        import hashlib

        from .zk.stark_proof import stark_verify

        key = hashlib.sha3_256(proof.proof_bytes).digest()
        stark_obj = ZKTransferMode._stark_proof_cache.get(key)
        if stark_obj is None:
            return False
        return stark_verify(commitment.commitment_value, stark_obj)

    def create_hiding_commitment(self, entity_id: str) -> ZKCommitment:
        """
        Create a hiding commitment to entity_id.

        With py_ecc (GROTH16): Real Pedersen C = m*G + r*H on BLS12-381.
        Without py_ecc / SIMULATED / STARK: Hash-based simulation.
        """
        blinding_factor = os.urandom(32)

        if self._use_real_ec_backend():
            from .zk.pedersen import pedersen_commit

            commitment_value = pedersen_commit(entity_id, blinding_factor).hex()
        elif self.config.proof_system == ZKProofSystem.SIMULATED:
            # py_ecc not available — fall back to hash-based commitment
            warnings.warn(
                "py_ecc not installed; SIMULATED using hash fallback. "
                "Install with: pip install 'ltp[zk]'",
                stacklevel=2,
            )
            commitment_value = canonical_hash(entity_id.encode() + blinding_factor)
        elif self.config.proof_system == ZKProofSystem.GROTH16:
            # py_ecc not available — fall back to hash simulation
            warnings.warn(
                "py_ecc not installed; GROTH16 falling back to hash simulation. "
                "Install with: pip install 'ltp[zk]'",
                stacklevel=2,
            )
            commitment_value = canonical_hash(
                entity_id.encode() + blinding_factor + self.config.curve.encode()
            )
        elif self.config.proof_system == ZKProofSystem.STARK:
            # STARK: hash-based commitment (PQ-safe, commitment is SHA3-256)
            commitment_value = canonical_hash(entity_id.encode() + blinding_factor)

        return ZKCommitment(
            commitment_value=commitment_value,
            blinding_factor=blinding_factor,
            entity_id=entity_id,
        )

    def create_zk_proof(
        self,
        entity_id: str,
        commitment: ZKCommitment,
    ) -> ZKProof:
        """
        Create a ZK proof that the committer knows entity_id opening C.

        With py_ecc (GROTH16): Real Sigma protocol proof (~160 bytes).
        Without py_ecc / SIMULATED / STARK: Hash-based simulation.
        """
        if commitment.entity_id != entity_id:
            raise ValueError("Entity ID does not match commitment")

        if self._use_real_ec_backend():
            from .zk.sigma_proof import create_sigma_proof

            sigma = create_sigma_proof(
                entity_id,
                commitment.blinding_factor,
                bytes.fromhex(commitment.commitment_value),
            )
            proof_bytes = sigma.to_bytes()
        elif self.config.proof_system == ZKProofSystem.SIMULATED:
            # py_ecc not available — hash fallback
            proof_bytes = canonical_hash_bytes(
                entity_id.encode() + commitment.blinding_factor + b"proof"
            )
        elif self.config.proof_system == ZKProofSystem.GROTH16:
            # py_ecc not available — hash simulation fallback
            proof_bytes = canonical_hash_bytes(
                entity_id.encode() + commitment.blinding_factor + b"groth16-proof"
            )
            proof_bytes = proof_bytes + os.urandom(160)
        elif self.config.proof_system == ZKProofSystem.STARK:
            import hashlib as _hl

            from .zk.stark_proof import stark_prove

            stark = stark_prove(
                entity_id,
                commitment.blinding_factor,
                commitment.commitment_value,
            )
            proof_bytes = stark.to_bytes()
            # Cache the StarkProof object for verification
            cache_key = _hl.sha3_256(proof_bytes).digest()
            ZKTransferMode._stark_proof_cache[cache_key] = stark
        else:
            raise ValueError(f"Unknown proof system: {self.config.proof_system}")

        return ZKProof(
            proof_bytes=proof_bytes,
            proof_system=self.config.proof_system,
            public_inputs={
                "commitment": commitment.commitment_value,
            },
        )

    def verify_zk_proof(
        self,
        commitment: ZKCommitment,
        proof: ZKProof,
    ) -> bool:
        """
        Verify a ZK proof against a commitment.

        With py_ecc (GROTH16): Real Sigma protocol verification using
        ONLY public inputs (commitment_value + proof_bytes). Does NOT
        access entity_id or blinding_factor — true zero-knowledge.

        Without py_ecc / SIMULATED / STARK: Hash-based verification.
        """
        if proof.proof_system != self.config.proof_system:
            return False

        if self._use_real_ec_backend():
            from .zk.sigma_proof import SigmaProof, verify_sigma_proof

            try:
                sigma = SigmaProof.from_bytes(proof.proof_bytes)
                return verify_sigma_proof(
                    bytes.fromhex(commitment.commitment_value),
                    sigma,
                )
            except (ValueError, TypeError):
                return False

        if self.config.proof_system == ZKProofSystem.SIMULATED:
            expected = canonical_hash_bytes(
                commitment.entity_id.encode() + commitment.blinding_factor + b"proof"
            )
            return hmac.compare_digest(proof.proof_bytes, expected)
        elif self.config.proof_system == ZKProofSystem.GROTH16:
            # py_ecc not available — hash simulation fallback
            expected_prefix = canonical_hash_bytes(
                commitment.entity_id.encode() + commitment.blinding_factor + b"groth16-proof"
            )
            return hmac.compare_digest(proof.proof_bytes[: len(expected_prefix)], expected_prefix)
        elif self.config.proof_system == ZKProofSystem.STARK:
            from .zk.stark_proof import StarkProof, stark_verify

            try:
                # Deserialize is complex; for now, re-prove and compare binding
                # Real verification: parse proof bytes and run FRI verify
                # We use the StarkProof object passed through public_inputs
                return self._verify_stark_proof(commitment, proof)
            except (ValueError, TypeError):
                return False

        return False

    def open_commitment(
        self,
        commitment: ZKCommitment,
        entity_id: str,
        blinding_factor: bytes,
    ) -> bool:
        """
        Open (reveal) a commitment — verify that C was created from
        the given entity_id and blinding_factor.

        This is NOT zero-knowledge (it reveals entity_id). Used for
        dispute resolution or selective disclosure.
        """
        if self._use_real_ec_backend():
            from .zk.pedersen import pedersen_open

            return pedersen_open(
                bytes.fromhex(commitment.commitment_value),
                entity_id,
                blinding_factor,
            )

        # Hash-based fallback (STARK or py_ecc-missing paths)
        expected = canonical_hash(entity_id.encode() + blinding_factor)
        return hmac.compare_digest(commitment.commitment_value, expected)


@dataclass
class ContentPropertyProof:
    """
    A proof about entity content properties without revealing the content.

    Examples:
      - "This entity is a valid JSON document"
      - "This entity's 'age' field is >= 18"
      - "This entity conforms to schema X"

    Open Question 8(a): What is the appropriate circuit composition model?
    """

    property_name: str  # Human-readable property
    property_circuit_id: str  # Circuit identifier
    proof: ZKProof  # The ZK proof
    public_inputs: dict  # Public inputs to the circuit

    @property
    def is_verifiable(self) -> bool:
        """Whether the proof can be verified (has required fields)."""
        return (
            bool(self.property_circuit_id)
            and self.proof.proof_bytes is not None
            and len(self.proof.proof_bytes) > 0
        )
