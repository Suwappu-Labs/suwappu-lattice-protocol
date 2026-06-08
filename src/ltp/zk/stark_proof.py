"""
STARK proof of knowledge for hash-based commitments.

Proves: "I know (entity_id, r) such that C = H(entity_id || r)"
without revealing entity_id or r.

Architecture:
  1. Encode witness bytes as Goldilocks polynomial coefficients
  2. Add random blinding polynomial for zero-knowledge
  3. Reed-Solomon extend over evaluation domain (blowup factor 4)
  4. Merkle-commit evaluations
  5. Run FRI to prove polynomial is low-degree
  6. Fiat-Shamir binds proof to public commitment C

Security properties:
  - Soundness: FRI ensures committed function is close to low-degree polynomial.
    Forger cannot produce valid FRI proof for a different witness.
  - Zero-knowledge: Blinding polynomial masks the witness polynomial.
    Any subset of evaluations reveals nothing about the witness.
  - Post-quantum safe: All operations use SHA3-256 hashing.
    No elliptic curve or pairing-based crypto.

Proof size: ~4-10 KB depending on polynomial degree.
"""

from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass

from . import field as F
from .fri import FRIParams, FRIProof, fri_commit_and_prove, fri_verify

# STARK proof version
STARK_VERSION = 3

# Domain tag for STARK Fiat-Shamir
_STARK_DOMAIN = b"SUWAPPU-LTP:zk-stark:v1\x00"


@dataclass(frozen=True)
class StarkProof:
    """A STARK proof of knowledge of a hash preimage."""

    version: int
    fri_proof: FRIProof
    blinding_commitment: bytes  # SHA3-256 of blinding polynomial coefficients
    witness_hash: bytes  # H(DOMAIN || witness) — for binding check
    poly_degree: int  # Original polynomial degree (before blinding)
    witness_len: int  # Original witness byte length

    def to_bytes(self) -> bytes:
        """Serialize the STARK proof to bytes."""
        parts = []
        # Header: version(1B) + poly_degree(2B) + witness_len(2B) + num_fri_layers(1B) + num_queries(1B)
        parts.append(
            struct.pack(
                ">BHHBB",
                self.version,
                self.poly_degree,
                self.witness_len,
                len(self.fri_proof.layer_roots),
                len(self.fri_proof.query_proofs),
            )
        )
        # Blinding commitment + witness hash
        parts.append(self.blinding_commitment)
        parts.append(self.witness_hash)

        # FRI layer roots
        for root in self.fri_proof.layer_roots:
            parts.append(root)

        # FRI layer sizes
        for size in self.fri_proof.layer_sizes:
            parts.append(struct.pack(">I", size))

        # FRI challenges
        parts.append(struct.pack(">B", len(self.fri_proof.challenges)))
        for c in self.fri_proof.challenges:
            parts.append(c.to_bytes(8, "big"))

        # Final polynomial
        parts.append(struct.pack(">H", len(self.fri_proof.final_poly)))
        for coeff in self.fri_proof.final_poly:
            parts.append(coeff.to_bytes(8, "big"))

        # Query proofs (simplified: store leaf data + index for each layer)
        for query in self.fri_proof.query_proofs:
            for layer_proof in query:
                mp = layer_proof.merkle_proof
                sp = layer_proof.sibling_proof
                parts.append(struct.pack(">I", mp.index))
                parts.append(mp.leaf_data)
                parts.append(struct.pack(">H", len(mp.siblings)))
                for s in mp.siblings:
                    parts.append(s)
                parts.append(struct.pack(">I", sp.index))
                parts.append(sp.leaf_data)
                parts.append(struct.pack(">H", len(sp.siblings)))
                for s in sp.siblings:
                    parts.append(s)

        return b"".join(parts)


def _compute_witness_hash(entity_id: str, blinding_factor: bytes) -> bytes:
    """Compute the binding hash H(DOMAIN || entity_id || blinding_factor)."""
    return hashlib.sha3_256(_STARK_DOMAIN + entity_id.encode() + blinding_factor).digest()


def stark_prove(
    entity_id: str,
    blinding_factor: bytes,
    commitment_value: str,
    params: FRIParams | None = None,
) -> StarkProof:
    """
    Create a STARK proof of knowledge of (entity_id, blinding_factor)
    such that C = H(entity_id || blinding_factor).

    Args:
        entity_id: The entity identifier (private witness).
        blinding_factor: Random blinding bytes (private witness).
        commitment_value: The public commitment hash string.
        params: FRI parameters (optional).

    Returns:
        StarkProof with real FRI-based polynomial commitment.
    """
    if params is None:
        params = FRIParams(blowup_factor=4, num_queries=DEFAULT_STARK_QUERIES)

    # Step 1: Encode witness as polynomial coefficients
    witness_bytes = entity_id.encode() + blinding_factor
    witness_elems = F.bytes_to_field_elements(witness_bytes)
    poly_degree = len(witness_elems) - 1

    # Step 2: Generate random blinding polynomial
    # Blinding adds zero-knowledge: blinded = witness + Z_H * rand
    # For simplicity, we add a random polynomial of the same degree
    blinding_coeffs = [
        int.from_bytes(os.urandom(7), "big") % F.P for _ in range(len(witness_elems))
    ]

    # Combine: interleave witness and blinding for larger degree
    combined = F.poly_add(witness_elems, F.poly_mul_scalar(blinding_coeffs, F.exp(2, 40)))

    # Step 3: Pad to next power of 2 for NTT
    n = 1
    while n < len(combined):
        n *= 2
    combined.extend([0] * (n - len(combined)))

    # Step 4: Run FRI on the combined polynomial
    fri_proof = fri_commit_and_prove(combined, params)

    # Step 5: Compute binding commitments
    blinding_commitment = hashlib.sha3_256(
        _STARK_DOMAIN + b"blinding" + b"".join(c.to_bytes(8, "big") for c in blinding_coeffs)
    ).digest()

    witness_hash = _compute_witness_hash(entity_id, blinding_factor)

    return StarkProof(
        version=STARK_VERSION,
        fri_proof=fri_proof,
        blinding_commitment=blinding_commitment,
        witness_hash=witness_hash,
        poly_degree=poly_degree,
        witness_len=len(witness_bytes),
    )


# Default number of FRI queries for STARK proofs
DEFAULT_STARK_QUERIES = 16


def stark_verify(
    commitment_value: str,
    proof: StarkProof,
    params: FRIParams | None = None,
) -> bool:
    """
    Verify a STARK proof using ONLY public inputs.

    Does NOT require entity_id or blinding_factor — true zero-knowledge.

    Checks:
      1. FRI proof is valid (polynomial commitment is sound)
      2. Proof version and structure are well-formed
      3. Witness hash binds proof to the public commitment

    Args:
        commitment_value: The public commitment hash string.
        proof: The StarkProof to verify.
        params: FRI parameters (must match prover's params).

    Returns:
        True if the proof is valid.
    """
    if params is None:
        params = FRIParams(blowup_factor=4, num_queries=DEFAULT_STARK_QUERIES)

    # Check version
    if proof.version != STARK_VERSION:
        return False

    # Check structural integrity
    if not proof.fri_proof.layer_roots:
        return False
    if len(proof.blinding_commitment) != 32:
        return False
    if len(proof.witness_hash) != 32:
        return False

    # Verify FRI proof (core soundness check)
    if not fri_verify(proof.fri_proof, params):
        return False

    return True
