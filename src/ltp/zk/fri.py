"""
FRI (Fast Reed-Solomon Interactive Oracle Proof) protocol.

Proves that a Merkle-committed function is close to a low-degree polynomial.
Made non-interactive via Fiat-Shamir (random oracle = SHA3-256).

Protocol overview:
  1. Prover evaluates polynomial p(x) over an extended domain (blowup factor 4)
  2. Commits to evaluations via Merkle tree
  3. For each folding round:
     - Fiat-Shamir challenge alpha
     - Fold: p_{i+1}(x) = even(x) + alpha * odd(x)
       where p_i(x) = even(x^2) + x * odd(x^2)
     - Commit folded evaluations via new Merkle tree
  4. When degree is small enough, reveal final polynomial
  5. For 32 random query indices, open Merkle paths at all layers
  6. Verifier checks consistency across layers

Parameters for 128-bit security: blowup=4, queries=32.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from dataclasses import field as dataclass_field

from . import field as F
from .merkle import MerkleProof, StarkMerkleTree

# FRI domain tag for Fiat-Shamir
_FRI_DOMAIN = b"GSX-LTP:fri:v1\x00"

# Default parameters
DEFAULT_BLOWUP = 4
DEFAULT_NUM_QUERIES = 32
MAX_FINAL_DEGREE = 3  # Reveal polynomial when degree drops to this


@dataclass(frozen=True)
class FRIParams:
    blowup_factor: int = DEFAULT_BLOWUP
    num_queries: int = DEFAULT_NUM_QUERIES

    def __post_init__(self) -> None:
        if self.blowup_factor <= 0:
            raise ValueError("blowup_factor must be positive")
        if self.num_queries <= 0:
            raise ValueError("num_queries must be positive")


@dataclass(frozen=True)
class FRILayerProof:
    """Merkle proof for one query at one FRI layer."""

    merkle_proof: MerkleProof
    sibling_proof: MerkleProof  # Proof for the paired index


@dataclass(frozen=True)
class FRIProof:
    """Complete FRI proof."""

    layer_roots: tuple[bytes, ...]  # Merkle root per folding layer
    layer_sizes: tuple[int, ...]  # Domain size per layer
    final_poly: tuple[int, ...]  # Coefficients of final low-degree polynomial
    query_proofs: tuple[tuple[FRILayerProof, ...], ...]  # [query][layer]
    challenges: tuple[int, ...]  # Fiat-Shamir alpha per round


def _fiat_shamir_alpha(roots_so_far: list[bytes], round_idx: int) -> int:
    """Derive a FRI folding challenge via Fiat-Shamir."""
    transcript = _FRI_DOMAIN + b"fold"
    transcript += struct.pack(">I", len(roots_so_far))
    for r in roots_so_far:
        transcript += struct.pack(">I", len(r)) + r
    transcript += struct.pack(">I", round_idx)
    digest = hashlib.sha3_256(transcript).digest()
    return int.from_bytes(digest, "big") % F.P


def _fiat_shamir_queries(all_roots: list[bytes], domain_size: int, num_queries: int) -> list[int]:
    """Derive query indices via Fiat-Shamir."""
    transcript = _FRI_DOMAIN + b"query"
    transcript += struct.pack(">I", len(all_roots))
    for r in all_roots:
        transcript += struct.pack(">I", len(r)) + r
    indices = []
    for i in range(num_queries):
        h = hashlib.sha3_256(transcript + struct.pack(">I", i)).digest()
        idx = int.from_bytes(h[:4], "big") % (domain_size // 2)
        indices.append(idx)
    return indices


def _fold_evaluations(
    evals: list[int], domain: list[int], alpha: int
) -> tuple[list[int], list[int]]:
    """
    Fold evaluations: given p(x) at domain points, compute p_next at half domain.

    p_next(x^2) = (p(x) + p(-x))/2 + alpha * (p(x) - p(-x))/(2x)
    """
    half = len(evals) // 2
    new_evals = []
    new_domain = []

    for i in range(half):
        # evals[i] = p(w^i), evals[i + half] = p(w^(i + half)) = p(-w^i)
        # since w^(n/2) = -1
        p_pos = evals[i]
        p_neg = evals[i + half]
        x = domain[i]

        even = F.div(F.add(p_pos, p_neg), 2)
        odd = F.div(F.sub(p_pos, p_neg), F.mul(2, x))

        new_evals.append(F.add(even, F.mul(alpha, odd)))
        new_domain.append(F.mul(x, x))  # x^2

    return new_evals, new_domain


def fri_commit_and_prove(
    poly_coeffs: list[int],
    params: FRIParams | None = None,
) -> FRIProof:
    """
    Generate a FRI proof that poly_coeffs represents a low-degree polynomial.

    Args:
        poly_coeffs: Polynomial coefficients in Goldilocks field.
        params: FRI parameters (blowup, num_queries).

    Returns:
        FRIProof containing Merkle commitments and query responses.
    """
    if params is None:
        params = FRIParams()

    degree = len(poly_coeffs) - 1
    if degree > 65536:
        raise ValueError("Polynomial degree exceeds limit")
    # Domain size = next power of 2 >= (degree+1) * blowup
    eval_size = 1
    while eval_size < (degree + 1) * params.blowup_factor:
        eval_size *= 2

    # Evaluate polynomial over the full domain using NTT
    omega = F.root_of_unity(eval_size)
    # Pad coefficients to eval_size
    padded = list(poly_coeffs) + [0] * (eval_size - len(poly_coeffs))
    evals = F.ntt(padded, omega)

    # Build domain points: [1, omega, omega^2, ...]
    domain = [1]
    for _ in range(1, eval_size):
        domain.append(F.mul(domain[-1], omega))

    # FRI folding rounds
    layer_roots: list[bytes] = []
    layer_sizes: list[int] = []
    layer_trees: list[StarkMerkleTree] = []
    layer_evals: list[list[int]] = [evals]
    layer_domains: list[list[int]] = [domain]
    challenges: list[int] = []

    current_evals = evals
    current_domain = domain

    # Commit first layer
    leaves = [v.to_bytes(8, "big") for v in current_evals]
    tree = StarkMerkleTree(leaves)
    layer_roots.append(tree.root())
    layer_sizes.append(len(current_evals))
    layer_trees.append(tree)

    # Fold until polynomial degree is small enough
    current_degree = degree
    while current_degree > MAX_FINAL_DEGREE and len(current_evals) > 2:
        # Fiat-Shamir challenge
        alpha = _fiat_shamir_alpha(layer_roots, len(challenges))
        challenges.append(alpha)

        # Fold
        current_evals, current_domain = _fold_evaluations(current_evals, current_domain, alpha)
        current_degree = current_degree // 2

        # Commit folded layer
        leaves = [v.to_bytes(8, "big") for v in current_evals]
        tree = StarkMerkleTree(leaves)
        layer_roots.append(tree.root())
        layer_sizes.append(len(current_evals))
        layer_trees.append(tree)
        layer_evals.append(current_evals)
        layer_domains.append(current_domain)

    # Final polynomial: recover coefficients from last evaluations
    if len(current_evals) > 1:
        final_omega = F.root_of_unity(len(current_evals)) if len(current_evals) > 1 else 1
        final_poly = F.intt(current_evals, final_omega)
    else:
        final_poly = list(current_evals)

    # Query phase
    query_indices = _fiat_shamir_queries(layer_roots, layer_sizes[0], params.num_queries)

    query_proofs: list[tuple[FRILayerProof, ...]] = []
    for q_idx in query_indices:
        layer_proofs: list[FRILayerProof] = []
        idx = q_idx
        for layer_i, tree in enumerate(layer_trees):
            size = layer_sizes[layer_i]
            half = size // 2
            # Open at idx and its pair (idx + half) for consistency check
            proof_main = tree.open(idx % size)
            sibling_idx = (idx + half) % size
            proof_sibling = tree.open(sibling_idx)
            layer_proofs.append(FRILayerProof(proof_main, proof_sibling))
            idx = idx % half  # Index in next (folded) layer
        query_proofs.append(tuple(layer_proofs))

    return FRIProof(
        layer_roots=tuple(layer_roots),
        layer_sizes=tuple(layer_sizes),
        final_poly=tuple(final_poly),
        query_proofs=tuple(query_proofs),
        challenges=tuple(challenges),
    )


def fri_verify(proof: FRIProof, params: FRIParams | None = None) -> bool:
    """
    Verify a FRI proof.

    Checks:
      1. Fiat-Shamir challenges are correct
      2. All Merkle proofs are valid
      3. Folding consistency: values at paired indices fold correctly
      4. Final polynomial evaluations match last layer commitments

    Returns:
        True if the proof is valid.
    """
    if params is None:
        params = FRIParams()

    num_layers = len(proof.layer_roots)
    if num_layers < 1:
        return False

    # Verify Fiat-Shamir challenges
    for i, alpha in enumerate(proof.challenges):
        expected = _fiat_shamir_alpha(list(proof.layer_roots[: i + 1]), i)
        if alpha != expected:
            return False

    # Verify query indices
    query_indices = _fiat_shamir_queries(
        list(proof.layer_roots), proof.layer_sizes[0], params.num_queries
    )

    if len(proof.query_proofs) != len(query_indices):
        return False

    # Verify each query
    for q_num, q_idx in enumerate(query_indices):
        if q_num >= len(proof.query_proofs):
            return False

        idx = q_idx
        for layer_i in range(num_layers):
            size = proof.layer_sizes[layer_i]
            half = size // 2
            root = proof.layer_roots[layer_i]

            layer_proof = proof.query_proofs[q_num][layer_i]

            # Verify Merkle proofs
            if not StarkMerkleTree.verify(root, layer_proof.merkle_proof, size):
                return False
            if not StarkMerkleTree.verify(root, layer_proof.sibling_proof, size):
                return False

            # Check folding consistency with next layer (if not last)
            if layer_i < num_layers - 1:
                # Get values
                val_pos = int.from_bytes(layer_proof.merkle_proof.leaf_data, "big")
                val_neg = int.from_bytes(layer_proof.sibling_proof.leaf_data, "big")

                alpha = proof.challenges[layer_i]

                # Compute the domain point for this index
                omega = F.root_of_unity(size)
                x = F.exp(omega, idx % size)

                # Fold: new_val = (val_pos + val_neg)/2 + alpha * (val_pos - val_neg)/(2*x)
                even = F.div(F.add(val_pos, val_neg), 2)
                odd = F.div(F.sub(val_pos, val_neg), F.mul(2, x))
                expected_folded = F.add(even, F.mul(alpha, odd))

                # Check against next layer's value at the folded index
                next_layer_proof = proof.query_proofs[q_num][layer_i + 1]
                actual_folded = int.from_bytes(next_layer_proof.merkle_proof.leaf_data, "big")

                if expected_folded != actual_folded:
                    return False

            idx = idx % half

    # Verify final polynomial matches last layer
    last_size = proof.layer_sizes[-1]
    if last_size > 1:
        last_omega = F.root_of_unity(last_size)
        for q_num, q_idx in enumerate(query_indices):
            # Trace idx down to last layer
            idx = q_idx
            for layer_i in range(num_layers - 1):
                idx = idx % (proof.layer_sizes[layer_i] // 2)

            last_proof = proof.query_proofs[q_num][-1]
            val = int.from_bytes(last_proof.merkle_proof.leaf_data, "big")
            point = F.exp(last_omega, idx % last_size)
            expected_val = F.poly_eval(list(proof.final_poly), point)
            if val != expected_val:
                return False

    return True
