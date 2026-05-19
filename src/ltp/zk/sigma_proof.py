"""
Sigma protocol (Schnorr-like) ZK proof of knowledge for Pedersen commitments.

Proves: "I know (m, r) such that C = m*G + r*H"
without revealing m or r.

Protocol (non-interactive via Fiat-Shamir):

  Prover(m, r, C):
    k_m, k_r  <- random scalars
    T          = k_m*G + k_r*H
    e          = H_fs(domain || G || H || C || T) mod order
    s_m        = (k_m + e * m) mod order
    s_r        = (k_r + e * r) mod order
    proof      = T || s_m || s_r                     # 160 bytes

  Verifier(C, proof):
    Parse (T, s_m, s_r)
    e          = H_fs(domain || G || H || C || T) mod order
    Check: s_m*G + s_r*H == T + e*C

Security properties:
  - Completeness: Honest prover always convinces verifier.
  - Special soundness: Two accepting transcripts with distinct challenges
    yield (m, r) — so a forger must break DLP.
  - Honest-verifier zero-knowledge: Simulator can produce indistinguishable
    transcripts without knowing (m, r).
  - Non-interactive via Fiat-Shamir (random oracle model).

Proof size: 96 (T) + 32 (s_m) + 32 (s_r) = 160 bytes.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from .ec_backend import (
    curve_order,
    g1_add,
    g1_deserialize,
    g1_eq,
    g1_generator,
    g1_h_generator,
    g1_scalar_mul,
    g1_serialize,
    random_scalar,
    scalar_from_bytes,
    scalar_from_entity_id,
)

# Proof is 96 (T point) + 32 (s_m scalar) + 32 (s_r scalar) = 160 bytes
SIGMA_PROOF_SIZE = 160


def _fiat_shamir_challenge(
    commitment_bytes: bytes,
    t_bytes: bytes,
) -> int:
    """
    Compute the Fiat-Shamir challenge scalar.

    e = SHA3-256(DOMAIN || G_serialized || H_serialized || C || T) mod order

    The generators G and H are included to bind the proof to the specific
    Pedersen parameter set (prevents rogue-parameter attacks).
    """
    from ..domain import DOMAIN_ZK_TRANSFER

    g_bytes = g1_serialize(g1_generator())
    h_bytes = g1_serialize(g1_h_generator())

    transcript = (
        DOMAIN_ZK_TRANSFER
        + b"sigma"
        + struct.pack(">I", len(g_bytes))
        + g_bytes
        + struct.pack(">I", len(h_bytes))
        + h_bytes
        + struct.pack(">I", len(commitment_bytes))
        + commitment_bytes
        + struct.pack(">I", len(t_bytes))
        + t_bytes
    )
    digest = hashlib.sha3_256(transcript).digest()
    return int.from_bytes(digest, "big") % curve_order()


@dataclass(frozen=True)
class SigmaProof:
    """Non-interactive Sigma protocol proof of Pedersen commitment opening."""

    t_point: bytes  # 96B uncompressed G1 point T (prover's first message)
    s_m: bytes  # 32B scalar response for message component
    s_r: bytes  # 32B scalar response for blinding component

    def to_bytes(self) -> bytes:
        """Serialize to 160 bytes: T || s_m || s_r."""
        return self.t_point + self.s_m + self.s_r

    @classmethod
    def from_bytes(cls, data: bytes) -> SigmaProof:
        """Deserialize from 160 bytes."""
        if len(data) != SIGMA_PROOF_SIZE:
            raise ValueError(f"Sigma proof must be {SIGMA_PROOF_SIZE} bytes, got {len(data)}")
        return cls(
            t_point=data[:96],
            s_m=data[96:128],
            s_r=data[128:160],
        )


def create_sigma_proof(
    entity_id: str,
    blinding_factor: bytes,
    commitment_bytes: bytes,
) -> SigmaProof:
    """
    Create a non-interactive Sigma proof of knowledge of (m, r)
    such that C = m*G + r*H.

    Args:
        entity_id: The entity identifier (private witness).
        blinding_factor: The blinding factor bytes (private witness).
        commitment_bytes: 96-byte serialized commitment point (public).

    Returns:
        SigmaProof with 160 bytes total.
    """
    order = curve_order()
    m = scalar_from_entity_id(entity_id)
    r = scalar_from_bytes(blinding_factor)

    # Step 1: Prover picks random nonces
    k_m = random_scalar()
    k_r = random_scalar()

    # Step 2: Compute T = k_m*G + k_r*H
    T = g1_add(
        g1_scalar_mul(g1_generator(), k_m),
        g1_scalar_mul(g1_h_generator(), k_r),
    )
    t_bytes = g1_serialize(T)

    # Step 3: Fiat-Shamir challenge
    e = _fiat_shamir_challenge(commitment_bytes, t_bytes)

    # Step 4: Compute responses
    s_m = (k_m + e * m) % order
    s_r = (k_r + e * r) % order

    return SigmaProof(
        t_point=t_bytes,
        s_m=s_m.to_bytes(32, "big"),
        s_r=s_r.to_bytes(32, "big"),
    )


def verify_sigma_proof(
    commitment_bytes: bytes,
    proof: SigmaProof,
) -> bool:
    """
    Verify a Sigma proof against a Pedersen commitment.

    Uses ONLY public inputs: the commitment and the proof.
    Does NOT require entity_id or blinding_factor — this is the
    fundamental zero-knowledge property.

    Checks: s_m*G + s_r*H == T + e*C

    Args:
        commitment_bytes: 96-byte serialized commitment point.
        proof: The SigmaProof to verify.

    Returns:
        True if the proof is valid.
    """
    try:
        # Deserialize points
        T = g1_deserialize(proof.t_point)
        C = g1_deserialize(commitment_bytes)
    except (ValueError, TypeError):
        return False

    # Reconstruct challenge
    e = _fiat_shamir_challenge(commitment_bytes, proof.t_point)

    # Parse scalar responses
    s_m = int.from_bytes(proof.s_m, "big")
    s_r = int.from_bytes(proof.s_r, "big")

    order = curve_order()
    if s_m >= order or s_r >= order:
        return False

    # LHS = s_m*G + s_r*H
    lhs = g1_add(
        g1_scalar_mul(g1_generator(), s_m),
        g1_scalar_mul(g1_h_generator(), s_r),
    )

    # RHS = T + e*C
    rhs = g1_add(T, g1_scalar_mul(C, e))

    return g1_eq(lhs, rhs)
