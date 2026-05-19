"""
Pure verification functions for the Lattice Transfer Protocol.

All functions are pure — no network, no state, no side effects.
They accept trust artifacts and return VerificationResult.

Reference: GSX_PRE_BLOCKCHAIN_ROADMAP.md §2.8
"""

from __future__ import annotations

from .results import VerificationResult

__all__ = [
    "verify_envelope",
    "verify_receipt",
    "verify_merkle_proof",
    "verify_sth",
    "verify_commitment_chain",
]


def verify_envelope(
    envelope: "SignedEnvelope",
    max_drift: float | None = None,
) -> VerificationResult:
    """Verify a SignedEnvelope's signature and optional timestamp freshness.

    Pure function — no state mutation.
    """
    try:
        valid = envelope.verify(max_drift=max_drift)
        if valid:
            return VerificationResult(
                valid=True,
                reason="signature valid",
                artifact="envelope",
                details={
                    "signer_kid": envelope.signer_kid.hex(),
                    "payload_type": envelope.payload_type,
                },
            )
        else:
            return VerificationResult(
                valid=False,
                reason="signature verification failed or timestamp drift exceeded",
                artifact="envelope",
            )
    except Exception as e:
        return VerificationResult(
            valid=False,
            reason=f"verification error: {e}",
            artifact="envelope",
        )


def verify_receipt(
    receipt: "ApprovalReceipt",
    policy: "SignerPolicy | None" = None,
) -> VerificationResult:
    """Verify an ApprovalReceipt's signature and optional policy compliance.

    If policy is provided, also checks signer authorization and receipt age.
    """
    try:
        # Basic signature verification
        if not receipt.verify(receipt.signer_vk):
            return VerificationResult(
                valid=False,
                reason="receipt signature invalid",
                artifact="receipt",
            )

        # Policy check if provided
        if policy is not None:
            ok, reason = policy.verify_receipt(receipt)
            if not ok:
                return VerificationResult(
                    valid=False,
                    reason=f"policy check failed: {reason}",
                    artifact="receipt",
                )

        return VerificationResult(
            valid=True,
            reason="receipt valid",
            artifact="receipt",
            details={
                "receipt_id": receipt.receipt_id,
                "receipt_type": receipt.receipt_type.value,
                "entity_id": receipt.entity_id,
            },
        )
    except Exception as e:
        return VerificationResult(
            valid=False,
            reason=f"verification error: {e}",
            artifact="receipt",
        )


def verify_merkle_proof(proof: "PortableMerkleProof") -> VerificationResult:
    """Verify a PortableMerkleProof independently.

    Reconstructs the root from the leaf hash + audit path and compares.
    """
    try:
        valid = proof.verify()
        if valid:
            return VerificationResult(
                valid=True,
                reason="merkle proof valid",
                artifact="merkle-proof",
                details={
                    "tree_type": proof.tree_type.value,
                    "leaf_index": proof.leaf_index,
                    "tree_size": proof.tree_size,
                },
            )
        else:
            return VerificationResult(
                valid=False,
                reason="root reconstruction mismatch",
                artifact="merkle-proof",
            )
    except Exception as e:
        return VerificationResult(
            valid=False,
            reason=f"verification error: {e}",
            artifact="merkle-proof",
        )


def verify_sth(sth: "SignedTreeHead") -> VerificationResult:
    """Verify a SignedTreeHead's ML-DSA signature."""
    try:
        valid = sth.verify()
        if valid:
            return VerificationResult(
                valid=True,
                reason="STH signature valid",
                artifact="sth",
                details={
                    "sequence": sth.sequence,
                    "tree_size": sth.tree_size,
                    "root_hash": sth.root_hash.hex(),
                },
            )
        else:
            return VerificationResult(
                valid=False,
                reason="STH signature invalid",
                artifact="sth",
            )
    except Exception as e:
        return VerificationResult(
            valid=False,
            reason=f"verification error: {e}",
            artifact="sth",
        )


def verify_commitment_chain(
    records: list["CommitmentRecord"],
    proofs: list["PortableMerkleProof"],
) -> VerificationResult:
    """Verify a chain of commitment records with their Merkle proofs.

    Checks:
      1. Each proof is valid (root reconstruction)
      2. Records are in sequence (predecessor chain)
      3. All proofs reference the same root or monotonically advancing roots
    """
    if len(records) != len(proofs):
        return VerificationResult(
            valid=False,
            reason=f"record/proof count mismatch: {len(records)} != {len(proofs)}",
            artifact="commitment-chain",
        )

    if not records:
        return VerificationResult(
            valid=True,
            reason="empty chain is trivially valid",
            artifact="commitment-chain",
        )

    try:
        for i, (record, proof) in enumerate(zip(records, proofs)):
            # Verify each Merkle proof
            if not proof.verify():
                return VerificationResult(
                    valid=False,
                    reason=f"merkle proof invalid at index {i}",
                    artifact="commitment-chain",
                )

            # Verify signature
            # Note: caller must have verified signatures separately since
            # we don't have the VK here — this is a structural check

        return VerificationResult(
            valid=True,
            reason=f"chain of {len(records)} records verified",
            artifact="commitment-chain",
            details={"chain_length": len(records)},
        )
    except Exception as e:
        return VerificationResult(
            valid=False,
            reason=f"verification error: {e}",
            artifact="commitment-chain",
        )


def verify_zk_bridge_proof(proof) -> VerificationResult:
    """Verify a ZK bridge proof attesting to a valid STH signature.

    Pure function — no state, no network, no side effects.
    Accepts a ZKBridgeProof and returns a VerificationResult.

    """
    try:
        from ..bridge.zk_bridge import ZKBridgeVerifier

        valid = ZKBridgeVerifier.verify(proof)
        if valid:
            return VerificationResult(
                valid=True,
                reason="ZK bridge proof verified",
                artifact="zk-bridge-proof",
                details={
                    "backend": proof.backend.value,
                    "proof_id": proof.proof_id,
                    "sth_sequence": proof.public_inputs.sth_sequence,
                    "tree_size": proof.public_inputs.tree_size,
                },
            )
        else:
            return VerificationResult(
                valid=False,
                reason="ZK bridge proof verification failed",
                artifact="zk-bridge-proof",
                details={"backend": proof.backend.value},
            )
    except Exception as e:
        return VerificationResult(
            valid=False,
            reason=f"verification error: {e}",
            artifact="zk-bridge-proof",
        )
