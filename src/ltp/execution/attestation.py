"""AttestationEngine — signs multi-VM state roots with ML-DSA-65 and/or BLS."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

from ..domain import (
    DOMAIN_BLS_ATTEST,
    DOMAIN_MULTI_VM_ATTEST,
    bls_aggregate_sigs,
    bls_aggregate_verify,
    bls_domain_sign,
    bls_domain_verify,
    domain_hash_bytes,
    domain_sign,
    domain_verify,
    signer_fingerprint,
)
from ..keypair import KeyPair
from .state_root import MultiVMStateRoot


@dataclass(frozen=True)
class MultiVMAttestation:
    """Signed commitment to multi-VM state at a given round."""

    state_root: MultiVMStateRoot
    consensus_round: int
    epoch: int
    active_vm_tags: list[int]
    mldsa_signature: Optional[bytes]
    bls_aggregate: Optional[bytes]
    operator_vk_hash: bytes
    timestamp_ms: int
    chain_id: int

    @property
    def digest(self) -> bytes:
        """Canonical digest for signing — domain-separated."""
        payload = (
            self.state_root.root
            + self.consensus_round.to_bytes(8, "big")
            + self.epoch.to_bytes(8, "big")
            + bytes(self.active_vm_tags)
            + self.chain_id.to_bytes(8, "big")
        )
        return domain_hash_bytes(DOMAIN_MULTI_VM_ATTEST, payload)

    def verify(self, vk: bytes = None, bls_pks: list[bytes] = None) -> bool:
        """Convenience: verify whichever signatures are present.

        - vk only: checks ML-DSA
        - bls_pks only: checks BLS aggregate
        - both: checks both (both must pass)
        """
        results = []
        if vk is not None and self.mldsa_signature is not None:
            results.append(self.verify_mldsa(vk))
        if bls_pks is not None and self.bls_aggregate is not None:
            results.append(self.verify_bls(bls_pks))
        if not results:
            return False
        return all(results)

    def verify_mldsa(self, vk: bytes) -> bool:
        """Verify the ML-DSA-65 signature against a verification key."""
        if self.mldsa_signature is None:
            return False
        payload = (
            self.state_root.root
            + self.consensus_round.to_bytes(8, "big")
            + self.epoch.to_bytes(8, "big")
            + bytes(self.active_vm_tags)
            + self.chain_id.to_bytes(8, "big")
        )
        return domain_verify(DOMAIN_MULTI_VM_ATTEST, vk, payload, self.mldsa_signature)

    def verify_bls(self, bls_pks: list[bytes]) -> bool:
        """Verify BLS aggregate against committee public keys."""
        if self.bls_aggregate is None:
            return False
        return bls_aggregate_verify(DOMAIN_BLS_ATTEST, bls_pks, self.digest, self.bls_aggregate)


class AttestationEngine:
    """Signs multi-VM state roots with ML-DSA-65 and/or BLS for settlement anchoring."""

    def __init__(
        self,
        operator_keypair: Optional[KeyPair],
        chain_id: int,
        bls_identity=None,
    ) -> None:
        if operator_keypair is None:
            raise TypeError("operator_keypair is required — attestations must be signed")
        self._keypair = operator_keypair
        self._chain_id = chain_id
        self._vk_hash = signer_fingerprint(operator_keypair.vk)
        self._bls_identity = bls_identity

    def _build_payload(self, state_root, consensus_round, epoch, active_vm_tags) -> bytes:
        return (
            state_root.root
            + consensus_round.to_bytes(8, "big")
            + epoch.to_bytes(8, "big")
            + bytes(active_vm_tags)
            + self._chain_id.to_bytes(8, "big")
        )

    def sign(
        self,
        state_root: MultiVMStateRoot,
        consensus_round: int,
        epoch: int,
        active_vm_tags: list[int],
    ) -> MultiVMAttestation:
        """Create an ML-DSA-only signed attestation (backward compatible)."""
        payload = self._build_payload(state_root, consensus_round, epoch, active_vm_tags)
        signature = domain_sign(DOMAIN_MULTI_VM_ATTEST, self._keypair, payload)

        return MultiVMAttestation(
            state_root=state_root,
            consensus_round=consensus_round,
            epoch=epoch,
            active_vm_tags=active_vm_tags,
            mldsa_signature=signature,
            bls_aggregate=None,
            operator_vk_hash=self._vk_hash,
            timestamp_ms=int(time.time() * 1000),
            chain_id=self._chain_id,
        )

    def sign_bls(
        self,
        state_root: MultiVMStateRoot,
        consensus_round: int,
        epoch: int,
        active_vm_tags: list[int],
    ) -> MultiVMAttestation:
        """Create a BLS-only signed attestation."""
        if self._bls_identity is None:
            raise ValueError(
                "No BLS identity configured — use bls_identity parameter in constructor"
            )

        att_unsigned = MultiVMAttestation(
            state_root=state_root,
            consensus_round=consensus_round,
            epoch=epoch,
            active_vm_tags=active_vm_tags,
            mldsa_signature=None,
            bls_aggregate=None,
            operator_vk_hash=self._vk_hash,
            timestamp_ms=int(time.time() * 1000),
            chain_id=self._chain_id,
        )

        bls_sig = bls_domain_sign(
            DOMAIN_BLS_ATTEST,
            self._bls_identity.sk_accessor(),
            att_unsigned.digest,
        )

        return MultiVMAttestation(
            state_root=state_root,
            consensus_round=consensus_round,
            epoch=epoch,
            active_vm_tags=active_vm_tags,
            mldsa_signature=None,
            bls_aggregate=bls_sig,
            operator_vk_hash=self._vk_hash,
            timestamp_ms=att_unsigned.timestamp_ms,
            chain_id=self._chain_id,
        )

    def sign_dual(
        self,
        state_root: MultiVMStateRoot,
        consensus_round: int,
        epoch: int,
        active_vm_tags: list[int],
    ) -> MultiVMAttestation:
        """Create a dual-signed attestation (ML-DSA + BLS)."""
        if self._bls_identity is None:
            raise ValueError(
                "No BLS identity configured — use bls_identity parameter in constructor"
            )

        payload = self._build_payload(state_root, consensus_round, epoch, active_vm_tags)
        mldsa_sig = domain_sign(DOMAIN_MULTI_VM_ATTEST, self._keypair, payload)

        att_mldsa = MultiVMAttestation(
            state_root=state_root,
            consensus_round=consensus_round,
            epoch=epoch,
            active_vm_tags=active_vm_tags,
            mldsa_signature=mldsa_sig,
            bls_aggregate=None,
            operator_vk_hash=self._vk_hash,
            timestamp_ms=int(time.time() * 1000),
            chain_id=self._chain_id,
        )

        bls_sig = bls_domain_sign(
            DOMAIN_BLS_ATTEST,
            self._bls_identity.sk_accessor(),
            att_mldsa.digest,
        )

        return MultiVMAttestation(
            state_root=state_root,
            consensus_round=consensus_round,
            epoch=epoch,
            active_vm_tags=active_vm_tags,
            mldsa_signature=mldsa_sig,
            bls_aggregate=bls_sig,
            operator_vk_hash=self._vk_hash,
            timestamp_ms=att_mldsa.timestamp_ms,
            chain_id=self._chain_id,
        )


class AttestationAggregator:
    """Collects individual BLS signatures from multiple operators and produces
    a constant-size 96-byte aggregate signature (Spec C1 §5.4).

    Stateless with respect to keys — does not hold signing keys, just collects
    signatures from operators who sign independently.
    """

    def __init__(self) -> None:
        self._signatures: list[bytes] = []
        self._pks: list[bytes] = []

    def add_signature(self, operator_bls_pk: bytes, sig: bytes) -> None:
        """Accumulate an individual operator's BLS signature."""
        self._pks.append(operator_bls_pk)
        self._signatures.append(sig)

    def finalize(self) -> bytes:
        """Produce the 96-byte aggregate signature."""
        if not self._signatures:
            raise ValueError("No signatures to aggregate")
        return bls_aggregate_sigs(self._signatures)

    def signer_count(self) -> int:
        """Number of signatures collected."""
        return len(self._signatures)

    def signer_pks(self) -> list[bytes]:
        """Public keys of all signers, in order added."""
        return list(self._pks)
