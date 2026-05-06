"""AttestationEngine — signs multi-VM state roots with ML-DSA-65."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

from ..domain import (
    DOMAIN_MULTI_VM_ATTEST,
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

    def verify(self, vk: bytes) -> bool:
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


class AttestationEngine:
    """Signs multi-VM state roots with ML-DSA-65 for settlement anchoring."""

    def __init__(self, operator_keypair: Optional[KeyPair], chain_id: int) -> None:
        if operator_keypair is None:
            raise TypeError("operator_keypair is required — attestations must be signed")
        self._keypair = operator_keypair
        self._chain_id = chain_id
        self._vk_hash = signer_fingerprint(operator_keypair.vk)

    def sign(
        self,
        state_root: MultiVMStateRoot,
        consensus_round: int,
        epoch: int,
        active_vm_tags: list[int],
    ) -> MultiVMAttestation:
        """Create a signed attestation for a multi-VM state root."""
        payload = (
            state_root.root
            + consensus_round.to_bytes(8, "big")
            + epoch.to_bytes(8, "big")
            + bytes(active_vm_tags)
            + self._chain_id.to_bytes(8, "big")
        )
        signature = domain_sign(DOMAIN_MULTI_VM_ATTEST, self._keypair.sk, payload)

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
