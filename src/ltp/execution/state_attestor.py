"""StateAttestor — dual-mode attestation of state roots (Spec D1c §4)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from .execution_config import ExecutionConfig

if TYPE_CHECKING:
    from .attestation import AttestationEngine, MultiVMAttestation
    from .types import BatchResult

from .committee.dkg.threshold_signing import DOMAIN_STATE_ROOT

__all__ = ["AttestationResult", "StateAttestor"]


@dataclass(frozen=True)
class AttestationResult:
    """Result of attesting a batch's state root."""

    state_root: Optional[bytes]
    round: int
    epoch: int
    mldsa_attestation: Optional[MultiVMAttestation] = None
    bls_signature: Optional[bytes] = None
    mode: str = "none"


class StateAttestor:
    """Dual-mode attestation using AttestationEngine and CommitteeManager."""

    def __init__(
        self,
        attestation_engine: Optional[AttestationEngine],
        committee_manager: object | None,
        config: ExecutionConfig,
    ) -> None:
        self._engine = attestation_engine
        self._cm = committee_manager
        self._config = config

    def attest(self, batch_result: BatchResult, epoch: int) -> AttestationResult:
        """Sign the state root using best available mode."""
        if batch_result.state_root is None:
            return AttestationResult(
                state_root=None,
                round=batch_result.round,
                epoch=epoch,
                mode="none",
            )

        state_root = batch_result.state_root
        root_bytes = state_root.root
        active_tags = sorted(state_root.vm_roots.keys())

        mldsa_att = None
        bls_sig = None

        # ML-DSA attestation
        if self._engine is not None:
            mldsa_att = self._engine.sign(state_root, batch_result.round, epoch, active_tags)

        # BLS threshold attestation
        if self._cm is not None and hasattr(self._cm, "has_dkg_result"):
            if self._cm.has_dkg_result(epoch):
                sig = self._cm.sign_as_committee(root_bytes, DOMAIN_STATE_ROOT)
                if sig is not None:
                    bls_sig = sig

        # Determine mode
        if mldsa_att is not None and bls_sig is not None:
            mode = "dual"
        elif mldsa_att is not None:
            mode = "mldsa_only"
        else:
            mode = "none"

        return AttestationResult(
            state_root=root_bytes,
            round=batch_result.round,
            epoch=epoch,
            mldsa_attestation=mldsa_att,
            bls_signature=bls_sig,
            mode=mode,
        )

    def attestation_mode(self) -> str:
        """Current mode based on key availability."""
        has_mldsa = self._engine is not None
        has_bls = self._cm is not None and hasattr(self._cm, "has_dkg_result")
        if has_mldsa and has_bls:
            return "dual"
        elif has_mldsa:
            return "mldsa_only"
        return "none"
