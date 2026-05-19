"""
RISC Zero ZK Bridge Prover — wraps the RISC Zero circuit for ML-DSA-65 verification.

Supports 2 prove modes:
  - mock:  Hash-based proof for testing (no RISC Zero toolchain needed)
  - local: RISC Zero local prover via host binary subprocess

The circuit proves the same statement as SP1: "There exists a valid ML-DSA-65
signature by operator_vk_hash on an STH with root_hash, tree_size, and sequence."
"""

from __future__ import annotations

import logging
import os

from ..primitives import canonical_hash_bytes
from .zk_bridge import (
    ZKBridgeBackend,
    ZKBridgeProof,
    ZKBridgeProver,
    ZKBridgePublicInputs,
)

logger = logging.getLogger(__name__)

__all__ = ["RiscZeroZKBridgeProver"]


class RiscZeroZKBridgeProver(ZKBridgeProver):
    """RISC Zero zkVM prover for ML-DSA-65 signature validity.

    Mock mode delegates to a real FRI-based STARK fallback (shared with SP1),
    so proofs have genuine cryptographic soundness even without the RISC Zero
    toolchain installed.
    """

    def __init__(self, prove_mode: str = "mock") -> None:
        self._prove_mode = prove_mode

    @property
    def backend(self) -> ZKBridgeBackend:
        return ZKBridgeBackend.RISC_ZERO

    @property
    def prove_mode(self) -> str:
        return self._prove_mode

    def prove_sth_signature(self, sth) -> ZKBridgeProof:
        """Generate a ZK proof that the ML-DSA-65 signature on this STH is valid."""
        if not sth.verify():
            raise ValueError("Cannot generate RISC Zero proof for invalid STH signature")

        public_inputs = ZKBridgePublicInputs.from_sth(sth)

        if self._prove_mode == "mock":
            proof_bytes = self._mock_proof(sth, public_inputs)
        elif self._prove_mode == "local":
            stdin_data = self._marshal_witnesses(sth)
            proof_bytes = self._local_proof(stdin_data)
        else:
            raise ValueError(f"Unknown prove_mode: {self._prove_mode!r}")

        proof_id = canonical_hash_bytes(proof_bytes).hex()

        return ZKBridgeProof(
            proof_bytes=proof_bytes,
            backend=ZKBridgeBackend.RISC_ZERO,
            public_inputs=public_inputs,
            proof_id=proof_id,
        )

    def _mock_proof(self, sth, public_inputs: ZKBridgePublicInputs) -> bytes:
        """Real STARK-based fallback proof when RISC Zero toolchain is not available."""
        from ._stark_fallback import stark_fallback_proof_bytes

        return stark_fallback_proof_bytes(sth)

    def _local_proof(self, stdin_data: bytes) -> bytes:
        """Generate proof using RISC Zero host binary."""
        import subprocess

        host_binary = self._host_binary_path()
        if not os.path.exists(host_binary):
            raise FileNotFoundError(
                f"RISC Zero host binary not found: {host_binary}. "
                "Build with: cd zkvm/risc0-host && cargo build --release"
            )

        result = subprocess.run(
            [host_binary],
            input=stdin_data,
            capture_output=True,
            timeout=600,
        )

        if result.stderr:
            for line in result.stderr.decode(errors="replace").strip().split("\n"):
                logger.info("R0: %s", line)

        if result.returncode != 0:
            raise RuntimeError(
                f"RISC Zero proof failed (exit {result.returncode}): "
                f"{result.stderr.decode(errors='replace')[:500]}"
            )
        return result.stdout

    def _host_binary_path(self) -> str:
        return self._zkvm_binary("risc0-host/target/release/risc0-host")
