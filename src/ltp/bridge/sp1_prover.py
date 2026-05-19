"""
SP1 ZK Bridge Prover — wraps the compiled SP1 circuit for ML-DSA-65 verification.

Supports 3 prove modes:
  - mock:    Hash-based proof for testing (no SP1 toolchain needed)
  - local:   SP1 local prover via subprocess (slow, ~5 min)
  - network: SP1 Network API (fast, ~30s, requires API key)

The circuit proves: "There exists a valid ML-DSA-65 signature by operator_vk_hash
on an STH with root_hash, tree_size, and sequence."

Private witnesses: operator_vk (1952B), signature (3309B), signable_payload (56B)
Public inputs: sth_root_hash (32B), operator_vk_hash (32B), tree_size (8B), sth_sequence (8B)
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from ..primitives import canonical_hash_bytes
from .zk_bridge import (
    ZKBridgeBackend,
    ZKBridgeProof,
    ZKBridgeProver,
    ZKBridgePublicInputs,
)

logger = logging.getLogger(__name__)

__all__ = ["SP1ZKBridgeProver"]

# Default ELF path relative to the project's ``zkvm/`` directory.
_DEFAULT_ELF_REL_SUBPATH = (
    "sp1-mldsa-verifier/target/"
    "elf-compilation/riscv64im-succinct-zkvm-elf/release/sp1-mldsa-verifier"
)


class SP1ZKBridgeProver(ZKBridgeProver):
    """SP1 zkVM prover for ML-DSA-65 signature validity.

    Wraps the compiled SP1 circuit (Rust → RISC-V ELF) with Python
    witness marshaling and proof collection.
    """

    def __init__(
        self,
        elf_path: str = "",
        prove_mode: str = "mock",
        network_api_key: str = "",
    ) -> None:
        """
        Args:
            elf_path: Path to compiled SP1 ELF binary. Empty = auto-detect.
            prove_mode: "mock" (testing), "local" (SP1 local), "network" (SP1 Network)
            network_api_key: API key for SP1 Network prover (prove_mode="network")
        """
        self._elf_path = elf_path or self._default_elf_path()
        self._prove_mode = prove_mode
        self._network_api_key = network_api_key

    @property
    def backend(self) -> ZKBridgeBackend:
        return ZKBridgeBackend.SP1

    @property
    def prove_mode(self) -> str:
        return self._prove_mode

    @property
    def elf_path(self) -> str:
        return self._elf_path

    def prove_sth_signature(self, sth) -> ZKBridgeProof:
        """Generate a ZK proof that the ML-DSA-65 signature on this STH is valid.

        Steps:
          1. Soundness check — verify signature locally
          2. Extract public inputs from STH
          3. Marshal witnesses for SP1 stdin
          4. Generate proof (mode-dependent)
          5. Return ZKBridgeProof

        Raises ValueError if the STH signature is invalid.
        """
        # Step 1: Soundness pre-check
        if not sth.verify():
            raise ValueError("Cannot generate SP1 proof for invalid STH signature")

        # Step 2: Extract public inputs
        public_inputs = ZKBridgePublicInputs.from_sth(sth)

        # Step 3: Marshal witnesses
        stdin_data = self._marshal_witnesses(sth)

        # Step 4: Generate proof
        if self._prove_mode == "mock":
            proof_bytes = self._mock_proof(sth, public_inputs)
        elif self._prove_mode == "local":
            proof_bytes = self._local_proof(stdin_data)
        elif self._prove_mode == "network":
            proof_bytes = self._network_proof(stdin_data)
        else:
            raise ValueError(f"Unknown prove_mode: {self._prove_mode!r}")

        # Step 5: Build proof object
        proof_id = canonical_hash_bytes(proof_bytes).hex()

        return ZKBridgeProof(
            proof_bytes=proof_bytes,
            backend=ZKBridgeBackend.SP1,
            public_inputs=public_inputs,
            proof_id=proof_id,
        )

    # ------------------------------------------------------------------
    # Prove modes
    # ------------------------------------------------------------------

    def _mock_proof(self, sth, public_inputs: ZKBridgePublicInputs) -> bytes:
        """Real STARK-based fallback proof when SP1 toolchain is not available."""
        from ._stark_fallback import stark_fallback_proof_bytes

        return stark_fallback_proof_bytes(sth)

    def _local_proof(self, stdin_data: bytes) -> bytes:
        """Generate proof using SP1 host binary (local CPU prover)."""
        import subprocess

        host_binary = self._host_binary_path()
        if not os.path.exists(host_binary):
            raise FileNotFoundError(
                f"SP1 host binary not found: {host_binary}. "
                "Build with: cd zkvm/sp1-host && cargo build --release"
            )

        logger.info("SP1 local proof: invoking %s (may take several minutes)", host_binary)

        result = subprocess.run(
            [host_binary],
            input=stdin_data,
            capture_output=True,
            timeout=600,  # 10 min timeout for local proving
        )

        # Log stderr (contains progress info)
        if result.stderr:
            for line in result.stderr.decode(errors="replace").strip().split("\n"):
                logger.info("SP1: %s", line)

        if result.returncode != 0:
            raise RuntimeError(
                f"SP1 local proof failed (exit {result.returncode}): "
                f"{result.stderr.decode(errors='replace')[:500]}"
            )
        return result.stdout

    def _network_proof(self, stdin_data: bytes) -> bytes:
        """Generate proof using SP1 Network API (HTTP).

        Sends the ELF binary and witness data to Succinct's SP1 Network
        prover service, polls for completion, and returns the proof bytes.

        Requires: SP1_NETWORK_API_KEY env var or network_api_key parameter.
        """
        import base64
        import time

        import httpx

        if not self._network_api_key:
            raise ValueError(
                "SP1 Network API key required for prove_mode='network'. "
                "Set network_api_key parameter or SP1_NETWORK_API_KEY env var."
            )

        api_url = os.environ.get("SP1_NETWORK_API_URL", "https://rpc.succinct.xyz")
        if not api_url.startswith("https://"):
            raise ValueError(f"SP1 Network API requires HTTPS. Refused: {api_url[:40]}")
        headers = {"Authorization": f"Bearer {self._network_api_key}"}

        # Load ELF binary
        elf_path = self._elf_path or self._default_elf_path()
        if not os.path.exists(elf_path):
            raise FileNotFoundError(
                f"SP1 ELF binary not found at {elf_path}. "
                "Compile with: cd zkvm/sp1-mldsa-verifier && cargo prove build"
            )
        with open(elf_path, "rb") as f:
            elf_bytes = f.read()

        # Submit proof request
        with httpx.Client(timeout=600.0) as client:
            submit_resp = client.post(
                f"{api_url}/api/prove",
                json={
                    "elf": base64.b64encode(elf_bytes).decode(),
                    "stdin": base64.b64encode(stdin_data).decode(),
                    "mode": "groth16",
                },
                headers=headers,
            )
            if submit_resp.status_code != 200:
                raise RuntimeError(
                    f"SP1 Network proof submission failed: "
                    f"{submit_resp.status_code} {submit_resp.text}"
                )

            proof_id = submit_resp.json().get("proof_id")
            if not proof_id:
                raise RuntimeError("SP1 Network returned no proof_id")

            logger.info("SP1 Network proof submitted: %s", proof_id)

            # Poll for completion (max 10 min)
            deadline = time.monotonic() + 600
            while time.monotonic() < deadline:
                status_resp = client.get(
                    f"{api_url}/api/proof/{proof_id}/status",
                    headers=headers,
                )
                if status_resp.status_code != 200:
                    raise RuntimeError(f"SP1 Network status check failed: {status_resp.text}")
                status = status_resp.json().get("status", "")
                if status == "completed":
                    break
                if status == "failed":
                    raise RuntimeError(
                        f"SP1 Network proof generation failed: "
                        f"{status_resp.json().get('error', 'unknown')}"
                    )
                time.sleep(5)
            else:
                raise TimeoutError("SP1 Network proof timed out after 600s")

            # Fetch proof bytes
            proof_resp = client.get(
                f"{api_url}/api/proof/{proof_id}/proof",
                headers=headers,
            )
            if proof_resp.status_code != 200:
                raise RuntimeError(f"SP1 Network proof fetch failed: {proof_resp.text}")

            logger.info("SP1 Network proof received: %d bytes", len(proof_resp.content))
            return proof_resp.content

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _host_binary_path(self) -> str:
        """Resolve path to the sp1-host binary."""
        return self._zkvm_binary("sp1-host/target/release/sp1-host")

    @staticmethod
    def _default_elf_path() -> str:
        """Resolve default ELF path relative to this source file."""
        elf = Path(SP1ZKBridgeProver._zkvm_binary(_DEFAULT_ELF_REL_SUBPATH))
        return str(elf) if elf.exists() else str(elf)
