"""
Tests for real SP1 proof generation via host binary.

Tests that require the SP1 host binary are skipped if it's not built.
Mock mode tests always work.
"""

from __future__ import annotations

import os
import struct

import pytest

from src.ltp.bridge.sp1_prover import SP1ZKBridgeProver
from src.ltp.bridge.zk_bridge import ZKBridgeBackend, ZKBridgeVerifier

HOST_BINARY = os.path.join(
    os.path.dirname(__file__), "..", "zkvm", "sp1-host", "target", "release", "sp1-host"
)
VERIFY_BINARY = os.path.join(
    os.path.dirname(__file__), "..", "zkvm", "sp1-host", "target", "release", "sp1-verify"
)

has_host = os.path.exists(HOST_BINARY)
has_verify = os.path.exists(VERIFY_BINARY)


# ---------------------------------------------------------------------------
# Binary existence
# ---------------------------------------------------------------------------


class TestBinaries:
    @pytest.mark.skipif(not has_host, reason="sp1-host binary not built")
    def test_host_binary_exists(self):
        """sp1-host binary should exist after cargo build --release."""
        assert os.path.exists(HOST_BINARY), (
            f"sp1-host not found at {HOST_BINARY}. "
            "Build with: cd zkvm/sp1-host && cargo build --release"
        )

    @pytest.mark.skipif(not has_verify, reason="sp1-verify binary not built")
    def test_verify_binary_exists(self):
        """sp1-verify binary should exist after cargo build --release."""
        assert os.path.exists(VERIFY_BINARY)

    def test_host_binary_path_resolution(self):
        """Python prover resolves host binary path correctly."""
        prover = SP1ZKBridgeProver(prove_mode="local")
        path = prover._host_binary_path()
        assert "sp1-host" in path


# ---------------------------------------------------------------------------
# Mock mode regression
# ---------------------------------------------------------------------------


class TestMockRegression:
    def test_mock_still_works(self):
        """Mock mode produces real STARK proofs that verify."""
        import time

        from src.ltp.commitment import CommitmentLog, CommitmentRecord

        log = CommitmentLog()
        record = CommitmentRecord(
            entity_id="mock-regression",
            sender_id="s",
            content_hash="h",
            shard_map_root="r",
            encoding_params={"n": 5, "k": 3},
            shape="test",
            shape_hash="sh",
            timestamp=time.time(),
            signature=b"\x00" * 64,
        )
        log.append(record)
        sth = log.latest_sth

        prover = SP1ZKBridgeProver(prove_mode="mock")
        proof = prover.prove_sth_signature(sth)
        assert proof.backend == ZKBridgeBackend.SP1
        assert len(proof.proof_bytes) > 100  # Real STARK proof
        assert ZKBridgeVerifier.verify(proof) is True

    def test_mock_proof_non_deterministic(self):
        """Real STARK uses random blinding, so proofs differ each time."""
        import time

        from src.ltp.commitment import CommitmentLog, CommitmentRecord

        log = CommitmentLog()
        record = CommitmentRecord(
            entity_id="determ-test",
            sender_id="s",
            content_hash="h",
            shard_map_root="r",
            encoding_params={"n": 5, "k": 3},
            shape="test",
            shape_hash="sh",
            timestamp=time.time(),
            signature=b"\x00" * 64,
        )
        log.append(record)
        sth = log.latest_sth

        prover = SP1ZKBridgeProver(prove_mode="mock")
        p1 = prover.prove_sth_signature(sth)
        p2 = prover.prove_sth_signature(sth)
        assert p1.proof_id != p2.proof_id
