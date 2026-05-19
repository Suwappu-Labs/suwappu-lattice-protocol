"""Tests for ZK Transfer Mode (Open Question 8, §3.2)."""

import pytest

from src.ltp.zk.ec_backend import bls12_381_available
from src.ltp.zk_transfer import (
    ContentPropertyProof,
    ZKCommitment,
    ZKConfig,
    ZKProof,
    ZKProofSystem,
    ZKTransferMode,
)

_has_py_ecc = bls12_381_available()


# ---------------------------------------------------------------------------
# ZKConfig
# ---------------------------------------------------------------------------


class TestZKConfig:
    def test_defaults(self):
        cfg = ZKConfig()
        assert cfg.enabled is False
        assert cfg.proof_system == ZKProofSystem.STARK  # Default to PQ-safe
        assert cfg.curve == "bls12_381"
        assert cfg.hiding_commitment is True

    def test_custom(self):
        cfg = ZKConfig(enabled=True, proof_system=ZKProofSystem.GROTH16)
        assert cfg.enabled is True
        assert cfg.proof_system == ZKProofSystem.GROTH16


# ---------------------------------------------------------------------------
# ZKCommitment
# ---------------------------------------------------------------------------


class TestZKCommitment:
    def test_is_hiding_with_nonzero_blinding(self):
        c = ZKCommitment(
            commitment_value="abc",
            blinding_factor=b"\x01" * 32,
            entity_id="e1",
        )
        assert c.is_hiding is True

    def test_is_hiding_zero_blinding(self):
        c = ZKCommitment(
            commitment_value="abc",
            blinding_factor=b"\x00" * 32,
            entity_id="e1",
        )
        assert c.is_hiding is False

    def test_is_hiding_empty_blinding(self):
        c = ZKCommitment(
            commitment_value="abc",
            blinding_factor=b"",
            entity_id="e1",
        )
        assert c.is_hiding is False


# ---------------------------------------------------------------------------
# ZKProof
# ---------------------------------------------------------------------------


class TestZKProof:
    def test_proof_size(self):
        p = ZKProof(
            proof_bytes=b"\x00" * 64,
            proof_system=ZKProofSystem.SIMULATED,
        )
        assert p.proof_size_bytes == 64


# ---------------------------------------------------------------------------
# ZKTransferMode — Simulated
# ---------------------------------------------------------------------------


class TestZKTransferModeSimulated:
    def setup_method(self):
        self.zk = ZKTransferMode(ZKConfig(proof_system=ZKProofSystem.SIMULATED))

    def test_create_hiding_commitment(self):
        c = self.zk.create_hiding_commitment("entity-1")
        assert c.entity_id == "entity-1"
        assert isinstance(c.commitment_value, str)
        assert len(c.commitment_value) > 0
        assert c.is_hiding

    def test_commitment_is_unique_per_call(self):
        c1 = self.zk.create_hiding_commitment("entity-1")
        c2 = self.zk.create_hiding_commitment("entity-1")
        # Different blinding factors → different commitment values
        assert c1.commitment_value != c2.commitment_value

    def test_create_and_verify_proof(self):
        c = self.zk.create_hiding_commitment("entity-1")
        proof = self.zk.create_zk_proof("entity-1", c)
        assert isinstance(proof, ZKProof)
        assert proof.proof_system == ZKProofSystem.SIMULATED
        assert self.zk.verify_zk_proof(c, proof)

    def test_proof_fails_for_wrong_entity(self):
        c = self.zk.create_hiding_commitment("entity-1")
        with pytest.raises(ValueError, match="does not match"):
            self.zk.create_zk_proof("entity-2", c)

    def test_tampered_proof_fails_verification(self):
        c = self.zk.create_hiding_commitment("entity-1")
        proof = self.zk.create_zk_proof("entity-1", c)
        bad_proof = ZKProof(
            proof_bytes=b"\xff" * len(proof.proof_bytes),
            proof_system=proof.proof_system,
        )
        assert self.zk.verify_zk_proof(c, bad_proof) is False

    def test_proof_system_mismatch_fails(self):
        c = self.zk.create_hiding_commitment("entity-1")
        proof = self.zk.create_zk_proof("entity-1", c)
        # Change the proof system
        bad = ZKProof(
            proof_bytes=proof.proof_bytes,
            proof_system=ZKProofSystem.GROTH16,
        )
        assert self.zk.verify_zk_proof(c, bad) is False

    def test_open_commitment(self):
        c = self.zk.create_hiding_commitment("entity-1")
        assert self.zk.open_commitment(c, "entity-1", c.blinding_factor)

    def test_open_commitment_wrong_entity(self):
        c = self.zk.create_hiding_commitment("entity-1")
        assert self.zk.open_commitment(c, "entity-2", c.blinding_factor) is False

    def test_open_commitment_wrong_blinding(self):
        c = self.zk.create_hiding_commitment("entity-1")
        assert self.zk.open_commitment(c, "entity-1", b"\x00" * 32) is False


# ---------------------------------------------------------------------------
# ZKTransferMode — Groth16
# ---------------------------------------------------------------------------


class TestZKTransferModeGroth16:
    def setup_method(self):
        self.zk = ZKTransferMode(ZKConfig(proof_system=ZKProofSystem.GROTH16))

    def test_create_and_verify_proof(self):
        c = self.zk.create_hiding_commitment("entity-g16")
        proof = self.zk.create_zk_proof("entity-g16", c)
        assert proof.proof_system == ZKProofSystem.GROTH16
        assert proof.proof_size_bytes > 32
        assert self.zk.verify_zk_proof(c, proof)

    def test_commitment_uses_curve(self):
        c = self.zk.create_hiding_commitment("entity-curve")
        assert len(c.commitment_value) > 0

    @pytest.mark.skipif(not _has_py_ecc, reason="py_ecc not installed")
    def test_real_ec_proof_size(self):
        """Real Sigma protocol proof is exactly 160 bytes."""
        c = self.zk.create_hiding_commitment("entity-g16-size")
        proof = self.zk.create_zk_proof("entity-g16-size", c)
        assert proof.proof_size_bytes == 160

    @pytest.mark.skipif(not _has_py_ecc, reason="py_ecc not installed")
    def test_real_ec_commitment_is_96_byte_point(self):
        """Real Pedersen commitment is a 96-byte EC point (hex-encoded)."""
        c = self.zk.create_hiding_commitment("entity-g16-point")
        assert len(bytes.fromhex(c.commitment_value)) == 96

    @pytest.mark.skipif(not _has_py_ecc, reason="py_ecc not installed")
    def test_real_ec_verify_rejects_tampered_proof(self):
        """Tampered Sigma proof bytes must fail verification."""
        c = self.zk.create_hiding_commitment("entity-g16-tamper")
        proof = self.zk.create_zk_proof("entity-g16-tamper", c)
        bad_bytes = bytearray(proof.proof_bytes)
        bad_bytes[100] ^= 0xFF
        bad_proof = ZKProof(
            proof_bytes=bytes(bad_bytes),
            proof_system=ZKProofSystem.GROTH16,
        )
        assert self.zk.verify_zk_proof(c, bad_proof) is False

    @pytest.mark.skipif(not _has_py_ecc, reason="py_ecc not installed")
    def test_real_ec_open_commitment(self):
        """Real Pedersen open_commitment works with correct inputs."""
        c = self.zk.create_hiding_commitment("entity-g16-open")
        assert self.zk.open_commitment(c, "entity-g16-open", c.blinding_factor)
        assert not self.zk.open_commitment(c, "wrong", c.blinding_factor)


# ---------------------------------------------------------------------------
# ZKTransferMode — STARK
# ---------------------------------------------------------------------------


class TestZKTransferModeSTARK:
    def setup_method(self):
        self.zk = ZKTransferMode(ZKConfig(proof_system=ZKProofSystem.STARK))

    def test_create_and_verify_proof(self):
        c = self.zk.create_hiding_commitment("entity-stark")
        proof = self.zk.create_zk_proof("entity-stark", c)
        assert proof.proof_system == ZKProofSystem.STARK
        assert self.zk.verify_zk_proof(c, proof)


# ---------------------------------------------------------------------------
# ContentPropertyProof
# ---------------------------------------------------------------------------


class TestContentPropertyProof:
    def test_is_verifiable(self):
        proof = ZKProof(proof_bytes=b"\x01" * 32, proof_system=ZKProofSystem.SIMULATED)
        cpp = ContentPropertyProof(
            property_name="age >= 18",
            property_circuit_id="age_check_v1",
            proof=proof,
            public_inputs={"threshold": 18},
        )
        assert cpp.is_verifiable is True

    def test_not_verifiable_empty_circuit_id(self):
        proof = ZKProof(proof_bytes=b"\x01" * 32, proof_system=ZKProofSystem.SIMULATED)
        cpp = ContentPropertyProof(
            property_name="age >= 18",
            property_circuit_id="",
            proof=proof,
            public_inputs={},
        )
        assert cpp.is_verifiable is False

    def test_not_verifiable_empty_proof(self):
        proof = ZKProof(proof_bytes=b"", proof_system=ZKProofSystem.SIMULATED)
        cpp = ContentPropertyProof(
            property_name="age >= 18",
            property_circuit_id="age_check_v1",
            proof=proof,
            public_inputs={},
        )
        assert cpp.is_verifiable is False


# ---------------------------------------------------------------------------
# Default config (disabled)
# ---------------------------------------------------------------------------


class TestZKTransferModeDefault:
    def test_default_config(self):
        zk = ZKTransferMode()
        assert zk.config.enabled is False
        # Still functional even when disabled (config is advisory)
        c = zk.create_hiding_commitment("test")
        assert c.is_hiding
