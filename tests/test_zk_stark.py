"""Tests for real FRI-based STARK proofs — field, Merkle, FRI, and STARK integration."""

import os

import pytest

from src.ltp.zk import field as F
from src.ltp.zk.fri import FRIParams, fri_commit_and_prove, fri_verify
from src.ltp.zk.merkle import MerkleProof, StarkMerkleTree
from src.ltp.zk.stark_proof import DEFAULT_STARK_QUERIES, stark_prove, stark_verify

# ---------------------------------------------------------------------------
# Goldilocks Field
# ---------------------------------------------------------------------------


class TestGoldilocksField:
    def test_add_wrap(self):
        assert F.add(F.P - 1, 2) == 1

    def test_mul_inv(self):
        assert F.mul(3, F.inv(3)) == 1

    def test_sub_underflow(self):
        assert F.sub(0, 1) == F.P - 1

    def test_exp(self):
        assert F.exp(2, 10) == 1024

    def test_inv_zero_raises(self):
        with pytest.raises(ZeroDivisionError):
            F.inv(0)

    def test_root_of_unity_order(self):
        omega = F.root_of_unity(16)
        assert F.exp(omega, 16) == 1
        assert F.exp(omega, 8) != 1

    def test_root_of_unity_rejects_non_power_of_2(self):
        with pytest.raises(ValueError):
            F.root_of_unity(7)

    def test_ntt_roundtrip(self):
        coeffs = [1, 2, 3, 4, 5, 6, 7, 8]
        omega = F.root_of_unity(8)
        vals = F.ntt(coeffs, omega)
        assert F.intt(vals, omega) == coeffs

    def test_ntt_matches_horner(self):
        coeffs = [10, 20, 30, 40]
        omega = F.root_of_unity(4)
        vals = F.ntt(coeffs, omega)
        for i, v in enumerate(vals):
            assert v == F.poly_eval(coeffs, F.exp(omega, i))

    def test_bytes_roundtrip(self):
        for data in [b"hello", os.urandom(64), b"a" * 100, b"x"]:
            elems = F.bytes_to_field_elements(data)
            recovered = F.field_elements_to_bytes(elems, len(data))
            assert recovered == data


# ---------------------------------------------------------------------------
# STARK Merkle Tree
# ---------------------------------------------------------------------------


class TestStarkMerkle:
    def test_build_and_verify(self):
        leaves = [os.urandom(32) for _ in range(8)]
        tree = StarkMerkleTree(leaves)
        root = tree.root()
        for i in range(8):
            assert StarkMerkleTree.verify(root, tree.open(i), 8)

    def test_tampered_leaf_fails(self):
        leaves = [os.urandom(32) for _ in range(4)]
        tree = StarkMerkleTree(leaves)
        proof = tree.open(0)
        bad = MerkleProof(index=0, leaf_data=os.urandom(32), siblings=proof.siblings)
        assert not StarkMerkleTree.verify(tree.root(), bad, 4)

    def test_wrong_root_fails(self):
        leaves = [os.urandom(32) for _ in range(4)]
        tree = StarkMerkleTree(leaves)
        assert not StarkMerkleTree.verify(os.urandom(32), tree.open(0), 4)

    def test_pads_to_power_of_2(self):
        leaves = [os.urandom(32) for _ in range(5)]
        tree = StarkMerkleTree(leaves)
        # 5 leaves padded to 8
        for i in range(8):
            assert StarkMerkleTree.verify(tree.root(), tree.open(i), 8)


# ---------------------------------------------------------------------------
# FRI Protocol
# ---------------------------------------------------------------------------


class TestFRI:
    def test_honest_proof_verifies(self):
        coeffs = [F.mul(i + 1, 1000) for i in range(16)]
        params = FRIParams(blowup_factor=4, num_queries=8)
        proof = fri_commit_and_prove(coeffs, params)
        assert fri_verify(proof, params)

    def test_tampered_query_fails(self):
        coeffs = [F.mul(i + 1, 1000) for i in range(16)]
        params = FRIParams(blowup_factor=4, num_queries=8)
        proof = fri_commit_and_prove(coeffs, params)

        # Tamper with a query response leaf
        from src.ltp.zk.fri import FRILayerProof, FRIProof

        bad_proofs = list(proof.query_proofs)
        bad_layer = list(bad_proofs[0])
        orig = bad_layer[0]
        bad_layer[0] = FRILayerProof(
            merkle_proof=MerkleProof(
                index=orig.merkle_proof.index,
                leaf_data=os.urandom(8),
                siblings=orig.merkle_proof.siblings,
            ),
            sibling_proof=orig.sibling_proof,
        )
        bad_proofs[0] = tuple(bad_layer)
        tampered = FRIProof(
            layer_roots=proof.layer_roots,
            layer_sizes=proof.layer_sizes,
            final_poly=proof.final_poly,
            query_proofs=tuple(bad_proofs),
            challenges=proof.challenges,
        )
        assert not fri_verify(tampered, params)

    def test_multiple_folding_rounds(self):
        """Larger polynomial should have multiple FRI layers."""
        coeffs = list(range(1, 65))  # degree 63
        params = FRIParams(blowup_factor=4, num_queries=8)
        proof = fri_commit_and_prove(coeffs, params)
        assert len(proof.layer_roots) >= 3  # At least 3 layers
        assert fri_verify(proof, params)


# ---------------------------------------------------------------------------
# STARK Proof Integration
# ---------------------------------------------------------------------------


class TestSTARKProof:
    def test_prove_and_verify(self):
        params = FRIParams(blowup_factor=4, num_queries=DEFAULT_STARK_QUERIES)
        proof = stark_prove("entity-test", os.urandom(32), "sha3-256:abc", params)
        assert stark_verify("sha3-256:abc", proof, params)

    def test_proof_has_real_fri(self):
        params = FRIParams(blowup_factor=4, num_queries=DEFAULT_STARK_QUERIES)
        proof = stark_prove("entity-fri", os.urandom(32), "commitment", params)
        assert len(proof.fri_proof.layer_roots) >= 1
        assert len(proof.fri_proof.query_proofs) == DEFAULT_STARK_QUERIES

    def test_proof_size_is_substantial(self):
        """Real STARK proof should be >> 32 bytes (the old simulation)."""
        params = FRIParams(blowup_factor=4, num_queries=DEFAULT_STARK_QUERIES)
        proof = stark_prove("entity-size", os.urandom(32), "commitment", params)
        assert len(proof.to_bytes()) > 1000

    def test_version_check(self):
        from src.ltp.zk.stark_proof import STARK_VERSION

        params = FRIParams(blowup_factor=4, num_queries=DEFAULT_STARK_QUERIES)
        proof = stark_prove("entity-ver", os.urandom(32), "commitment", params)
        assert proof.version == STARK_VERSION

    def test_binding_hashes_present(self):
        params = FRIParams(blowup_factor=4, num_queries=DEFAULT_STARK_QUERIES)
        proof = stark_prove("entity-bind", os.urandom(32), "commitment", params)
        assert len(proof.blinding_commitment) == 32
        assert len(proof.witness_hash) == 32


class TestSTARKTransferIntegration:
    """Test STARK through the ZKTransferMode API."""

    def test_stark_create_and_verify(self):
        from src.ltp.zk_transfer import ZKConfig, ZKProofSystem, ZKTransferMode

        zk = ZKTransferMode(ZKConfig(proof_system=ZKProofSystem.STARK))
        c = zk.create_hiding_commitment("entity-stark-int")
        proof = zk.create_zk_proof("entity-stark-int", c)
        assert proof.proof_system == ZKProofSystem.STARK
        assert proof.proof_size_bytes > 1000  # Real STARK, not 32B hash
        assert zk.verify_zk_proof(c, proof)

    def test_stark_open_commitment(self):
        from src.ltp.zk_transfer import ZKConfig, ZKProofSystem, ZKTransferMode

        zk = ZKTransferMode(ZKConfig(proof_system=ZKProofSystem.STARK))
        c = zk.create_hiding_commitment("entity-stark-open")
        assert zk.open_commitment(c, "entity-stark-open", c.blinding_factor)
        assert not zk.open_commitment(c, "wrong", c.blinding_factor)

    def test_stark_tampered_proof_fails(self):
        from src.ltp.zk_transfer import ZKConfig, ZKProof, ZKProofSystem, ZKTransferMode

        zk = ZKTransferMode(ZKConfig(proof_system=ZKProofSystem.STARK))
        c = zk.create_hiding_commitment("entity-stark-tamp")
        bad = ZKProof(proof_bytes=b"\xff" * 100, proof_system=ZKProofSystem.STARK)
        assert not zk.verify_zk_proof(c, bad)
