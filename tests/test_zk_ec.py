"""
Tests for real elliptic curve ZK proofs on BLS12-381.

All tests gated behind py_ecc availability — they are skipped in CI
environments without the [zk] extras group installed.
"""

import os

import pytest

from src.ltp.zk.ec_backend import bls12_381_available

pytestmark = pytest.mark.skipif(not bls12_381_available(), reason="py_ecc not installed")


# ---------------------------------------------------------------------------
# EC Backend
# ---------------------------------------------------------------------------


class TestECBackend:
    def test_bls12_381_available(self):
        assert bls12_381_available() is True

    def test_g1_generator_is_not_identity(self):
        from src.ltp.zk.ec_backend import g1_eq, g1_generator, g1_identity

        G = g1_generator()
        assert not g1_eq(G, g1_identity())

    def test_h_generator_is_not_g(self):
        from src.ltp.zk.ec_backend import g1_eq, g1_generator, g1_h_generator

        G = g1_generator()
        H = g1_h_generator()
        assert not g1_eq(G, H)

    def test_h_generator_is_on_curve(self):
        """H must satisfy y^2 = x^3 + 4 (BLS12-381 G1 curve equation)."""
        from src.ltp.zk.ec_backend import g1_h_generator

        H = g1_h_generator()
        x, y = H[0], H[1]
        assert y**2 == x**3 + type(x)(4)

    def test_h_generator_is_cached(self):
        from src.ltp.zk.ec_backend import g1_h_generator

        H1 = g1_h_generator()
        H2 = g1_h_generator()
        assert H1 is H2  # Same object (cached)

    def test_scalar_mul_identity(self):
        """0 * G should be identity (None in py_ecc)."""
        from src.ltp.zk.ec_backend import g1_generator, g1_scalar_mul

        result = g1_scalar_mul(g1_generator(), 0)
        assert result is None

    def test_scalar_mul_additive_homomorphism(self):
        """a*G + b*G should equal (a+b)*G."""
        from src.ltp.zk.ec_backend import (
            curve_order,
            g1_add,
            g1_eq,
            g1_generator,
            g1_scalar_mul,
        )

        G = g1_generator()
        a, b = 12345, 67890
        aG = g1_scalar_mul(G, a)
        bG = g1_scalar_mul(G, b)
        abG = g1_add(aG, bG)
        expected = g1_scalar_mul(G, (a + b) % curve_order())
        assert g1_eq(abG, expected)

    def test_scalar_from_entity_id_in_range(self):
        from src.ltp.zk.ec_backend import curve_order, scalar_from_entity_id

        s = scalar_from_entity_id("test-entity")
        assert 0 < s < curve_order()

    def test_scalar_from_entity_id_deterministic(self):
        from src.ltp.zk.ec_backend import scalar_from_entity_id

        s1 = scalar_from_entity_id("same-entity")
        s2 = scalar_from_entity_id("same-entity")
        assert s1 == s2

    def test_scalar_from_different_entities_differ(self):
        from src.ltp.zk.ec_backend import scalar_from_entity_id

        s1 = scalar_from_entity_id("entity-a")
        s2 = scalar_from_entity_id("entity-b")
        assert s1 != s2

    def test_random_scalar_in_range(self):
        from src.ltp.zk.ec_backend import curve_order, random_scalar

        for _ in range(10):
            s = random_scalar()
            assert 0 <= s < curve_order()

    def test_g1_serialize_deserialize_roundtrip(self):
        from src.ltp.zk.ec_backend import (
            g1_deserialize,
            g1_eq,
            g1_generator,
            g1_h_generator,
            g1_scalar_mul,
            g1_serialize,
        )

        for point in [g1_generator(), g1_h_generator(), g1_scalar_mul(g1_generator(), 42)]:
            data = g1_serialize(point)
            assert len(data) == 96
            restored = g1_deserialize(data)
            assert g1_eq(point, restored)

    def test_g1_serialize_identity(self):
        from src.ltp.zk.ec_backend import g1_deserialize, g1_identity, g1_serialize

        data = g1_serialize(g1_identity())
        assert data == b"\x00" * 96
        assert g1_deserialize(data) is None

    def test_g1_deserialize_rejects_invalid_length(self):
        from src.ltp.zk.ec_backend import g1_deserialize

        with pytest.raises(ValueError, match="96 bytes"):
            g1_deserialize(b"\x00" * 48)

    def test_g1_deserialize_rejects_off_curve_point(self):
        from src.ltp.zk.ec_backend import g1_deserialize

        # Random bytes are overwhelmingly unlikely to be on the curve
        bad_data = os.urandom(96)
        with pytest.raises(ValueError):
            g1_deserialize(bad_data)


# ---------------------------------------------------------------------------
# Pedersen Commitments
# ---------------------------------------------------------------------------


class TestPedersenCommitment:
    def test_commit_deterministic_given_same_inputs(self):
        from src.ltp.zk.pedersen import pedersen_commit

        blinding = b"\x42" * 32
        c1 = pedersen_commit("entity-det", blinding)
        c2 = pedersen_commit("entity-det", blinding)
        assert c1 == c2

    def test_different_entity_ids_produce_different_commitments(self):
        from src.ltp.zk.pedersen import pedersen_commit

        blinding = b"\x42" * 32
        c1 = pedersen_commit("entity-a", blinding)
        c2 = pedersen_commit("entity-b", blinding)
        assert c1 != c2

    def test_different_blinding_factors_produce_different_commitments(self):
        from src.ltp.zk.pedersen import pedersen_commit

        c1 = pedersen_commit("entity-x", b"\x01" * 32)
        c2 = pedersen_commit("entity-x", b"\x02" * 32)
        assert c1 != c2

    def test_commitment_is_96_bytes(self):
        from src.ltp.zk.pedersen import pedersen_commit

        c = pedersen_commit("entity-size", os.urandom(32))
        assert len(c) == 96

    def test_commitment_is_on_curve(self):
        """Commitment point must satisfy y^2 = x^3 + 4."""
        from src.ltp.zk.ec_backend import g1_deserialize
        from src.ltp.zk.pedersen import pedersen_commit

        c_bytes = pedersen_commit("entity-curve-check", os.urandom(32))
        point = g1_deserialize(c_bytes)
        assert point is not None
        x, y = point[0], point[1]
        assert y**2 == x**3 + type(x)(4)

    def test_open_correct(self):
        from src.ltp.zk.pedersen import pedersen_commit, pedersen_open

        blinding = os.urandom(32)
        c = pedersen_commit("entity-open", blinding)
        assert pedersen_open(c, "entity-open", blinding)

    def test_open_wrong_entity_fails(self):
        from src.ltp.zk.pedersen import pedersen_commit, pedersen_open

        blinding = os.urandom(32)
        c = pedersen_commit("entity-open", blinding)
        assert not pedersen_open(c, "wrong-entity", blinding)

    def test_open_wrong_blinding_fails(self):
        from src.ltp.zk.pedersen import pedersen_commit, pedersen_open

        c = pedersen_commit("entity-open", b"\x01" * 32)
        assert not pedersen_open(c, "entity-open", b"\x02" * 32)


# ---------------------------------------------------------------------------
# Sigma Protocol Proofs
# ---------------------------------------------------------------------------


class TestSigmaProof:
    def _make_commitment_and_proof(self, entity_id="entity-sigma"):
        from src.ltp.zk.pedersen import pedersen_commit
        from src.ltp.zk.sigma_proof import create_sigma_proof

        blinding = os.urandom(32)
        c = pedersen_commit(entity_id, blinding)
        proof = create_sigma_proof(entity_id, blinding, c)
        return c, blinding, proof

    def test_create_and_verify(self):
        from src.ltp.zk.sigma_proof import verify_sigma_proof

        c, _, proof = self._make_commitment_and_proof()
        assert verify_sigma_proof(c, proof)

    def test_proof_is_160_bytes(self):
        from src.ltp.zk.sigma_proof import SIGMA_PROOF_SIZE

        _, _, proof = self._make_commitment_and_proof()
        assert len(proof.to_bytes()) == SIGMA_PROOF_SIZE == 160

    def test_proof_components_correct_sizes(self):
        _, _, proof = self._make_commitment_and_proof()
        assert len(proof.t_point) == 96
        assert len(proof.s_m) == 32
        assert len(proof.s_r) == 32

    def test_tampered_t_point_fails(self):
        from src.ltp.zk.sigma_proof import SigmaProof, verify_sigma_proof

        c, _, proof = self._make_commitment_and_proof()
        # Forge a different T point (use a valid point to avoid deserialization error)
        from src.ltp.zk.ec_backend import g1_generator, g1_scalar_mul, g1_serialize

        fake_T = g1_serialize(g1_scalar_mul(g1_generator(), 999))
        bad_proof = SigmaProof(t_point=fake_T, s_m=proof.s_m, s_r=proof.s_r)
        assert not verify_sigma_proof(c, bad_proof)

    def test_tampered_s_m_fails(self):
        from src.ltp.zk.sigma_proof import SigmaProof, verify_sigma_proof

        c, _, proof = self._make_commitment_and_proof()
        bad_sm = ((int.from_bytes(proof.s_m, "big") + 1) % (2**256)).to_bytes(32, "big")
        bad_proof = SigmaProof(t_point=proof.t_point, s_m=bad_sm, s_r=proof.s_r)
        assert not verify_sigma_proof(c, bad_proof)

    def test_tampered_s_r_fails(self):
        from src.ltp.zk.sigma_proof import SigmaProof, verify_sigma_proof

        c, _, proof = self._make_commitment_and_proof()
        bad_sr = ((int.from_bytes(proof.s_r, "big") + 1) % (2**256)).to_bytes(32, "big")
        bad_proof = SigmaProof(t_point=proof.t_point, s_m=proof.s_m, s_r=bad_sr)
        assert not verify_sigma_proof(c, bad_proof)

    def test_wrong_commitment_fails(self):
        from src.ltp.zk.pedersen import pedersen_commit
        from src.ltp.zk.sigma_proof import verify_sigma_proof

        c, _, proof = self._make_commitment_and_proof("entity-original")
        c_other = pedersen_commit("entity-other", os.urandom(32))
        assert not verify_sigma_proof(c_other, proof)

    def test_proof_serialization_roundtrip(self):
        from src.ltp.zk.sigma_proof import SigmaProof, verify_sigma_proof

        c, _, proof = self._make_commitment_and_proof()
        data = proof.to_bytes()
        restored = SigmaProof.from_bytes(data)
        assert restored.t_point == proof.t_point
        assert restored.s_m == proof.s_m
        assert restored.s_r == proof.s_r
        assert verify_sigma_proof(c, restored)

    def test_from_bytes_rejects_wrong_size(self):
        from src.ltp.zk.sigma_proof import SigmaProof

        with pytest.raises(ValueError, match="160 bytes"):
            SigmaProof.from_bytes(b"\x00" * 100)

    def test_verifier_uses_no_private_data(self):
        """
        The verify function takes ONLY commitment_bytes and proof.
        It does not accept entity_id or blinding_factor — this is the
        core zero-knowledge property.
        """
        import inspect

        from src.ltp.zk.sigma_proof import verify_sigma_proof

        sig = inspect.signature(verify_sigma_proof)
        params = list(sig.parameters.keys())
        assert params == ["commitment_bytes", "proof"]

    def test_multiple_proofs_for_same_commitment_all_valid(self):
        """Different random nonces produce different but all-valid proofs."""
        from src.ltp.zk.pedersen import pedersen_commit
        from src.ltp.zk.sigma_proof import create_sigma_proof, verify_sigma_proof

        blinding = os.urandom(32)
        c = pedersen_commit("entity-multi", blinding)

        proofs = [create_sigma_proof("entity-multi", blinding, c) for _ in range(3)]
        # All different (random nonces)
        proof_bytes = [p.to_bytes() for p in proofs]
        assert len(set(proof_bytes)) == 3
        # All valid
        for p in proofs:
            assert verify_sigma_proof(c, p)
