"""Tests for Pedersen VSS (Spec C3b §4)."""

from __future__ import annotations

import pytest

from src.ltp.zk.ec_backend import bls12_381_available
from src.ltp.execution.committee.dkg.scalar_poly import ScalarField, ScalarPoly

pytestmark = pytest.mark.skipif(
    not bls12_381_available(), reason="py_ecc not installed"
)


from src.ltp.execution.committee.dkg.vss import PedersenVSS  # noqa: E402


R = ScalarField.R


class TestGenerators:

    def test_g_and_h_are_distinct(self):
        from src.ltp.execution.committee.dkg.vss import G_POINT, H_POINT
        assert G_POINT != H_POINT

    def test_h_is_not_identity(self):
        from src.ltp.execution.committee.dkg.vss import H_POINT
        assert H_POINT is not None


class TestGenerateCommitments:

    def test_returns_correct_count(self):
        secret_poly = ScalarPoly([10, 20])
        blinding_poly = ScalarPoly([30, 40])
        feldman, pedersen = PedersenVSS.generate_commitments(secret_poly, blinding_poly)
        assert len(feldman) == 2
        assert len(pedersen) == 2

    def test_commitments_are_96_bytes(self):
        secret_poly = ScalarPoly([10, 20])
        blinding_poly = ScalarPoly([30, 40])
        feldman, pedersen = PedersenVSS.generate_commitments(secret_poly, blinding_poly)
        for c in feldman + pedersen:
            assert len(c) == 96

    def test_feldman_and_pedersen_differ(self):
        secret_poly = ScalarPoly([10, 20])
        blinding_poly = ScalarPoly([5, 15])
        feldman, pedersen = PedersenVSS.generate_commitments(secret_poly, blinding_poly)
        assert feldman[0] != pedersen[0]


class TestCreateShare:

    def test_share_matches_poly_evaluation(self):
        secret_poly = ScalarPoly([10, 20, 30])
        blinding_poly = ScalarPoly([5, 15, 25])
        share, blinding = PedersenVSS.create_share(secret_poly, blinding_poly, 1)
        assert share == secret_poly.evaluate(1)
        assert blinding == blinding_poly.evaluate(1)

    def test_different_recipients_get_different_shares(self):
        secret_poly = ScalarPoly([10, 20])
        blinding_poly = ScalarPoly([5, 15])
        s1, b1 = PedersenVSS.create_share(secret_poly, blinding_poly, 1)
        s2, b2 = PedersenVSS.create_share(secret_poly, blinding_poly, 2)
        assert s1 != s2
        assert b1 != b2


class TestVerifyShare:

    def test_valid_share_verifies(self):
        secret_poly = ScalarPoly([10, 20])
        blinding_poly = ScalarPoly([5, 15])
        _, pedersen = PedersenVSS.generate_commitments(secret_poly, blinding_poly)
        share, blinding = PedersenVSS.create_share(secret_poly, blinding_poly, 1)
        assert PedersenVSS.verify_share(1, share, blinding, pedersen) is True

    def test_tampered_share_fails(self):
        secret_poly = ScalarPoly([10, 20])
        blinding_poly = ScalarPoly([5, 15])
        _, pedersen = PedersenVSS.generate_commitments(secret_poly, blinding_poly)
        share, blinding = PedersenVSS.create_share(secret_poly, blinding_poly, 1)
        assert PedersenVSS.verify_share(1, share + 1, blinding, pedersen) is False

    def test_tampered_blinding_fails(self):
        secret_poly = ScalarPoly([10, 20])
        blinding_poly = ScalarPoly([5, 15])
        _, pedersen = PedersenVSS.generate_commitments(secret_poly, blinding_poly)
        share, blinding = PedersenVSS.create_share(secret_poly, blinding_poly, 1)
        assert PedersenVSS.verify_share(1, share, blinding + 1, pedersen) is False

    def test_wrong_index_fails(self):
        secret_poly = ScalarPoly([10, 20])
        blinding_poly = ScalarPoly([5, 15])
        _, pedersen = PedersenVSS.generate_commitments(secret_poly, blinding_poly)
        share, blinding = PedersenVSS.create_share(secret_poly, blinding_poly, 1)
        assert PedersenVSS.verify_share(2, share, blinding, pedersen) is False

    def test_multiple_recipients_all_verify(self):
        secret_poly = ScalarPoly.random(2)
        blinding_poly = ScalarPoly.random(2)
        _, pedersen = PedersenVSS.generate_commitments(secret_poly, blinding_poly)
        for i in range(1, 6):
            share, blinding = PedersenVSS.create_share(secret_poly, blinding_poly, i)
            assert PedersenVSS.verify_share(i, share, blinding, pedersen) is True
