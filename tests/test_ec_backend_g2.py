"""Tests for BLS12-381 G2 operations and G1/G2 compression (Spec C3c §3)."""

from __future__ import annotations

import pytest

from src.ltp.zk.ec_backend import bls12_381_available

pytestmark = pytest.mark.skipif(not bls12_381_available(), reason="py_ecc not installed")

from src.ltp.zk.ec_backend import (  # noqa: E402
    g1_compress,
    g1_generator,
    g1_scalar_mul,
    g1_serialize,
    g2_add,
    g2_compress,
    g2_generator,
    g2_identity,
    g2_scalar_mul,
)


class TestG2Generator:
    def test_returns_non_identity(self):
        g2 = g2_generator()
        assert g2 is not None
        assert g2 != g2_identity()

    def test_is_three_tuple(self):
        """py_ecc optimized G2 uses projective coordinates (3-tuple)."""
        g2 = g2_generator()
        assert len(g2) == 3


class TestG2ScalarMul:
    def test_mul_by_one_returns_generator(self):
        g2 = g2_generator()
        result = g2_scalar_mul(g2, 1)
        assert g2_compress(result) == g2_compress(g2)

    def test_mul_by_zero_returns_identity(self):
        g2 = g2_generator()
        result = g2_scalar_mul(g2, 0)
        assert g2_compress(result) == g2_compress(g2_identity())

    def test_mul_produces_different_points(self):
        g2 = g2_generator()
        p2 = g2_scalar_mul(g2, 2)
        p3 = g2_scalar_mul(g2, 3)
        assert g2_compress(p2) != g2_compress(p3)


class TestG2Add:
    def test_commutative(self):
        g2 = g2_generator()
        p2 = g2_scalar_mul(g2, 2)
        p3 = g2_scalar_mul(g2, 3)
        assert g2_compress(g2_add(p2, p3)) == g2_compress(g2_add(p3, p2))

    def test_add_matches_scalar_mul(self):
        """2G + 3G == 5G."""
        g2 = g2_generator()
        p2 = g2_scalar_mul(g2, 2)
        p3 = g2_scalar_mul(g2, 3)
        p5 = g2_scalar_mul(g2, 5)
        assert g2_compress(g2_add(p2, p3)) == g2_compress(p5)

    def test_add_identity(self):
        g2 = g2_generator()
        result = g2_add(g2, g2_identity())
        assert g2_compress(result) == g2_compress(g2)


class TestG2Compress:
    def test_produces_96_bytes(self):
        g2 = g2_generator()
        compressed = g2_compress(g2)
        assert len(compressed) == 96

    def test_identity_produces_96_bytes(self):
        compressed = g2_compress(g2_identity())
        assert len(compressed) == 96

    def test_different_points_different_bytes(self):
        g2 = g2_generator()
        p2 = g2_scalar_mul(g2, 2)
        assert g2_compress(g2) != g2_compress(p2)


class TestG1Compress:
    def test_produces_48_bytes(self):
        g1 = g1_generator()
        compressed = g1_compress(g1)
        assert len(compressed) == 48

    def test_roundtrip_with_bls_verify(self):
        """Compressed G1 is compatible with BLS.verify() pk format."""
        from src.ltp.bls import BLS

        # Generate a real BLS keypair
        pk, sk = BLS.keygen()
        assert len(pk) == 48  # BLS.keygen returns compressed G1

        # Our g1_compress should produce the same format
        g1 = g1_generator()
        compressed = g1_compress(g1)
        assert len(compressed) == 48

    def test_compress_uncompressed_roundtrip(self):
        """g1_compress(point) where point came from g1_scalar_mul works."""
        g1 = g1_generator()
        point = g1_scalar_mul(g1, 42)
        serialized = g1_serialize(point)
        assert len(serialized) == 96  # uncompressed
        compressed = g1_compress(point)
        assert len(compressed) == 48  # compressed
