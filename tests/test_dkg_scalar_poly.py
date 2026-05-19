"""Tests for BLS12-381 scalar field polynomial arithmetic (Spec C3b §3)."""

from __future__ import annotations

import pytest

from src.ltp.execution.committee.dkg.scalar_poly import ScalarField, ScalarPoly

R = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001


class TestScalarField:
    def test_add_basic(self):
        assert ScalarField.add(3, 5) == 8

    def test_add_wraps_mod_r(self):
        assert ScalarField.add(R - 1, 2) == 1

    def test_mul_basic(self):
        assert ScalarField.mul(3, 7) == 21

    def test_mul_wraps_mod_r(self):
        assert ScalarField.mul(R - 1, 2) == R - 2

    def test_neg(self):
        assert ScalarField.add(5, ScalarField.neg(5)) == 0

    def test_neg_zero(self):
        assert ScalarField.neg(0) == 0

    def test_inv(self):
        a = 42
        a_inv = ScalarField.inv(a)
        assert ScalarField.mul(a, a_inv) == 1

    def test_inv_one(self):
        assert ScalarField.inv(1) == 1

    def test_random_in_range(self):
        for _ in range(10):
            val = ScalarField.random()
            assert 1 <= val < R


class TestScalarPoly:
    def test_constant_poly(self):
        p = ScalarPoly([42])
        assert p.evaluate(0) == 42
        assert p.evaluate(1) == 42
        assert p.evaluate(999) == 42

    def test_linear_poly(self):
        # f(x) = 10 + 3x
        p = ScalarPoly([10, 3])
        assert p.evaluate(0) == 10
        assert p.evaluate(1) == 13
        assert p.evaluate(2) == 16

    def test_quadratic_poly(self):
        # f(x) = 1 + 2x + 3x^2
        p = ScalarPoly([1, 2, 3])
        assert p.evaluate(0) == 1
        assert p.evaluate(1) == 6
        assert p.evaluate(2) == 17

    def test_evaluate_mod_r(self):
        p = ScalarPoly([R - 1, 2])
        assert p.evaluate(1) == 1

    def test_random_has_correct_degree(self):
        p = ScalarPoly.random(3)
        assert len(p.coeffs) == 4

    def test_random_coefficients_in_range(self):
        p = ScalarPoly.random(2)
        for c in p.coeffs:
            assert 1 <= c < R

    def test_lagrange_basic_2_of_3(self):
        secret = 5
        p = ScalarPoly([secret, 7])
        participants = [1, 2, 3]
        shares = {i: p.evaluate(i) for i in participants}
        subset = [1, 2]
        reconstructed = 0
        for i in subset:
            li = ScalarPoly.lagrange_coefficient(i, subset)
            reconstructed = ScalarField.add(reconstructed, ScalarField.mul(shares[i], li))
        assert reconstructed == secret

    def test_lagrange_3_of_5(self):
        secret = 42
        p = ScalarPoly([secret, 11, 23])
        participants = [1, 2, 3, 4, 5]
        shares = {i: p.evaluate(i) for i in participants}
        subset = [2, 4, 5]
        reconstructed = 0
        for i in subset:
            li = ScalarPoly.lagrange_coefficient(i, subset)
            reconstructed = ScalarField.add(reconstructed, ScalarField.mul(shares[i], li))
        assert reconstructed == secret

    def test_lagrange_insufficient_shares_fails(self):
        secret = 100
        p = ScalarPoly([secret, 7])
        share_1 = p.evaluate(1)
        li = ScalarPoly.lagrange_coefficient(1, [1])
        result = ScalarField.mul(share_1, li)
        assert result != secret
