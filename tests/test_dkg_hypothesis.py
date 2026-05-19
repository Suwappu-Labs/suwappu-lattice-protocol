"""Hypothesis property-based tests for DKG subsystem (Spec C3b)."""

from __future__ import annotations

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from src.ltp.execution.committee.dkg.registry import DKGKeyRegistry
from src.ltp.execution.committee.dkg.scalar_poly import ScalarField, ScalarPoly
from src.ltp.execution.committee.dkg.types import DKGPhase, DKGResult

R = ScalarField.R

small_scalars = st.integers(min_value=1, max_value=R - 1)
poly_degrees = st.integers(min_value=0, max_value=5)


class TestScalarFieldProperties:
    @given(a=small_scalars, b=small_scalars)
    def test_add_commutative(self, a, b):
        assert ScalarField.add(a, b) == ScalarField.add(b, a)

    @given(a=small_scalars, b=small_scalars)
    def test_mul_commutative(self, a, b):
        assert ScalarField.mul(a, b) == ScalarField.mul(b, a)

    @given(a=small_scalars)
    def test_additive_inverse(self, a):
        assert ScalarField.add(a, ScalarField.neg(a)) == 0

    @given(a=small_scalars)
    @settings(max_examples=10)
    def test_multiplicative_inverse(self, a):
        assert ScalarField.mul(a, ScalarField.inv(a)) == 1

    @given(a=small_scalars, b=small_scalars, c=small_scalars)
    def test_distributive(self, a, b, c):
        lhs = ScalarField.mul(a, ScalarField.add(b, c))
        rhs = ScalarField.add(ScalarField.mul(a, b), ScalarField.mul(a, c))
        assert lhs == rhs


class TestScalarPolyProperties:
    @given(degree=poly_degrees)
    def test_random_poly_has_correct_length(self, degree):
        p = ScalarPoly.random(degree)
        assert len(p.coeffs) == degree + 1

    @given(degree=poly_degrees)
    def test_evaluate_at_zero_is_constant_term(self, degree):
        p = ScalarPoly.random(degree)
        assert p.evaluate(0) == p.coeffs[0]


class TestLagrangeReconstruction:
    @given(
        secret=st.integers(min_value=1, max_value=1000),
        n=st.integers(min_value=2, max_value=6),
        t=st.integers(min_value=2, max_value=6),
    )
    def test_reconstruction_with_t_shares(self, secret, n, t):
        """Any t shares from a degree-(t-1) polynomial reconstruct the secret."""
        assume(t <= n)
        coeffs = [secret] + [ScalarField.random() for _ in range(t - 1)]
        p = ScalarPoly(coeffs)
        all_indices = list(range(1, n + 1))
        shares = {i: p.evaluate(i) for i in all_indices}

        # Take the first t shares
        subset = all_indices[:t]
        reconstructed = 0
        for i in subset:
            li = ScalarPoly.lagrange_coefficient(i, subset)
            reconstructed = ScalarField.add(
                reconstructed,
                ScalarField.mul(shares[i], li),
            )
        assert reconstructed == secret


class TestDKGKeyRegistryProperties:
    @given(n=st.integers(min_value=1, max_value=20))
    def test_epoch_count_matches_stores(self, n):
        reg = DKGKeyRegistry(0x01)
        for epoch in range(1, n + 1):
            reg.store(
                DKGResult(
                    vm_tag=0x01,
                    epoch=epoch,
                    group_pk=bytes([epoch % 256]) * 48,
                    participant_vks={},
                    threshold=1,
                    qual_set=frozenset(),
                    phase=DKGPhase.EAGER,
                )
            )
        assert reg.epoch_count() == n

    @given(n=st.integers(min_value=1, max_value=20))
    def test_current_is_always_max_epoch(self, n):
        reg = DKGKeyRegistry(0x01)
        for epoch in range(1, n + 1):
            reg.store(
                DKGResult(
                    vm_tag=0x01,
                    epoch=epoch,
                    group_pk=bytes([epoch % 256]) * 48,
                    participant_vks={},
                    threshold=1,
                    qual_set=frozenset(),
                    phase=DKGPhase.EAGER,
                )
            )
        assert reg.current().epoch == n
