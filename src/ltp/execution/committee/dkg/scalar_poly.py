"""BLS12-381 scalar field polynomial arithmetic (Spec C3b §3)."""

from __future__ import annotations

import secrets

__all__ = ["ScalarField", "ScalarPoly"]


class ScalarField:
    """Arithmetic over BLS12-381 scalar field Z_r."""

    R = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001

    @staticmethod
    def add(a: int, b: int) -> int:
        return (a + b) % ScalarField.R

    @staticmethod
    def mul(a: int, b: int) -> int:
        return (a * b) % ScalarField.R

    @staticmethod
    def inv(a: int) -> int:
        return pow(a, ScalarField.R - 2, ScalarField.R)

    @staticmethod
    def neg(a: int) -> int:
        return (-a) % ScalarField.R

    @staticmethod
    def random() -> int:
        return secrets.randbelow(ScalarField.R - 1) + 1


class ScalarPoly:
    """Polynomial over BLS12-381 scalar field Z_r.

    coeffs[0] is the constant term (the secret in Shamir's scheme).
    """

    def __init__(self, coeffs: list[int]) -> None:
        self.coeffs = coeffs

    @staticmethod
    def random(degree: int) -> ScalarPoly:
        return ScalarPoly([ScalarField.random() for _ in range(degree + 1)])

    def evaluate(self, x: int) -> int:
        result = 0
        for coeff in reversed(self.coeffs):
            result = ScalarField.add(ScalarField.mul(result, x), coeff)
        return result

    @staticmethod
    def lagrange_coefficient(i: int, participants: list[int]) -> int:
        R = ScalarField.R
        numerator = 1
        denominator = 1
        for j in participants:
            if j == i:
                continue
            numerator = ScalarField.mul(numerator, ScalarField.neg(j))
            denominator = ScalarField.mul(denominator, (i - j) % R)
        return ScalarField.mul(numerator, ScalarField.inv(denominator))
