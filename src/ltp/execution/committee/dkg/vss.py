"""Pedersen Verifiable Secret Sharing (Spec C3b §4)."""

from __future__ import annotations

import hashlib

from src.ltp.zk.ec_backend import (
    bls12_381_available,
    g1_add,
    g1_deserialize,
    g1_eq,
    g1_generator,
    g1_identity,
    g1_scalar_mul,
    g1_serialize,
)

from .scalar_poly import ScalarField, ScalarPoly

__all__ = ["PedersenVSS", "G_POINT", "H_POINT"]


def _derive_h_generator():
    """Derive H via hash-to-curve with DKG-specific domain separation."""
    from py_ecc.bls12_381 import (
        field_modulus,
        multiply as _g1_multiply,
    )
    from py_ecc.bls12_381 import FQ

    cofactor = 0x396C8C005555E1568C00AAAB0000AAAB
    seed = b"ETP-PEDERSEN-DKG-H"

    for attempt in range(256):
        h = hashlib.sha3_256(seed + attempt.to_bytes(2, "big")).digest()
        x = int.from_bytes(h, "big") % field_modulus
        x_fq = FQ(x)
        y_squared = x_fq ** 3 + FQ(4)
        y_candidate = y_squared ** ((field_modulus + 1) // 4)
        if y_candidate ** 2 == y_squared:
            y = y_candidate
            if int(y) % 2 != 0:
                y = FQ(field_modulus - int(y))
            point = (x_fq, y)
            h_point = _g1_multiply(point, cofactor)
            if h_point is not None:
                return h_point

    raise RuntimeError("Failed to derive DKG H generator")


if bls12_381_available():
    G_POINT = g1_generator()
    H_POINT = _derive_h_generator()
else:
    G_POINT = None
    H_POINT = None


class PedersenVSS:
    """Pedersen VSS — dual-commitment verifiable secret sharing."""

    @staticmethod
    def generate_commitments(
        secret_poly: ScalarPoly,
        blinding_poly: ScalarPoly,
    ) -> tuple[list[bytes], list[bytes]]:
        feldman = []
        pedersen = []
        for s_k, b_k in zip(secret_poly.coeffs, blinding_poly.coeffs):
            s_G = g1_scalar_mul(G_POINT, s_k)
            b_H = g1_scalar_mul(H_POINT, b_k)
            feldman.append(g1_serialize(s_G))
            pedersen.append(g1_serialize(g1_add(s_G, b_H)))
        return feldman, pedersen

    @staticmethod
    def create_share(
        secret_poly: ScalarPoly,
        blinding_poly: ScalarPoly,
        recipient_index: int,
    ) -> tuple[int, int]:
        return (
            secret_poly.evaluate(recipient_index),
            blinding_poly.evaluate(recipient_index),
        )

    @staticmethod
    def verify_share(
        recipient_index: int,
        share: int,
        blinding_share: int,
        pedersen_commitments: list[bytes],
    ) -> bool:
        lhs = g1_add(
            g1_scalar_mul(G_POINT, share),
            g1_scalar_mul(H_POINT, blinding_share),
        )

        rhs = g1_identity()
        x_power = 1
        for commitment_bytes in pedersen_commitments:
            c_point = g1_deserialize(commitment_bytes)
            term = g1_scalar_mul(c_point, x_power)
            rhs = g1_add(rhs, term) if rhs is not None else term
            x_power = ScalarField.mul(x_power, recipient_index)

        return g1_eq(lhs, rhs)
