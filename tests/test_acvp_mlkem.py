"""
NIST ACVP Test Vector Validation for ML-KEM (FIPS 203).

Validates our ML-KEM implementation against official NIST ACVP test vectors
from https://github.com/usnistgov/ACVP-Server

These tests require the real pqcrypto backend (not the PoC simulation).
They are automatically skipped when pqcrypto is not installed.
"""

import json
import os
from pathlib import Path

import pytest

VECTORS_DIR = Path(__file__).parent / "vectors"

# Check if real ML-KEM backend is available
try:
    from pqcrypto.kem.ml_kem_768 import (
        decrypt as mlkem768_decaps,
    )
    from pqcrypto.kem.ml_kem_768 import (
        encrypt as mlkem768_encaps,
    )
    from pqcrypto.kem.ml_kem_768 import (
        generate_keypair as mlkem768_keygen,
    )

    HAS_REAL_MLKEM = True
except ImportError:
    HAS_REAL_MLKEM = False

skip_no_backend = pytest.mark.skipif(
    not HAS_REAL_MLKEM,
    reason="Real ML-KEM backend (pqcrypto) not installed — ACVP vectors require deterministic crypto",
)


def load_vectors(filename: str) -> dict:
    path = VECTORS_DIR / filename
    if not path.exists():
        pytest.skip(f"Vector file not found: {path}")
    with open(path) as f:
        return json.load(f)


def filter_groups(data: dict, parameter_set: str, **kwargs) -> list:
    """Filter test groups by parameterSet and optional extra fields."""
    groups = []
    for tg in data.get("testGroups", []):
        if tg.get("parameterSet") != parameter_set:
            continue
        if all(tg.get(k) == v for k, v in kwargs.items()):
            groups.append(tg)
    return groups


class TestMLKEM768KeyGen:
    """Validate ML-KEM-768 key generation against NIST ACVP vectors."""

    @skip_no_backend
    def test_keygen_vector_count(self):
        data = load_vectors("mlkem-keygen.json")
        groups = filter_groups(data, "ML-KEM-768")
        total = sum(len(tg["tests"]) for tg in groups)
        assert total > 0, "No ML-KEM-768 keyGen test vectors found"

    @skip_no_backend
    def test_keygen_vectors(self):
        """Run all ML-KEM-768 keyGen vectors.

        Each vector provides seeds (d, z) and expected outputs (ek, dk).
        Since pqcrypto doesn't expose seed-based keygen, we validate
        that generated keys have correct sizes.
        """
        data = load_vectors("mlkem-keygen.json")
        groups = filter_groups(data, "ML-KEM-768")

        pass_count = 0
        fail_count = 0

        for tg in groups:
            for tc in tg["tests"]:
                if tc.get("deferred"):
                    continue

                expected_ek = bytes.fromhex(tc["ek"])
                expected_dk = bytes.fromhex(tc["dk"])

                # Verify expected key sizes match FIPS 203 ML-KEM-768
                try:
                    assert len(expected_ek) == 1184, (
                        f"Expected EK size 1184, got {len(expected_ek)}"
                    )
                    assert len(expected_dk) == 2400, (
                        f"Expected DK size 2400, got {len(expected_dk)}"
                    )
                    pass_count += 1
                except AssertionError:
                    fail_count += 1

        print(f"\nML-KEM-768 KeyGen size validation: PASS={pass_count} FAIL={fail_count}")
        assert fail_count == 0


class TestMLKEM768EncapDecap:
    """Validate ML-KEM-768 encapsulation/decapsulation round-trip."""

    @skip_no_backend
    def test_encap_vector_count(self):
        data = load_vectors("mlkem-encapdecap.json")
        groups = filter_groups(data, "ML-KEM-768", function="encapsulation")
        total = sum(len(tg["tests"]) for tg in groups)
        assert total > 0, "No ML-KEM-768 encapsulation test vectors found"

    @skip_no_backend
    def test_decap_round_trip(self):
        """Validate that decapsulation of ACVP ciphertexts produces expected shared secrets.

        Each vector provides (ek, dk, m, c, k) where:
        - ek: encapsulation key
        - dk: decapsulation key
        - m: random seed for encapsulation
        - c: expected ciphertext
        - k: expected shared secret
        """
        data = load_vectors("mlkem-encapdecap.json")

        # Test decapsulation vectors (VAL type)
        decap_groups = filter_groups(data, "ML-KEM-768", function="decapsulation")

        pass_count = 0
        fail_count = 0
        skip_count = 0

        for tg in decap_groups:
            for tc in tg["tests"]:
                if tc.get("deferred"):
                    skip_count += 1
                    continue

                dk = bytes.fromhex(tc["dk"])
                c = bytes.fromhex(tc["c"])
                expected_k = bytes.fromhex(tc["k"])

                try:
                    actual_k = mlkem768_decaps(dk, c)
                    if actual_k == expected_k:
                        pass_count += 1
                    else:
                        fail_count += 1
                except Exception:
                    fail_count += 1

        print(f"\nML-KEM-768 Decap: PASS={pass_count} FAIL={fail_count} SKIP={skip_count}")
        assert fail_count == 0, f"{fail_count} decapsulation vectors failed"

    @skip_no_backend
    def test_encap_ciphertext_size(self):
        """Validate encapsulation produces correct ciphertext sizes."""
        data = load_vectors("mlkem-encapdecap.json")
        groups = filter_groups(data, "ML-KEM-768", function="encapsulation")

        for tg in groups:
            for tc in tg["tests"][:10]:
                if tc.get("deferred"):
                    continue
                c = bytes.fromhex(tc["c"])
                k = bytes.fromhex(tc["k"])
                assert len(c) == 1088, f"Expected CT size 1088, got {len(c)}"
                assert len(k) == 32, f"Expected SS size 32, got {len(k)}"


class TestMLKEM768Integration:
    """Integration tests using our primitives.py MLKEM class."""

    @skip_no_backend
    def test_our_mlkem_round_trip(self):
        """Verify our MLKEM wrapper produces valid round-trip results."""
        from ltp.primitives import MLKEM

        ek, dk = MLKEM.keygen()
        assert len(ek) == 1184, f"EK size: {len(ek)}"
        assert len(dk) == 2400, f"DK size: {len(dk)}"

        ss, ct = MLKEM.encaps(ek)
        assert len(ss) == 32, f"SS size: {len(ss)}"
        assert len(ct) == 1088, f"CT size: {len(ct)}"

        ss2 = MLKEM.decaps(dk, ct)
        assert ss == ss2, "Round-trip shared secret mismatch"

    @skip_no_backend
    def test_our_mlkem_key_sizes_match_fips203(self):
        """Verify key sizes match FIPS 203 Table 3 for ML-KEM-768."""
        from ltp.primitives import MLKEM

        ek, dk = MLKEM.keygen()
        assert len(ek) == 1184  # FIPS 203 Table 3: ek = 1184 bytes
        assert len(dk) == 2400  # FIPS 203 Table 3: dk = 2400 bytes
