"""
Unit tests for ErasureCoder (Reed-Solomon over GF(256)).
"""

import os

import pytest

from src.ltp.erasure import ErasureCoder


class TestErasureCoder:
    def test_encode_returns_n_shards(self):
        shards = ErasureCoder.encode(b"hello world", n=6, k=3)
        assert len(shards) == 6

    def test_encode_shards_same_length(self):
        shards = ErasureCoder.encode(b"data", n=8, k=4)
        lengths = {len(s) for s in shards}
        assert len(lengths) == 1

    def test_decode_from_first_k_shards(self):
        data = b"reconstruct me"
        n, k = 8, 4
        shards = ErasureCoder.encode(data, n, k)
        recovered = ErasureCoder.decode({i: shards[i] for i in range(k)}, n, k)
        assert recovered == data

    def test_decode_from_last_k_shards(self):
        data = b"any k shards work"
        n, k = 8, 4
        shards = ErasureCoder.encode(data, n, k)
        recovered = ErasureCoder.decode({i: shards[i] for i in range(n - k, n)}, n, k)
        assert recovered == data

    def test_decode_from_non_sequential_shards(self):
        data = b"non-sequential recovery"
        n, k = 8, 4
        shards = ErasureCoder.encode(data, n, k)
        recovered = ErasureCoder.decode(
            {1: shards[1], 3: shards[3], 5: shards[5], 7: shards[7]}, n, k
        )
        assert recovered == data

    def test_decode_with_missing_first_shards(self):
        data = b"missing first k-1 shards"
        n, k = 8, 4
        shards = ErasureCoder.encode(data, n, k)
        # Destroy shards 0, 1, 2 — recover from 3, 4, 5, 6
        surviving = {i: shards[i] for i in range(3, 7)}
        recovered = ErasureCoder.decode(surviving, n, k)
        assert recovered == data

    def test_decode_below_k_shards_raises(self):
        data = b"not enough shards"
        n, k = 8, 4
        shards = ErasureCoder.encode(data, n, k)
        with pytest.raises(ValueError):
            ErasureCoder.decode({i: shards[i] for i in range(k - 1)}, n, k)

    def test_encode_decode_empty_bytes(self):
        data = b""
        shards = ErasureCoder.encode(data, n=4, k=2)
        recovered = ErasureCoder.decode({i: shards[i] for i in range(2)}, 4, 2)
        assert recovered == data

    def test_encode_decode_large_payload(self):
        data = os.urandom(50_000)
        n, k = 8, 4
        shards = ErasureCoder.encode(data, n, k)
        # Recover from non-sequential shards
        recovered = ErasureCoder.decode(
            {2: shards[2], 4: shards[4], 6: shards[6], 7: shards[7]}, n, k
        )
        assert recovered == data

    def test_all_k_subsets_reconstruct(self):
        """Every combination of k shards must reconstruct correctly."""
        from itertools import combinations

        data = b"MDS property verification"
        n, k = 5, 3
        shards = ErasureCoder.encode(data, n, k)
        for indices in combinations(range(n), k):
            recovered = ErasureCoder.decode({i: shards[i] for i in indices}, n, k)
            assert recovered == data, f"Failed for indices {indices}"

    def test_different_data_different_shards(self):
        shards_a = ErasureCoder.encode(b"message A", n=4, k=2)
        shards_b = ErasureCoder.encode(b"message B", n=4, k=2)
        assert shards_a != shards_b


class TestFastPathEquivalence:
    """The table-driven fast path must be byte-identical to the scalar
    §2.1.1 definition, and the O(k²) Lagrange decode matrix must equal the
    O(k³) Gauss-Jordan reference."""

    def test_lagrange_inverse_matches_gauss_jordan(self):
        """_lagrange_inverse and _invert_vandermonde agree on random and
        adversarial index sets."""
        import random

        rng = random.Random(2026)
        ErasureCoder._init_gf()
        cases = [[1], [1, 2], [1, 255], [3, 7, 11, 251], list(range(1, 33))]
        for _ in range(20):
            k = rng.randint(2, 48)
            cases.append(rng.sample(range(1, 256), k))
        for alphas in cases:
            k = len(alphas)
            assert ErasureCoder._lagrange_inverse(alphas, k) == (
                ErasureCoder._invert_vandermonde(alphas, k)
            ), f"inverse mismatch for alphas={alphas}"

    def test_lagrange_inverse_times_vandermonde_is_identity(self):
        """V · V⁻¹ = I over GF(256) for the Lagrange construction."""
        ErasureCoder._init_gf()
        alphas = [2, 5, 9, 17, 33, 65, 129, 254]
        k = len(alphas)
        w = ErasureCoder._lagrange_inverse(alphas, k)
        for i in range(k):
            vrow, power = [], 1
            for _ in range(k):
                vrow.append(power)
                power = ErasureCoder._gf_mul(power, alphas[i])
            for c in range(k):
                acc = 0
                for j in range(k):
                    acc ^= ErasureCoder._gf_mul(vrow[j], w[j][c])
                assert acc == (1 if i == c else 0)

    def test_translate_path_matches_scalar_definition(self):
        """Encode via the translate/big-int path equals a from-scratch
        scalar evaluation of the §2.1.1 polynomial, byte for byte."""
        import random
        import struct

        rng = random.Random(7)
        ErasureCoder._init_gf()
        for n, k, size in [(6, 3, 100), (8, 4, 257), (17, 5, 64), (255, 2, 9)]:
            data = rng.randbytes(size)
            fast = ErasureCoder.encode(data, n, k)

            prefixed = struct.pack(">Q", len(data)) + data
            padded = ErasureCoder._pad(prefixed, k)
            chunk_size = len(padded) // k
            chunks = [padded[i * chunk_size : (i + 1) * chunk_size] for i in range(k)]
            for i in range(n):
                alpha = i + 1
                powers = [1]
                for _ in range(1, k):
                    powers.append(ErasureCoder._gf_mul(powers[-1], alpha))
                scalar = bytes(
                    [
                        __import__("functools").reduce(
                            lambda acc, j: acc ^ ErasureCoder._gf_mul(powers[j], chunks[j][b]),
                            range(k),
                            0,
                        )
                        for b in range(chunk_size)
                    ]
                )
                assert fast[i] == scalar, f"shard {i} mismatch at n={n} k={k}"

    def test_mul_table_matches_gf_mul(self):
        """Every translation table entry equals the scalar product."""
        ErasureCoder._init_gf()
        for c in [0, 1, 2, 3, 0x1D, 127, 128, 254, 255]:
            table = ErasureCoder._mul_table(c)
            for b in range(256):
                assert table[b] == ErasureCoder._gf_mul(c, b), f"c={c} b={b}"
