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
