"""
Reed-Solomon erasure coding over GF(256) for the Lattice Transfer Protocol.

Provides:
  - ErasureCoder — encode data into n shards; decode from any k-of-n

Algorithm details:
  - GF(2^8) with irreducible polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D)
  - Vandermonde evaluation with α_i = i + 1 (non-zero evaluation points)
  - Any k shards reconstruct the original (MDS property)

Whitepaper parameters (§2.1 / encoding_params):
  algorithm : "reed-solomon-gf256"
  gf_poly   : "0x11d"
  eval      : "vandermonde-powers-of-0x02"
"""

from __future__ import annotations

import struct

_zfec_available = False
try:
    import zfec as _zfec_mod

    _zfec_available = True
except ImportError:
    _zfec_mod = None

__all__ = ["ErasureCoder"]


class ErasureCoder:
    """
    Erasure coding with true any-k-of-n reconstruction over GF(256).

    Uses a Vandermonde-matrix approach over GF(256) to produce n shards from
    data split into k chunks, where ANY k of the n shards are sufficient to
    reconstruct the original data. This is the core availability guarantee.

    Performance (PoC limitation):
      Encode/decode are O(n * k * chunk_size) pure-Python loops over GF(256).
      For a 100 KB payload with n=8, k=4: ~800K GF multiplications per encode.
      This is acceptable for testing and small payloads but will bottleneck at
      scale.  Production should swap in an optimized backend (zfec, liberasurecode,
      or Intel ISA-L) behind the same encode/decode API.
    """

    _GF_EXP = [0] * 512
    _GF_LOG = [0] * 256
    _GF_INITIALIZED = False

    @classmethod
    def _init_gf(cls) -> None:
        """Initialize GF(256) lookup tables (idempotent)."""
        if cls._GF_INITIALIZED:
            return
        x = 1
        for i in range(255):
            cls._GF_EXP[i] = x
            cls._GF_LOG[x] = i
            x <<= 1
            if x & 0x100:
                x ^= 0x11D  # x^8 + x^4 + x^3 + x^2 + 1
        for i in range(255, 512):
            cls._GF_EXP[i] = cls._GF_EXP[i - 255]
        cls._GF_LOG[0] = 0
        cls._GF_INITIALIZED = True

    @classmethod
    def _gf_mul(cls, a: int, b: int) -> int:
        """Multiply two GF(256) elements."""
        if a == 0 or b == 0:
            return 0
        return cls._GF_EXP[cls._GF_LOG[a] + cls._GF_LOG[b]]

    @classmethod
    def _gf_inv(cls, a: int) -> int:
        """Multiplicative inverse in GF(256). a must be non-zero."""
        assert a != 0, "Cannot invert zero in GF(256)"
        return cls._GF_EXP[255 - cls._GF_LOG[a]]

    @staticmethod
    def _pad(data: bytes, k: int) -> bytes:
        remainder = len(data) % k
        if remainder:
            data += b"\x00" * (k - remainder)
        return data

    @classmethod
    def encode(cls, data: bytes, n: int, k: int) -> list[bytes]:
        """
        Encode data into n shards using a Vandermonde matrix over GF(256).

        Evaluation points α_i = i + 1 (all non-zero, 1 through n).
        Any k shards reconstruct the original (MDS property).

        Returns: list of n shard bytes objects.
        """
        if not (n > k > 0):
            raise ValueError("Need n > k > 0")
        if n > 256:
            raise ValueError("GF(256) supports at most 256 evaluation points")

        length_prefix = struct.pack(">Q", len(data))
        prefixed = length_prefix + data
        padded = cls._pad(prefixed, k)
        chunk_size = len(padded) // k
        data_chunks = [padded[i * chunk_size : (i + 1) * chunk_size] for i in range(k)]

        # Fast path: zfec C backend
        if _zfec_available:
            encoder = _zfec_mod.Encoder(k, n)
            return encoder.encode(data_chunks)

        # Pure Python GF(256) fallback
        cls._init_gf()

        shards = []
        for i in range(n):
            alpha = i + 1
            alpha_powers = [0] * k
            alpha_powers[0] = 1
            for j in range(1, k):
                alpha_powers[j] = cls._gf_mul(alpha_powers[j - 1], alpha)

            shard = bytearray(chunk_size)
            for byte_pos in range(chunk_size):
                val = 0
                for j in range(k):
                    val ^= cls._gf_mul(alpha_powers[j], data_chunks[j][byte_pos])
                shard[byte_pos] = val
            shards.append(bytes(shard))

        return shards

    @classmethod
    def _invert_vandermonde(cls, alphas: list[int], k: int) -> list[list[int]]:
        """
        Invert the k×k Vandermonde matrix V[i][j] = alphas[i]^j
        via Gauss-Jordan elimination over GF(256).

        Returns V^{-1} so that coefficients = V^{-1} * evaluations.
        """
        aug = []
        for i in range(k):
            row = []
            alpha_power = 1
            for j in range(k):
                row.append(alpha_power)
                alpha_power = cls._gf_mul(alpha_power, alphas[i])
            row.extend(1 if j == i else 0 for j in range(k))
            aug.append(row)

        for col in range(k):
            pivot = None
            for row in range(col, k):
                if aug[row][col] != 0:
                    pivot = row
                    break
            assert pivot is not None, "Vandermonde matrix is singular (duplicate alphas?)"

            if pivot != col:
                aug[col], aug[pivot] = aug[pivot], aug[col]

            inv_pivot = cls._gf_inv(aug[col][col])
            for j in range(2 * k):
                aug[col][j] = cls._gf_mul(aug[col][j], inv_pivot)

            for row in range(k):
                if row == col:
                    continue
                factor = aug[row][col]
                if factor == 0:
                    continue
                for j in range(2 * k):
                    aug[row][j] ^= cls._gf_mul(factor, aug[col][j])

        return [aug[i][k:] for i in range(k)]

    @classmethod
    def decode(cls, shards: dict[int, bytes], n: int, k: int) -> bytes:
        """
        Decode from ANY k-of-n shards via Vandermonde matrix inversion over GF(256).

        Input: {shard_index: shard_data} — at least k entries, any indices.
        Returns: original data bytes.
        """
        if len(shards) < k:
            raise ValueError(f"Need at least {k} shards, got {len(shards)}")

        indices = sorted(shards.keys())[:k]
        chunk_size = len(shards[indices[0]])

        # Fast path: zfec C backend
        if _zfec_available:
            decoder = _zfec_mod.Decoder(k, n)
            share_data = [shards[idx] for idx in indices]
            decoded_chunks = decoder.decode(share_data, indices)
            result = b"".join(decoded_chunks)
            original_length = struct.unpack(">Q", result[:8])[0]
            return result[8 : 8 + original_length]

        # Pure Python GF(256) fallback
        cls._init_gf()

        alphas = [i + 1 for i in indices]
        V_inv = cls._invert_vandermonde(alphas, k)

        reconstructed = bytearray(chunk_size * k)
        for byte_pos in range(chunk_size):
            y_vals = [shards[idx][byte_pos] for idx in indices]
            for m in range(k):
                val = 0
                for j in range(k):
                    val ^= cls._gf_mul(V_inv[m][j], y_vals[j])
                reconstructed[m * chunk_size + byte_pos] = val

        result = bytes(reconstructed)
        original_length = struct.unpack(">Q", result[:8])[0]
        return result[8 : 8 + original_length]
