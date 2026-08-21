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

The "eval" value is a frozen historical label: encoding_params is hashed
into signed commitment records, so the string cannot change without
breaking record-hash compatibility. The evaluation points it denotes are
α_i = i + 1 (consecutive, as implemented below and specified in
whitepaper §2.1.1) — NOT powers of 0x02. Conformance is defined by
§2.1.1, not by parsing the label.
"""

from __future__ import annotations

import os
import struct

_zfec_available = False
try:
    import zfec as _zfec_mod

    _zfec_available = True
except ImportError:
    _zfec_mod = None

__all__ = ["ErasureCoder"]


def _use_zfec() -> bool:
    """Whether the zfec fast path is active.

    zfec is a *systematic* code — its first k shares are the raw data
    chunks, which whitepaper §2.1.1 explicitly rules non-conformant, and
    its shard bytes (hence shard roots) differ from the conformant
    Vandermonde path. It is therefore opt-in only: set
    LTP_ERASURE_BACKEND=zfec to accept non-conformant, environment-local
    shards in exchange for C-speed encoding. Never enable it where
    cross-implementation shard determinism matters (commitment roots).
    """
    return _zfec_available and os.environ.get("LTP_ERASURE_BACKEND") == "zfec"


class ErasureCoder:
    """
    Erasure coding with true any-k-of-n reconstruction over GF(256).

    Uses a Vandermonde-matrix approach over GF(256) to produce n shards from
    data split into k chunks, where ANY k of the n shards are sufficient to
    reconstruct the original data. This is the core availability guarantee.

    Performance:
      The bulk data path is table-driven: for each matrix coefficient c the
      GF(256) map b -> c ⊗ b is a fixed 256-entry byte substitution, so a
      whole chunk is multiplied with one C-speed bytes.translate() call and
      accumulated with one arbitrary-precision integer XOR (also C-speed).
      Total work remains O(n · |data|) field operations for encode and
      O(k · |data|) for decode, but the per-byte constant is a table lookup
      plus an XOR in C rather than interpreted Python arithmetic. The decode
      matrix is built in O(k²) via Lagrange interpolation (the classical
      Vandermonde inverse), not O(k³) Gauss-Jordan. The shard bytes are
      identical to the scalar §2.1.1 definition — the whitepaper's pinned
      test vectors and the Lean-kernel recomputation both gate this path.
    """

    _GF_EXP = [0] * 512
    _GF_LOG = [0] * 256
    _GF_INITIALIZED = False

    # Lazily built 256-byte translation tables, one per coefficient value:
    # _MUL_TABLE[c][b] = c ⊗ b. At most 255 tables of 256 bytes ever exist.
    _MUL_TABLE: dict[int, bytes] = {}

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

    @classmethod
    def _mul_table(cls, c: int) -> bytes:
        """256-byte translation table for the linear map b -> c ⊗ b.

        Multiplication by a constant is GF(2)-linear on the byte, so the
        whole map fits in one substitution table and applies to an entire
        chunk via bytes.translate() in C.
        """
        table = cls._MUL_TABLE.get(c)
        if table is None:
            cls._init_gf()
            if c == 0:
                table = bytes(256)
            else:
                exp = cls._GF_EXP
                log = cls._GF_LOG
                log_c = log[c]
                table = bytes([0] + [exp[log_c + log[b]] for b in range(1, 256)])
            cls._MUL_TABLE[c] = table
        return table

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

        Shard i is p(α_i) evaluated bytewise, where p(x) = Σ_j chunk_j · x^j.
        The inner product is factored by coefficient: each term
        α_i^j ⊗ chunk_j is one translate() pass, each accumulation one
        big-integer XOR, so the per-byte work runs in C.

        Returns: list of n shard bytes objects.
        """
        if not (n > k > 0):
            raise ValueError("Need n > k > 0")
        if n > 255:
            # Evaluation points are α_i = i + 1; GF(256) has only 255
            # distinct non-zero elements, so n = 256 has no valid point.
            raise ValueError("GF(256) supports at most 255 evaluation points")

        length_prefix = struct.pack(">Q", len(data))
        prefixed = length_prefix + data
        padded = cls._pad(prefixed, k)
        chunk_size = len(padded) // k
        data_chunks = [padded[i * chunk_size : (i + 1) * chunk_size] for i in range(k)]

        # Optional zfec C backend — opt-in only (LTP_ERASURE_BACKEND=zfec),
        # because it is systematic and non-conformant; see _use_zfec().
        if _use_zfec():
            encoder = _zfec_mod.Encoder(k, n)
            return encoder.encode(data_chunks)

        cls._init_gf()
        gf_mul = cls._gf_mul
        mul_table = cls._mul_table
        from_bytes = int.from_bytes

        # chunk_j as a big integer, reused wherever the coefficient is 1.
        chunk_ints = [from_bytes(chunk, "big") for chunk in data_chunks]

        shards = []
        for i in range(n):
            alpha = i + 1
            acc = chunk_ints[0]  # α_i^0 = 1
            coef = 1
            for j in range(1, k):
                coef = gf_mul(coef, alpha)
                if coef == 1:
                    acc ^= chunk_ints[j]
                else:
                    acc ^= from_bytes(data_chunks[j].translate(mul_table(coef)), "big")
            shards.append(acc.to_bytes(chunk_size, "big"))

        return shards

    @classmethod
    def _invert_vandermonde(cls, alphas: list[int], k: int) -> list[list[int]]:
        """
        Invert the k×k Vandermonde matrix V[i][j] = alphas[i]^j
        via Gauss-Jordan elimination over GF(256).

        Returns V^{-1} so that coefficients = V^{-1} * evaluations.

        Retained as the independent O(k³) reference; the decode path uses
        the O(k²) Lagrange construction (_lagrange_inverse), which is
        cross-checked against this method in the test suite.
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
    def _lagrange_inverse(cls, alphas: list[int], k: int) -> list[list[int]]:
        """
        Invert the k×k Vandermonde matrix V[i][j] = alphas[i]^j in O(k²)
        via Lagrange interpolation.

        Decoding Reed-Solomon *is* polynomial interpolation: the message
        chunks are the coefficients of p, and the shards are evaluations
        p(α_i). Writing p in the Lagrange basis,

            p(z) = Σ_i y_i · L_i(z),
            L_i(z) = Q_i(z) ⊗ d_i⁻¹,
            Q_i(z) = P(z) / (z ⊕ α_i),   P(z) = Π_t (z ⊕ α_t),
            d_i    = Q_i(α_i) = Π_{t≠i} (α_i ⊕ α_t),

        the m-th coefficient of p is Σ_i y_i ⊗ [z^m]Q_i ⊗ d_i⁻¹, so
        W[m][i] = [z^m]Q_i ⊗ d_i⁻¹ is exactly (V⁻¹)[m][i]. P costs O(k²)
        once; each Q_i is one O(k) synthetic division (α_i is a root of P,
        so the division is exact); each d_i one O(k) Horner evaluation.
        In characteristic 2, subtraction is XOR, so z − α is z ⊕ α.
        """
        cls._init_gf()
        gf_mul = cls._gf_mul

        # P(z) = Π (z ⊕ α_t), coefficients low-to-high, monic of degree k.
        poly = [1]
        for x in alphas:
            nxt = [0] * (len(poly) + 1)
            for j, p in enumerate(poly):
                nxt[j] ^= gf_mul(x, p)
                nxt[j + 1] ^= p
            poly = nxt

        inverse = [[0] * k for _ in range(k)]
        for i, x in enumerate(alphas):
            # Synthetic division Q_i = P / (z ⊕ x): exact because P(x) = 0.
            q = [0] * k
            q[k - 1] = poly[k]
            for j in range(k - 2, -1, -1):
                q[j] = poly[j + 1] ^ gf_mul(x, q[j + 1])
            # d_i = Q_i(x) by Horner.
            d = 0
            for j in range(k - 1, -1, -1):
                d = gf_mul(d, x) ^ q[j]
            d_inv = cls._gf_inv(d)
            for m in range(k):
                inverse[m][i] = gf_mul(q[m], d_inv)
        return inverse

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

        # Optional zfec C backend — must mirror encode()'s dispatch, since
        # zfec shards and Vandermonde shards are mutually undecodable.
        if _use_zfec():
            decoder = _zfec_mod.Decoder(k, n)
            share_data = [shards[idx] for idx in indices]
            decoded_chunks = decoder.decode(share_data, indices)
            result = b"".join(decoded_chunks)
            original_length = struct.unpack(">Q", result[:8])[0]
            return result[8 : 8 + original_length]

        cls._init_gf()
        mul_table = cls._mul_table
        from_bytes = int.from_bytes

        alphas = [i + 1 for i in indices]
        v_inv = cls._lagrange_inverse(alphas, k)

        selected = [shards[idx] for idx in indices]
        selected_ints = [from_bytes(s, "big") for s in selected]

        chunks = []
        for m in range(k):
            row = v_inv[m]
            acc = 0
            for j in range(k):
                w = row[j]
                if w == 0:
                    continue
                if w == 1:
                    acc ^= selected_ints[j]
                else:
                    acc ^= from_bytes(selected[j].translate(mul_table(w)), "big")
            chunks.append(acc.to_bytes(chunk_size, "big"))

        result = b"".join(chunks)
        original_length = struct.unpack(">Q", result[:8])[0]
        return result[8 : 8 + original_length]
