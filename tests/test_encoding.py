"""Tests for Canonical Object Encoding (encoding.py)."""

import math
import struct

import pytest

from src.ltp.encoding import CanonicalEncoder


class TestCanonicalEncoderPrimitives:
    """Test individual encoder methods."""

    def test_uint8(self):
        result = CanonicalEncoder(b"tag\x00").uint8(42).finalize()
        assert result == b"tag\x00" + struct.pack(">B", 42)

    def test_uint8_zero(self):
        result = CanonicalEncoder(b"tag\x00").uint8(0).finalize()
        assert result == b"tag\x00" + b"\x00"

    def test_uint8_max(self):
        result = CanonicalEncoder(b"tag\x00").uint8(255).finalize()
        assert result == b"tag\x00" + struct.pack(">B", 255)

    def test_uint8_out_of_range(self):
        with pytest.raises(ValueError):
            CanonicalEncoder(b"tag\x00").uint8(256)
        with pytest.raises(ValueError):
            CanonicalEncoder(b"tag\x00").uint8(-1)

    def test_uint32(self):
        result = CanonicalEncoder(b"tag\x00").uint32(123456).finalize()
        assert result == b"tag\x00" + struct.pack(">I", 123456)

    def test_uint32_max(self):
        result = CanonicalEncoder(b"tag\x00").uint32(0xFFFFFFFF).finalize()
        assert result == b"tag\x00" + struct.pack(">I", 0xFFFFFFFF)

    def test_uint32_out_of_range(self):
        with pytest.raises(ValueError):
            CanonicalEncoder(b"tag\x00").uint32(0x100000000)

    def test_uint64(self):
        result = CanonicalEncoder(b"tag\x00").uint64(2**48).finalize()
        assert result == b"tag\x00" + struct.pack(">Q", 2**48)

    def test_uint64_max(self):
        result = CanonicalEncoder(b"tag\x00").uint64(0xFFFFFFFFFFFFFFFF).finalize()
        assert result == b"tag\x00" + struct.pack(">Q", 0xFFFFFFFFFFFFFFFF)

    def test_uint64_out_of_range(self):
        with pytest.raises(ValueError):
            CanonicalEncoder(b"tag\x00").uint64(-1)

    def test_float64(self):
        result = CanonicalEncoder(b"tag\x00").float64(3.14).finalize()
        assert result == b"tag\x00" + struct.pack(">d", 3.14)

    def test_float64_rejects_nan(self):
        with pytest.raises(ValueError, match="NaN"):
            CanonicalEncoder(b"tag\x00").float64(float("nan"))

    def test_float64_rejects_inf(self):
        with pytest.raises(ValueError, match="Inf"):
            CanonicalEncoder(b"tag\x00").float64(float("inf"))
        with pytest.raises(ValueError, match="Inf"):
            CanonicalEncoder(b"tag\x00").float64(float("-inf"))

    def test_float64_zero(self):
        result = CanonicalEncoder(b"tag\x00").float64(0.0).finalize()
        assert result == b"tag\x00" + struct.pack(">d", 0.0)

    def test_raw_bytes(self):
        data = b"\xde\xad\xbe\xef"
        result = CanonicalEncoder(b"tag\x00").raw_bytes(data).finalize()
        assert result == b"tag\x00" + data

    def test_raw_bytes_empty(self):
        result = CanonicalEncoder(b"tag\x00").raw_bytes(b"").finalize()
        assert result == b"tag\x00"

    def test_length_prefixed_bytes(self):
        data = b"hello"
        result = CanonicalEncoder(b"tag\x00").length_prefixed_bytes(data).finalize()
        assert result == b"tag\x00" + struct.pack(">I", 5) + b"hello"

    def test_length_prefixed_bytes_empty(self):
        result = CanonicalEncoder(b"tag\x00").length_prefixed_bytes(b"").finalize()
        assert result == b"tag\x00" + struct.pack(">I", 0)

    def test_string(self):
        result = CanonicalEncoder(b"tag\x00").string("hello").finalize()
        assert result == b"tag\x00" + struct.pack(">I", 5) + b"hello"

    def test_string_utf8(self):
        s = "\u00e9"  # é
        raw = s.encode("utf-8")
        result = CanonicalEncoder(b"tag\x00").string(s).finalize()
        assert result == b"tag\x00" + struct.pack(">I", len(raw)) + raw

    def test_string_empty(self):
        result = CanonicalEncoder(b"tag\x00").string("").finalize()
        assert result == b"tag\x00" + struct.pack(">I", 0)

    def test_optional_bytes_present(self):
        result = CanonicalEncoder(b"tag\x00").optional_bytes(b"data").finalize()
        assert result == b"tag\x00" + b"\x01" + struct.pack(">I", 4) + b"data"

    def test_optional_bytes_absent(self):
        result = CanonicalEncoder(b"tag\x00").optional_bytes(None).finalize()
        assert result == b"tag\x00" + b"\x00"

    def test_optional_string_present(self):
        result = CanonicalEncoder(b"tag\x00").optional_string("hi").finalize()
        assert result == b"tag\x00" + b"\x01" + struct.pack(">I", 2) + b"hi"

    def test_optional_string_absent(self):
        result = CanonicalEncoder(b"tag\x00").optional_string(None).finalize()
        assert result == b"tag\x00" + b"\x00"

    def test_optional_uint64_present(self):
        result = CanonicalEncoder(b"tag\x00").optional_uint64(42).finalize()
        assert result == b"tag\x00" + b"\x01" + struct.pack(">Q", 42)

    def test_optional_uint64_absent(self):
        result = CanonicalEncoder(b"tag\x00").optional_uint64(None).finalize()
        assert result == b"tag\x00" + b"\x00"


class TestCanonicalEncoderMaps:
    """Test sorted_map encoding."""

    def test_sorted_map_empty(self):
        result = CanonicalEncoder(b"tag\x00").sorted_map({}).finalize()
        assert result == b"tag\x00" + struct.pack(">I", 0)

    def test_sorted_map_order(self):
        # Keys must be sorted lexicographically
        d = {"b": "2", "a": "1", "c": "3"}
        result = CanonicalEncoder(b"tag\x00").sorted_map(d).finalize()
        # Build expected
        enc = CanonicalEncoder(b"tag\x00")
        enc._parts.append(struct.pack(">I", 3))
        for k, v in [("a", "1"), ("b", "2"), ("c", "3")]:
            enc.string(k)
            enc.string(v)
        expected = enc.finalize()
        assert result == expected

    def test_sorted_map_deterministic(self):
        d1 = {"z": "26", "a": "1", "m": "13"}
        d2 = {"m": "13", "z": "26", "a": "1"}
        r1 = CanonicalEncoder(b"tag\x00").sorted_map(d1).finalize()
        r2 = CanonicalEncoder(b"tag\x00").sorted_map(d2).finalize()
        assert r1 == r2


class TestCanonicalEncoderDeterminism:
    """Test that encoding is deterministic."""

    def test_same_input_same_output(self):
        for _ in range(10):
            r = (
                CanonicalEncoder(b"SUWAPPU-LTP:test:v1\x00")
                .string("entity-123")
                .uint64(42)
                .float64(1234567890.123)
                .length_prefixed_bytes(b"\xab\xcd")
                .finalize()
            )
            assert r == (
                CanonicalEncoder(b"SUWAPPU-LTP:test:v1\x00")
                .string("entity-123")
                .uint64(42)
                .float64(1234567890.123)
                .length_prefixed_bytes(b"\xab\xcd")
                .finalize()
            )

    def test_different_tags_different_output(self):
        r1 = CanonicalEncoder(b"tag-A\x00").string("x").finalize()
        r2 = CanonicalEncoder(b"tag-B\x00").string("x").finalize()
        assert r1 != r2

    def test_empty_tag_rejected(self):
        with pytest.raises(ValueError):
            CanonicalEncoder(b"")

    def test_chaining(self):
        result = (
            CanonicalEncoder(b"t\x00")
            .uint8(1)
            .uint32(2)
            .uint64(3)
            .float64(4.0)
            .string("five")
            .finalize()
        )
        assert isinstance(result, bytes)
        assert len(result) > 0


class TestCanonicalEncoderIntegration:
    """Test with real protocol objects."""

    def test_commitment_record_canonical_bytes(self):
        from src.ltp import CommitmentRecord

        record = CommitmentRecord(
            entity_id="a" * 64,
            sender_id="alice",
            shard_map_root="b" * 64,
            content_hash="c" * 64,
            encoding_params={"n": "8", "k": "4"},
            shape="text/plain",
            shape_hash="d" * 64,
            timestamp=1234567890.123,
        )
        cb = record.canonical_bytes()
        assert isinstance(cb, bytes)
        assert len(cb) > 0
        # Determinism
        assert cb == record.canonical_bytes()

    def test_commitment_record_canonical_record_bytes(self):
        from src.ltp import CommitmentRecord

        record = CommitmentRecord(
            entity_id="a" * 64,
            sender_id="alice",
            shard_map_root="b" * 64,
            content_hash="c" * 64,
            encoding_params={"n": "8", "k": "4"},
            shape="text/plain",
            shape_hash="d" * 64,
            timestamp=1234567890.123,
            signature=b"\x00" * 100,
        )
        crb = record.canonical_record_bytes()
        assert isinstance(crb, bytes)
        assert len(crb) > len(record.canonical_bytes())

    def test_sth_canonical_bytes(self):
        from src.ltp import KeyPair

        kp = KeyPair.generate("test-op")
        from src.ltp.merkle_log.sth import SignedTreeHead

        sth = SignedTreeHead.sign(1, 5, b"\x00" * 32, kp.vk, kp.sk)
        cb = sth.canonical_bytes()
        assert isinstance(cb, bytes)
        assert cb == sth.canonical_bytes()

    def test_lattice_key_canonical_bytes(self):
        from src.ltp import LatticeKey

        lk = LatticeKey(
            entity_id="a" * 64,
            cek=b"\x01" * 32,
            commitment_ref="b" * 64,
        )
        cb = lk.canonical_bytes()
        assert isinstance(cb, bytes)
        assert cb == lk.canonical_bytes()

    def test_signable_payload_unchanged(self):
        """Verify legacy signable_payload() still works unchanged."""
        from src.ltp import CommitmentRecord

        record = CommitmentRecord(
            entity_id="a" * 64,
            sender_id="alice",
            shard_map_root="b" * 64,
            content_hash="c" * 64,
            encoding_params={"n": "8", "k": "4"},
            shape="text/plain",
            shape_hash="d" * 64,
            timestamp=1234567890.123,
        )
        sp = record.signable_payload()
        assert sp.startswith(b"LTP-COMMIT-v1\x00")
        # canonical_bytes uses new tag
        cb = record.canonical_bytes()
        assert cb.startswith(b"SUWAPPU-LTP:commit-record:v1\x00")
        assert sp != cb  # Different encoding paths
