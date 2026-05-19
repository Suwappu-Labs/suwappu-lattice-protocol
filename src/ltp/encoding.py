"""
Canonical object encoding for the Lattice Transfer Protocol.

Provides deterministic, versioned binary encoding for every protocol object
that participates in hashing or signing. Stdlib-only implementation.

Encoding rules:
  - Integers: big-endian fixed-width (uint8/uint32/uint64)
  - Floats: IEEE 754 big-endian double (rejects NaN/Inf)
  - Strings: UTF-8 encoded, 4B big-endian length prefix
  - Bytes: 4B big-endian length prefix + raw data
  - Optionals: 1B flag (0x00 absent, 0x01 present) + value if present
  - Maps: count prefix, sorted by key (lexicographic on UTF-8), each k-v length-prefixed

Wire format is designed to be translatable to CBOR (RFC 8949) for future
cross-language interop with Rust/Go/TS siblings.

Reference: GSX_PRE_BLOCKCHAIN_ROADMAP.md §2.1
"""

from __future__ import annotations

import math
import struct

__all__ = ["CanonicalEncoder"]


class CanonicalEncoder:
    """Builder for deterministic binary encoding. Stdlib-only.

    Usage:
        encoded = (
            CanonicalEncoder(b"GSX-LTP:commit-record:v1\\x00")
            .string(record.entity_id)
            .uint64(record.sequence)
            .raw_bytes(record.root_hash)
            .finalize()
        )

    The object_tag prefixes every encoded blob, providing domain separation
    and version disambiguation at the wire level.
    """

    def __init__(self, object_tag: bytes) -> None:
        """Initialize with an object tag that prefixes every encoded blob.

        Args:
            object_tag: Domain-separated tag, e.g. b"GSX-LTP:commit-record:v1\\x00"
        """
        if not object_tag:
            raise ValueError("object_tag must not be empty")
        self._parts: list[bytes] = [object_tag]

    def uint8(self, value: int) -> "CanonicalEncoder":
        """Encode unsigned 8-bit integer (big-endian)."""
        if not (0 <= value <= 0xFF):
            raise ValueError(f"uint8 out of range: {value}")
        self._parts.append(struct.pack(">B", value))
        return self

    def uint32(self, value: int) -> "CanonicalEncoder":
        """Encode unsigned 32-bit integer (big-endian)."""
        if not (0 <= value <= 0xFFFFFFFF):
            raise ValueError(f"uint32 out of range: {value}")
        self._parts.append(struct.pack(">I", value))
        return self

    def uint64(self, value: int) -> "CanonicalEncoder":
        """Encode unsigned 64-bit integer (big-endian)."""
        if not (0 <= value <= 0xFFFFFFFFFFFFFFFF):
            raise ValueError(f"uint64 out of range: {value}")
        self._parts.append(struct.pack(">Q", value))
        return self

    def float64(self, value: float) -> "CanonicalEncoder":
        """Encode IEEE 754 big-endian double. Rejects NaN and Inf."""
        if math.isnan(value) or math.isinf(value):
            raise ValueError(f"float64 rejects NaN/Inf: {value}")
        self._parts.append(struct.pack(">d", value))
        return self

    def raw_bytes(self, value: bytes) -> "CanonicalEncoder":
        """Encode raw bytes with no length prefix."""
        self._parts.append(value)
        return self

    def length_prefixed_bytes(self, value: bytes) -> "CanonicalEncoder":
        """Encode bytes with a 4B big-endian length prefix."""
        self._parts.append(struct.pack(">I", len(value)) + value)
        return self

    def string(self, value: str) -> "CanonicalEncoder":
        """Encode a UTF-8 string with a 4B big-endian length prefix."""
        raw = value.encode("utf-8")
        self._parts.append(struct.pack(">I", len(raw)) + raw)
        return self

    def optional_bytes(self, value: bytes | None) -> "CanonicalEncoder":
        """Encode optional bytes: 0x00 flag if absent, 0x01 + LP bytes if present."""
        if value is None:
            self._parts.append(b"\x00")
        else:
            self._parts.append(b"\x01")
            self.length_prefixed_bytes(value)
        return self

    def optional_string(self, value: str | None) -> "CanonicalEncoder":
        """Encode optional string: 0x00 flag if absent, 0x01 + LP string if present."""
        if value is None:
            self._parts.append(b"\x00")
        else:
            self._parts.append(b"\x01")
            self.string(value)
        return self

    def optional_uint64(self, value: int | None) -> "CanonicalEncoder":
        """Encode optional uint64: 0x00 flag if absent, 0x01 + uint64 if present."""
        if value is None:
            self._parts.append(b"\x00")
        else:
            self._parts.append(b"\x01")
            self.uint64(value)
        return self

    def sorted_map(self, d: dict[str, str]) -> "CanonicalEncoder":
        """Encode a string→string map, sorted by key (lexicographic on UTF-8).

        Format: uint32(count) + for each sorted entry: LP(key) + LP(value)
        """
        self._parts.append(struct.pack(">I", len(d)))
        for k in sorted(d.keys()):
            self.string(k)
            self.string(str(d[k]))
        return self

    def finalize(self) -> bytes:
        """Return the complete encoded byte string."""
        return b"".join(self._parts)
