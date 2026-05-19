"""
TransferBundle — cross-node transfer payload.

Bundles a sealed lattice key with its associated CommitmentRecord for
transport between nodes. The receiver uses the record to verify the
commitment reference and ML-DSA-65 signature without needing access
to the sender's commitment log.
"""

from __future__ import annotations

import json
import math
import struct
from dataclasses import dataclass

from ..commitment import CommitmentRecord

__all__ = ["TransferBundle"]

_MAGIC = b"ETPB"
_VERSION = 1
_MAX_SEALED_KEY_SIZE = 65536  # ML-KEM ciphertext is 1088 bytes; generous upper bound
_REQUIRED_RECORD_KEYS = (
    "entity_id",
    "sender_id",
    "shard_map_root",
    "content_hash",
    "encoding_params",
    "shape",
    "shape_hash",
    "timestamp",
    "signature",
    "sender_vk",
)


@dataclass
class TransferBundle:
    """Cross-node transfer payload: sealed lattice key + commitment record."""

    sealed_key: bytes
    record: CommitmentRecord

    def to_bytes(self) -> bytes:
        """Deterministic serialization.

        Format: magic(4) || version(4) || len(sealed_key)(4) || sealed_key || record_json
        Timestamp encoded as hex-packed IEEE 754 double for exact precision.
        """
        rec = self.record
        rec_dict = {
            "entity_id": rec.entity_id,
            "sender_id": rec.sender_id,
            "shard_map_root": rec.shard_map_root,
            "content_hash": rec.content_hash,
            "encoding_params": rec.encoding_params,
            "shape": rec.shape,
            "shape_hash": rec.shape_hash,
            "timestamp": struct.pack(">d", rec.timestamp).hex(),
            "ttl_epochs": rec.ttl_epochs,
            "predecessor": rec.predecessor,
            "signature": rec.signature.hex(),
            "sender_vk": rec.sender_vk.hex(),
        }
        rec_json = json.dumps(rec_dict, sort_keys=True, separators=(",", ":")).encode()

        return (
            _MAGIC
            + struct.pack(">I", _VERSION)
            + struct.pack(">I", len(self.sealed_key))
            + self.sealed_key
            + rec_json
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "TransferBundle":
        """Deserialize with bounds checking."""
        if len(data) < 12:
            raise ValueError("TransferBundle: truncated data (need >= 12 bytes)")
        if data[:4] != _MAGIC:
            raise ValueError("TransferBundle: invalid magic bytes")

        version = struct.unpack(">I", data[4:8])[0]
        if version != _VERSION:
            raise ValueError(f"TransferBundle: unsupported version {version}")

        sk_len = struct.unpack(">I", data[8:12])[0]
        if sk_len > _MAX_SEALED_KEY_SIZE:
            raise ValueError(
                f"TransferBundle: sealed_key too large ({sk_len} > {_MAX_SEALED_KEY_SIZE})"
            )
        if len(data) < 12 + sk_len + 1:
            raise ValueError("TransferBundle: truncated sealed_key")

        sealed_key = data[12 : 12 + sk_len]
        rec_json = data[12 + sk_len :]
        if not rec_json:
            raise ValueError("TransferBundle: missing record data")

        try:
            d = json.loads(rec_json)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ValueError(f"TransferBundle: invalid record JSON: {e}") from e

        missing = [k for k in _REQUIRED_RECORD_KEYS if k not in d]
        if missing:
            raise ValueError(f"TransferBundle: missing record fields: {missing}")

        try:
            ts = struct.unpack(">d", bytes.fromhex(d["timestamp"]))[0]
        except (ValueError, struct.error) as e:
            raise ValueError(f"TransferBundle: invalid timestamp encoding: {e}") from e
        if math.isnan(ts) or math.isinf(ts):
            raise ValueError(f"TransferBundle: invalid timestamp value: {ts}")

        record = CommitmentRecord(
            entity_id=d["entity_id"],
            sender_id=d["sender_id"],
            shard_map_root=d["shard_map_root"],
            content_hash=d["content_hash"],
            encoding_params=d["encoding_params"],
            shape=d["shape"],
            shape_hash=d["shape_hash"],
            timestamp=ts,
            ttl_epochs=d.get("ttl_epochs"),
            predecessor=d.get("predecessor"),
            signature=bytes.fromhex(d["signature"]),
            sender_vk=bytes.fromhex(d.get("sender_vk", "")),
        )
        return cls(sealed_key=sealed_key, record=record)
