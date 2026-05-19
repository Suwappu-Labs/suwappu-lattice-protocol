"""
Post-quantum authenticated handshake protocol for ETP nodes.

Builds on existing SignedEnvelope + CanonicalEncoder infrastructure.
Each handshake creates a signed envelope containing node identity,
verified via ML-DSA-65 signatures with domain separation.

Wire format for serialized envelopes:
  version(1B) || domain_len(4B) || domain || vk(LP) || signer_id(LP) ||
  kid(32B) || timestamp(8B) || payload_type(LP) || payload_hash(32B) ||
  payload(LP) || sig(LP)
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass

from ..domain import DOMAIN_NODE_HANDSHAKE
from ..encoding import CanonicalEncoder
from ..envelope import SignedEnvelope
from ..keypair import KeyPair

__all__ = [
    "PROTOCOL_VERSION",
    "HandshakePayload",
    "create_handshake_envelope",
    "verify_handshake_envelope",
    "serialize_envelope",
    "deserialize_envelope",
]

PROTOCOL_VERSION = 1


@dataclass
class HandshakePayload:
    """Payload carried inside a handshake SignedEnvelope."""

    node_id: str
    listen_address: str
    region: str
    protocol_version: int
    timestamp: float

    def to_bytes(self) -> bytes:
        """Canonical encoding using DOMAIN_NODE_HANDSHAKE."""
        return (
            CanonicalEncoder(DOMAIN_NODE_HANDSHAKE)
            .string(self.node_id)
            .string(self.listen_address)
            .string(self.region)
            .uint32(self.protocol_version)
            .float64(self.timestamp)
            .finalize()
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "HandshakePayload":
        """Deserialize from canonical encoding.

        Raises:
            ValueError: If the data is truncated or malformed.
        """
        offset = len(DOMAIN_NODE_HANDSHAKE)

        node_id, offset = _read_lp_string(data, offset, "node_id")
        listen_address, offset = _read_lp_string(data, offset, "listen_address")
        region, offset = _read_lp_string(data, offset, "region")
        _check_bounds(data, offset, 4, "protocol_version")
        protocol_version = struct.unpack_from(">I", data, offset)[0]
        offset += 4
        _check_bounds(data, offset, 8, "timestamp")
        timestamp = struct.unpack_from(">d", data, offset)[0]

        return cls(
            node_id=node_id,
            listen_address=listen_address,
            region=region,
            protocol_version=protocol_version,
            timestamp=timestamp,
        )


def create_handshake_envelope(
    keypair: KeyPair,
    payload: HandshakePayload,
) -> SignedEnvelope:
    """Create a signed handshake envelope from a keypair and payload."""
    return SignedEnvelope.create(
        domain=DOMAIN_NODE_HANDSHAKE,
        signer_vk=keypair.vk,
        signer_sk=keypair,
        signer_id=keypair.label,
        payload_type="node-handshake",
        payload=payload.to_bytes(),
    )


def verify_handshake_envelope(
    envelope: SignedEnvelope,
    max_drift: float = 30.0,
) -> tuple[bool, HandshakePayload | None]:
    """Verify a handshake envelope and extract the payload.

    Args:
        envelope: The signed envelope to verify.
        max_drift: Maximum allowed clock drift in seconds.

    Returns:
        (True, payload) on success, (False, None) on failure.
    """
    if not envelope.verify(max_drift=max_drift):
        return False, None

    if envelope.domain != DOMAIN_NODE_HANDSHAKE:
        return False, None

    try:
        payload = HandshakePayload.from_bytes(envelope.payload)
    except Exception:
        return False, None

    return True, payload


# ---------------------------------------------------------------------------
# Wire-format serialization for gRPC transport
# ---------------------------------------------------------------------------


def serialize_envelope(env: SignedEnvelope) -> bytes:
    """Serialize a SignedEnvelope to deterministic wire format for gRPC."""
    parts: list[bytes] = []

    # version (1B)
    parts.append(struct.pack(">B", env.version))
    # domain (LP)
    parts.append(struct.pack(">I", len(env.domain)))
    parts.append(env.domain)
    # signer_vk (LP)
    parts.append(struct.pack(">I", len(env.signer_vk)))
    parts.append(env.signer_vk)
    # signer_id (LP string)
    signer_id_bytes = env.signer_id.encode("utf-8")
    parts.append(struct.pack(">I", len(signer_id_bytes)))
    parts.append(signer_id_bytes)
    # signer_kid (32B raw)
    parts.append(env.signer_kid)
    # timestamp (8B double)
    parts.append(struct.pack(">d", env.timestamp))
    # payload_type (LP string)
    pt_bytes = env.payload_type.encode("utf-8")
    parts.append(struct.pack(">I", len(pt_bytes)))
    parts.append(pt_bytes)
    # payload_hash (32B raw)
    parts.append(env.payload_hash)
    # payload (LP)
    parts.append(struct.pack(">I", len(env.payload)))
    parts.append(env.payload)
    # signature (LP)
    parts.append(struct.pack(">I", len(env.signature)))
    parts.append(env.signature)

    return b"".join(parts)


def deserialize_envelope(data: bytes) -> SignedEnvelope:
    """Deserialize a SignedEnvelope from wire format.

    Raises:
        ValueError: If the data is truncated or malformed.
    """
    if len(data) < 1:
        raise ValueError("envelope data is empty")

    offset = 0

    # version
    _check_bounds(data, offset, 1, "version")
    version = struct.unpack_from(">B", data, offset)[0]
    offset += 1

    # domain
    domain, offset = _read_lp_bytes(data, offset, "domain")

    # signer_vk
    signer_vk, offset = _read_lp_bytes(data, offset, "signer_vk")

    # signer_id
    signer_id_raw, offset = _read_lp_bytes(data, offset, "signer_id")
    signer_id = signer_id_raw.decode("utf-8")

    # signer_kid (32B)
    _check_bounds(data, offset, 32, "signer_kid")
    signer_kid = data[offset : offset + 32]
    offset += 32

    # timestamp
    _check_bounds(data, offset, 8, "timestamp")
    timestamp = struct.unpack_from(">d", data, offset)[0]
    offset += 8

    # payload_type
    pt_raw, offset = _read_lp_bytes(data, offset, "payload_type")
    payload_type = pt_raw.decode("utf-8")

    # payload_hash (32B)
    _check_bounds(data, offset, 32, "payload_hash")
    payload_hash = data[offset : offset + 32]
    offset += 32

    # payload
    payload, offset = _read_lp_bytes(data, offset, "payload")

    # signature
    signature, offset = _read_lp_bytes(data, offset, "signature")

    return SignedEnvelope(
        version=version,
        domain=domain,
        signer_vk=signer_vk,
        signer_id=signer_id,
        signer_kid=signer_kid,
        timestamp=timestamp,
        payload_type=payload_type,
        payload_hash=payload_hash,
        payload=payload,
        signature=signature,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _check_bounds(data: bytes, offset: int, needed: int, field: str) -> None:
    """Raise ValueError if data is too short for the next read."""
    if offset + needed > len(data):
        raise ValueError(
            f"truncated envelope: need {needed} bytes for {field} "
            f"at offset {offset}, but only {len(data) - offset} available"
        )


def _read_lp_bytes(
    data: bytes,
    offset: int,
    field: str = "field",
) -> tuple[bytes, int]:
    """Read a length-prefixed bytes field with bounds checking."""
    _check_bounds(data, offset, 4, f"{field} length prefix")
    length = struct.unpack_from(">I", data, offset)[0]
    offset += 4
    _check_bounds(data, offset, length, f"{field} data ({length}B)")
    value = data[offset : offset + length]
    offset += length
    return value, offset


def _read_lp_string(data: bytes, offset: int, field: str = "field") -> tuple[str, int]:
    """Read a length-prefixed UTF-8 string field with bounds checking."""
    raw, offset = _read_lp_bytes(data, offset, field)
    return raw.decode("utf-8"), offset
