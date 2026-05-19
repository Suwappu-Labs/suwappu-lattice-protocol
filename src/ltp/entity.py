"""
Entity representation and canonicalization for the Lattice Transfer Protocol.

Provides:
  - canonicalize_shape() — normalize media type per whitepaper §1.1.1
  - Entity               — content + shape + deterministic EntityID
"""

from __future__ import annotations

import re as _re
import struct
from dataclasses import dataclass, field

from .primitives import canonical_hash

__all__ = ["canonicalize_shape", "Entity"]


# Shape validation regex: type/subtype with optional parameters.
# Accepts IANA media types (text/plain), parameterized types (text/plain; charset=utf-8),
# and LTP extension types (x-ltp/state-snapshot).
_SHAPE_PATTERN = _re.compile(
    r"^[a-zA-Z0-9][a-zA-Z0-9!#$&\-^_.+]*"  # type
    r"/[a-zA-Z0-9][a-zA-Z0-9!#$&\-^_.+]*"  # /subtype
    r"(?:\s*;\s*[a-zA-Z0-9\-]+\s*=\s*[^\s;]+)*$"  # optional params
)


def canonicalize_shape(shape: str) -> str:
    """
    Canonicalize a shape string per LTP Whitepaper §1.1.1.

    Rules:
      1. type/subtype components are lowercased (RFC 6838 §4.2)
      2. Parameters are sorted lexicographically by name
      3. Whitespace around ; and = delimiters is stripped
      4. Result is a deterministic UTF-8-safe string

    Raises ValueError if shape does not match the required format.

    Examples:
      "TEXT/PLAIN"                      → "text/plain"
      "text/plain; charset=utf-8"       → "text/plain;charset=utf-8"
      "application/json; schema=v1; charset=utf-8"
        → "application/json;charset=utf-8;schema=v1"
    """
    if not shape or not isinstance(shape, str):
        raise ValueError(f"Shape must be a non-empty string, got: {shape!r}")

    parts = shape.split(";")
    media_type = parts[0].strip().lower()

    if "/" not in media_type:
        raise ValueError(
            f"Invalid shape '{shape}': must be a media type (type/subtype). "
            f"See LTP Whitepaper §1.1.1."
        )

    params = []
    for param in parts[1:]:
        param = param.strip()
        if not param:
            continue
        if "=" not in param:
            raise ValueError(f"Invalid shape parameter (missing '='): '{param}'")
        name, value = param.split("=", 1)
        params.append((name.strip().lower(), value.strip()))

    params.sort(key=lambda p: p[0])

    canonical = media_type
    if params:
        canonical += ";" + ";".join(f"{n}={v}" for n, v in params)

    if not _SHAPE_PATTERN.match(canonical):
        raise ValueError(
            f"Invalid shape '{shape}' (canonical: '{canonical}'): "
            f"does not match media type format. See LTP Whitepaper §1.1.1."
        )

    return canonical


@dataclass
class Entity:
    """
    An entity to be transferred via LTP.

    Shape must be a valid media type per LTP Whitepaper §1.1.1:
      - IANA media type: "text/plain", "application/json", "image/png"
      - Parameterized: "text/plain; charset=utf-8"
      - LTP extension: "x-ltp/state-snapshot"

    Shape is automatically canonicalized (lowercased, params sorted,
    whitespace stripped) to ensure interoperability: two implementations
    that use different casing produce identical EntityIDs.
    """

    content: bytes
    shape: str
    metadata: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Canonicalize shape on construction."""
        self.shape = canonicalize_shape(self.shape)

    def compute_id(self, sender_vk: bytes, timestamp: float) -> str:
        """Compute deterministic EntityID = H(content || shape || timestamp || sender_vk).

        sender_vk is the sender's ML-DSA-65 verification key (1952 bytes), binding
        the entity's identity to the sender's cryptographic public identity rather
        than a mutable label string. Matches whitepaper §1.2 specification.
        """
        identity_input = (
            self.content + self.shape.encode() + struct.pack(">d", timestamp) + sender_vk
        )
        return canonical_hash(identity_input)
