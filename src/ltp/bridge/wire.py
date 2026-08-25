"""Canonical wire format for the untrusted relayer hop.

`Relayer.relay()` returns a `RelayPacket` and `L2Materializer.materialize()`
consumes one — but neither type could be serialized, so both ends had to live
in the same Python process. That made the relayer hop, the one link the trust
model explicitly assumes is hostile, the one link that could not actually be a
network. This module is that missing encoding.

Wire shape follows `src/ltp/corridor/wire.py`: bytes as unprefixed hex strings,
snake_case field names, one error type for every malformed input. It is
deliberately a *separate* error type and a separate module, because the two
formats make different promises — `corridor/wire.py` is the cross-repo
`LTP-corridor-v1` encoding pinned byte-for-byte against
`suwappu-dag/crates/suwappu-ltp`, while this one is a Python-side relayer
transport with no Rust counterpart. Sharing a `WireFormatError` would imply a
compatibility relationship that does not exist.

Two things this decoder is and is not responsible for:

**It is responsible for surviving a hostile sender.** The relayer is untrusted
by design, so everything arriving here is attacker-controlled: field types,
field lengths, the number of fields. Every value is type-checked before use and
every byte field has an explicit cap, so a packet claiming a 500 MB sealed key
is rejected on its length rather than after allocating it. Decoding must fail
with `BridgeWireError`, never with a `KeyError`, `TypeError`, or `MemoryError`
that a caller would not think to catch.

**It is not responsible for deciding whether a packet is legitimate.** The caps
here are generous enough to admit both the Level 3 and Level 5 PQ profiles,
because the sender's profile is not knowable from the wire and guessing wrong
would reject valid traffic. Authenticity stays where it already lives:
`SignedEnvelope.verify()` recomputes the signature over every field, and
`L2Materializer.materialize()` re-checks routing, finality, and replay. A
round-trip through this module preserves every byte those checks depend on, so
tampering anywhere in transit surfaces there — this module must never be the
thing that decides a packet is trustworthy.
"""

from __future__ import annotations

import json
from typing import Any

from ..envelope import SignedEnvelope
from .message import RelayPacket

__all__ = [
    "BridgeWireError",
    "MAX_ENVELOPE_PAYLOAD_BYTES",
    "MAX_SEALED_KEY_BYTES",
    "relay_packet_from_dict",
    "relay_packet_from_json",
    "relay_packet_to_dict",
    "relay_packet_to_json",
    "signed_envelope_from_dict",
    "signed_envelope_to_dict",
]


class BridgeWireError(ValueError):
    """Raised when a wire-format dict or JSON blob fails validation.

    Every malformed input reaches a caller as this type — never as a bare
    `KeyError` or `TypeError` from inside the decoder — so `except
    BridgeWireError` around a network read is sufficient.
    """


# Caps. Generous on purpose: they exist to bound allocation from a hostile
# sender, not to enforce a profile. A sealed LatticeKey is ~1.3 KB today
# (ML-KEM-768 ciphertext + ML-DSA-65 signature + framing); 64 KB leaves room
# for Level 5 and for framing changes without becoming a DoS surface.
MAX_SEALED_KEY_BYTES = 64 * 1024
#: An envelope payload carries a protocol object, not bulk data — the bridge
#: message itself travels as shards, never inline here.
MAX_ENVELOPE_PAYLOAD_BYTES = 256 * 1024
#: Room for ML-DSA-87 (vk 2592, sig 4627) plus margin.
_MAX_KEY_BYTES = 8 * 1024
_MAX_SIGNATURE_BYTES = 8 * 1024
_MAX_DOMAIN_BYTES = 256
_MAX_STRING_CHARS = 4096
#: A chain id or entity id is an identifier, not free text.
_MAX_IDENTIFIER_CHARS = 256
#: Block heights and nonces are non-negative and bounded well below any real
#: chain's ceiling; a u64 cap keeps them serializable everywhere downstream.
_MAX_UINT64 = 2**64 - 1


def _require_dict(value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BridgeWireError(f"{what} must be an object, got {type(value).__name__}")
    return value


def _hex_bytes(d: dict[str, Any], field: str, *, max_len: int) -> bytes:
    """Decode `d[field]` as hex, rejecting anything oversized before decoding."""
    try:
        value = d[field]
    except KeyError as e:
        raise BridgeWireError(f"missing field {field!r}") from e
    if not isinstance(value, str):
        raise BridgeWireError(f"field {field!r} must be a hex string, got {type(value).__name__}")
    # Check the *encoded* length first: bytes.fromhex on a 1 GB string would
    # allocate before we ever saw how big it was.
    if len(value) > 2 * max_len:
        raise BridgeWireError(
            f"field {field!r} is {len(value) // 2} bytes, over the {max_len}-byte cap"
        )
    try:
        return bytes.fromhex(value)
    except ValueError as e:
        raise BridgeWireError(f"field {field!r} is not valid hex: {e}") from e


def _string(d: dict[str, Any], field: str, *, max_len: int = _MAX_STRING_CHARS) -> str:
    try:
        value = d[field]
    except KeyError as e:
        raise BridgeWireError(f"missing field {field!r}") from e
    if not isinstance(value, str):
        raise BridgeWireError(f"field {field!r} must be a string, got {type(value).__name__}")
    if len(value) > max_len:
        raise BridgeWireError(f"field {field!r} is {len(value)} characters, over the {max_len} cap")
    return value


def _uint(d: dict[str, Any], field: str, *, max_value: int = _MAX_UINT64) -> int:
    try:
        value = d[field]
    except KeyError as e:
        raise BridgeWireError(f"missing field {field!r}") from e
    # bool is an int subclass; accepting it would silently turn `true` into 1.
    if isinstance(value, bool) or not isinstance(value, int):
        raise BridgeWireError(f"field {field!r} must be an integer, got {type(value).__name__}")
    if not 0 <= value <= max_value:
        raise BridgeWireError(f"field {field!r} must be in 0..{max_value}, got {value}")
    return value


def _float(d: dict[str, Any], field: str) -> float:
    try:
        value = d[field]
    except KeyError as e:
        raise BridgeWireError(f"missing field {field!r}") from e
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BridgeWireError(f"field {field!r} must be a number, got {type(value).__name__}")
    result = float(value)
    # NaN and the infinities survive JSON round-trips in Python but not in
    # strict JSON, and a NaN timestamp compares false against every freshness
    # window, which would read as "always stale" rather than as an error.
    if result != result or result in (float("inf"), float("-inf")):
        raise BridgeWireError(f"field {field!r} must be finite, got {value!r}")
    return result


# -- SignedEnvelope ---------------------------------------------------------


def signed_envelope_to_dict(e: SignedEnvelope) -> dict[str, Any]:
    """Encode every field `signable_content()` covers, plus the signature.

    Nothing is derived on the far side: `signer_kid` is a fingerprint of
    `signer_vk` and could be recomputed, but sending it means the decoder
    reconstructs exactly what was signed rather than something that merely
    ought to match. `verify()` re-checks that binding itself.
    """
    return {
        "version": e.version,
        "domain": e.domain.hex(),
        "signer_vk": e.signer_vk.hex(),
        "signer_id": e.signer_id,
        "signer_kid": e.signer_kid.hex(),
        "timestamp": e.timestamp,
        "payload_type": e.payload_type,
        "payload_hash": e.payload_hash.hex(),
        "payload": e.payload.hex(),
        "signature": e.signature.hex(),
    }


def signed_envelope_from_dict(d: dict[str, Any]) -> SignedEnvelope:
    """Rebuild a `SignedEnvelope`. Does **not** verify it — call `verify()`.

    Decoding deliberately stays separate from verification so a caller can log
    or route a packet it is about to reject; nothing downstream should treat a
    successfully decoded envelope as an authenticated one.
    """
    _require_dict(d, "envelope")
    return SignedEnvelope(
        version=_uint(d, "version", max_value=255),
        domain=_hex_bytes(d, "domain", max_len=_MAX_DOMAIN_BYTES),
        signer_vk=_hex_bytes(d, "signer_vk", max_len=_MAX_KEY_BYTES),
        signer_id=_string(d, "signer_id", max_len=_MAX_IDENTIFIER_CHARS),
        signer_kid=_hex_bytes(d, "signer_kid", max_len=_MAX_KEY_BYTES),
        timestamp=_float(d, "timestamp"),
        payload_type=_string(d, "payload_type", max_len=_MAX_IDENTIFIER_CHARS),
        payload_hash=_hex_bytes(d, "payload_hash", max_len=_MAX_KEY_BYTES),
        payload=_hex_bytes(d, "payload", max_len=MAX_ENVELOPE_PAYLOAD_BYTES),
        signature=_hex_bytes(d, "signature", max_len=_MAX_SIGNATURE_BYTES),
    )


# -- RelayPacket ------------------------------------------------------------


def relay_packet_to_dict(p: RelayPacket) -> dict[str, Any]:
    """Encode a `RelayPacket`, including its relay envelope when present."""
    out: dict[str, Any] = {
        "sealed_key": p.sealed_key.hex(),
        "source_chain": p.source_chain,
        "dest_chain": p.dest_chain,
        "nonce": p.nonce,
        "source_block": p.source_block,
        "entity_id": p.entity_id,
    }
    if p.relay_envelope is not None:
        if not isinstance(p.relay_envelope, SignedEnvelope):
            raise BridgeWireError(
                "relay_envelope must be a SignedEnvelope to be encoded, got "
                f"{type(p.relay_envelope).__name__}"
            )
        out["relay_envelope"] = signed_envelope_to_dict(p.relay_envelope)
    return out


def relay_packet_from_dict(d: dict[str, Any]) -> RelayPacket:
    """Rebuild a `RelayPacket` from its wire form.

    Structural validation only. The packet is not authenticated, not fresh, and
    not replay-checked until `L2Materializer.materialize()` says so.
    """
    _require_dict(d, "relay packet")

    envelope = None
    raw_envelope = d.get("relay_envelope")
    if raw_envelope is not None:
        envelope = signed_envelope_from_dict(_require_dict(raw_envelope, "relay_envelope"))

    return RelayPacket(
        sealed_key=_hex_bytes(d, "sealed_key", max_len=MAX_SEALED_KEY_BYTES),
        source_chain=_string(d, "source_chain", max_len=_MAX_IDENTIFIER_CHARS),
        dest_chain=_string(d, "dest_chain", max_len=_MAX_IDENTIFIER_CHARS),
        nonce=_uint(d, "nonce"),
        source_block=_uint(d, "source_block"),
        entity_id=_string(d, "entity_id", max_len=_MAX_IDENTIFIER_CHARS),
        relay_envelope=envelope,
    )


def relay_packet_to_json(p: RelayPacket) -> bytes:
    """Canonical JSON bytes — sorted keys, compact separators.

    Canonical rather than merely valid so two relayers encoding the same packet
    produce identical bytes, which makes a packet hashable for dedup and
    loggable for comparison.
    """
    return json.dumps(relay_packet_to_dict(p), sort_keys=True, separators=(",", ":")).encode()


def relay_packet_from_json(data: bytes) -> RelayPacket:
    """Decode canonical JSON bytes straight off a socket or queue."""
    if not isinstance(data, (bytes, bytearray)):
        raise BridgeWireError(f"expected bytes, got {type(data).__name__}")
    try:
        parsed = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise BridgeWireError(f"relay packet is not valid JSON: {e}") from e
    return relay_packet_from_dict(_require_dict(parsed, "relay packet"))
