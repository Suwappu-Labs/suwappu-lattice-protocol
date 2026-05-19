"""
Bridge message types — the data structures that cross the chain gap.

Provides:
  - BridgeMessage    — a cross-chain message (lock event, state update, etc.)
  - BridgeCommitment — L1-side commitment wrapping an ETP CommitmentRecord
  - RelayPacket      — the minimal blob transported by the untrusted relayer
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class BridgeMessage:
    """
    A cross-chain message (token lock, state transition, governance action).

    Serialized to canonical JSON for EntityID computation.  The canonical
    form sorts keys and uses compact separators, ensuring deterministic
    hashing across implementations.
    """

    msg_type: str  # "token_lock", "state_update", "governance"
    source_chain: str  # "ethereum", "optimism", "arbitrum", etc.
    dest_chain: str
    sender: str  # L1 address (hex string)
    recipient: str  # L2 address (hex string)
    payload: dict  # {token, amount, ...} — type-specific data
    nonce: int  # Per-sender monotonic counter (replay protection)
    timestamp: float = field(default_factory=time.time)

    def to_canonical_bytes(self) -> bytes:
        """Deterministic JSON encoding for EntityID computation."""
        return json.dumps(
            {
                "msg_type": self.msg_type,
                "source_chain": self.source_chain,
                "dest_chain": self.dest_chain,
                "sender": self.sender,
                "recipient": self.recipient,
                "payload": self.payload,
                "nonce": self.nonce,
                "timestamp": self.timestamp,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

    @classmethod
    def from_bytes(cls, data: bytes) -> "BridgeMessage":
        """Deserialize from canonical JSON bytes."""
        d = json.loads(data)
        return cls(**d)


@dataclass
class BridgeCommitment:
    """
    The L1-side commitment: wraps an ETP entity_id + commitment_ref with
    bridge-specific metadata for the relay and L2 verification.
    """

    message: BridgeMessage
    entity_id: str
    commitment_ref: str
    merkle_proof: dict  # InclusionProof data from CommitmentLog
    source_block: int  # L1 block number (finality tracking)


@dataclass
class RelayPacket:
    """
    The minimal cross-chain blob — transported by an untrusted relayer.

    Contains:
      - sealed_key:   ML-KEM sealed LatticeKey (~1.3KB opaque ciphertext)
      - source_chain: which L1 this came from
      - dest_chain:   which L2 this targets
      - nonce:        replay protection (must match inner message nonce)
      - source_block: L1 block for finality checks

    The relayer CANNOT:
      - Read the sealed key (ML-KEM encrypted to L2 verifier)
      - Forge the commitment (ML-DSA signed by L1 operator)
      - Redirect to wrong recipient (sealed to specific L2 verifier key)
    """

    sealed_key: bytes
    source_chain: str
    dest_chain: str
    nonce: int
    source_block: int
    entity_id: str  # Public — allows L2 to pre-fetch commitment
    relay_envelope: Optional[object] = None  # SignedEnvelope from relay operator
