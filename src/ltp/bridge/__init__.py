"""
ETP Bridge — L1↔L2 cross-chain transfer via the Lattice Transfer Protocol.

Maps ETP's three-phase protocol to blockchain bridging:

  COMMIT      → Lock tokens on L1, erasure-code + encrypt the lock event
  LATTICE     → Seal a minimal key (~1.3KB) to the L2 verifier
  MATERIALIZE → Unseal, verify commitment + signature, reconstruct, mint on L2

Security properties:
  - PQ-secure relay (ML-KEM-768 sealed key, untrusted transport)
  - Forward secrecy per bridge message (fresh encapsulation each time)
  - Append-only audit trail (CT-style Merkle log + ML-DSA STH)
  - Data availability (erasure-coded shards, k-of-n reconstruction)
  - Replay protection (per-sender monotonic nonces)
"""

from .anchor import L1Anchor
from .materializer import L2Materializer
from .message import BridgeCommitment, BridgeMessage, RelayPacket
from .relayer import Relayer
from .wire import (
    MAX_ENVELOPE_PAYLOAD_BYTES,
    MAX_SEALED_KEY_BYTES,
    BridgeWireError,
    relay_packet_from_dict,
    relay_packet_from_json,
    relay_packet_to_dict,
    relay_packet_to_json,
    signed_envelope_from_dict,
    signed_envelope_to_dict,
)

__all__ = [
    "BridgeMessage",
    "BridgeCommitment",
    "RelayPacket",
    "L1Anchor",
    "Relayer",
    "L2Materializer",
    # wire — the untrusted relayer hop
    "BridgeWireError",
    "relay_packet_to_dict",
    "relay_packet_from_dict",
    "relay_packet_to_json",
    "relay_packet_from_json",
    "signed_envelope_to_dict",
    "signed_envelope_from_dict",
    "MAX_SEALED_KEY_BYTES",
    "MAX_ENVELOPE_PAYLOAD_BYTES",
]

# LiveBridge requires web3 — import lazily to avoid hard dependency
# Optimistic bridge types are always available (no external deps)
from .challenge import ChallengeManager, ChallengeRecord, ChallengeStatus
from .fraud_proof import (
    FraudProofType,
    InconsistentSTHFraudProof,
    InvalidMerkleProofFraudProof,
    InvalidSignatureFraudProof,
)
from .watcher import STHStore, WatcherService, WatcherTickResult

__all__ += [
    "FraudProofType",
    "InvalidSignatureFraudProof",
    "InconsistentSTHFraudProof",
    "InvalidMerkleProofFraudProof",
    "ChallengeManager",
    "ChallengeStatus",
    "ChallengeRecord",
    "WatcherService",
    "STHStore",
    "WatcherTickResult",
]

# ZK bridge types
from .zk_bridge import (
    SimulatedZKBridgeProver,
    STARKBridgeProver,
    ZKBridgeBackend,
    ZKBridgeProof,
    ZKBridgeProver,
    ZKBridgePublicInputs,
    ZKBridgeVerifier,
)

__all__ += [
    "ZKBridgeBackend",
    "ZKBridgePublicInputs",
    "ZKBridgeProof",
    "ZKBridgeProver",
    "SimulatedZKBridgeProver",
    "STARKBridgeProver",
    "ZKBridgeVerifier",
]


def __getattr__(name):
    if name in ("LiveBridge", "LiveBridgeResult"):
        from .live import LiveBridge, LiveBridgeResult

        return {"LiveBridge": LiveBridge, "LiveBridgeResult": LiveBridgeResult}[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
