"""
ETP Node — bootstrap, discovery, and handshake for LTP network nodes.

Provides:
  - NodeConfig    — TOML/env-based configuration
  - PeerManager   — peer tracking and state management
  - ETPNode       — main node process (gRPC + REST)
"""

from __future__ import annotations

__all__ = [
    "NodeConfig",
    "PeerState",
    "PeerInfo",
    "PeerManager",
    "HandshakePayload",
    "ETPNode",
    "NetworkBridge",
    "AuditScheduler",
    "TransferBundle",
    "AnchorStatus",
    "AnchorRecord",
    "AnchorStatusTracker",
    "AnchorScheduler",
    "AnchorTickResult",
    "AnchorVerifier",
    "AnchorVerifyResult",
    "reconcile_on_startup",
    "AnchorStatusServer",
    "NodeDiagnosticsServer",
]


def __getattr__(name: str):
    """Lazy imports to keep the package lightweight."""
    if name == "NodeConfig":
        from .config import NodeConfig

        return NodeConfig
    if name in ("PeerState", "PeerInfo", "PeerManager"):
        from . import peer_manager as _pm

        return getattr(_pm, name)
    if name == "HandshakePayload":
        from .handshake import HandshakePayload

        return HandshakePayload
    if name == "ETPNode":
        from .main import ETPNode

        return ETPNode
    if name == "NetworkBridge":
        from .network_bridge import NetworkBridge

        return NetworkBridge
    if name == "AuditScheduler":
        from .audit_scheduler import AuditScheduler

        return AuditScheduler
    if name == "TransferBundle":
        from .transfer_bundle import TransferBundle

        return TransferBundle
    if name in ("AnchorStatus", "AnchorRecord", "AnchorStatusTracker"):
        from . import anchor_status as _as

        return getattr(_as, name)
    if name in ("AnchorScheduler", "AnchorTickResult"):
        from . import anchor_scheduler as _asch

        return getattr(_asch, name)
    if name in ("AnchorVerifier", "AnchorVerifyResult", "reconcile_on_startup"):
        from . import anchor_verifier as _av

        return getattr(_av, name)
    if name == "AnchorStatusServer":
        from .anchor_rest import AnchorStatusServer

        return AnchorStatusServer
    if name == "NodeDiagnosticsServer":
        from .node_diagnostics import NodeDiagnosticsServer

        return NodeDiagnosticsServer
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
