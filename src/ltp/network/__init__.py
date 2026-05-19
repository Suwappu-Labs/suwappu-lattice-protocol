"""
gRPC networking layer for LTP commitment nodes.

Provides:
  - NodeServer  — serves shard store/fetch/audit RPCs on a commitment node
  - NodeClient  — connects to a remote commitment node
  - RemoteNode  — CommitmentNode-compatible proxy that routes through gRPC

Requires: pip install grpcio grpcio-tools  (or install ltp[network])
"""

from __future__ import annotations

__all__ = [
    "NodeServer",
    "NodeClient",
    "RemoteNode",
    "NodeServicer",
    "SafeCommitmentNetwork",
    "TransferServicer",
]


def __getattr__(name: str):
    """Lazy imports to avoid hard grpc dependency."""
    if name == "NodeServer":
        from .server import NodeServer

        return NodeServer
    if name == "NodeClient":
        from .client import NodeClient

        return NodeClient
    if name == "RemoteNode":
        from .remote import RemoteNode

        return RemoteNode
    if name == "NodeServicer":
        from .node_servicer import NodeServicer

        return NodeServicer
    if name == "SafeCommitmentNetwork":
        from .safe_network import SafeCommitmentNetwork

        return SafeCommitmentNetwork
    if name == "TransferServicer":
        from .transfer_servicer import TransferServicer

        return TransferServicer
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
