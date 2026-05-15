"""
gRPC server for a commitment node.

Wraps a CommitmentNode and exposes its shard operations over the network.
"""

from __future__ import annotations

import logging
from concurrent import futures
from typing import TYPE_CHECKING, Iterator

import grpc

from . import shard_service_pb2 as pb2
from . import shard_service_pb2_grpc as pb2_grpc
from . import node_service_pb2_grpc as ns_pb2_grpc

if TYPE_CHECKING:
    from ..commitment import CommitmentNode
    from .node_servicer import NodeServicer
    from .transfer_servicer import TransferServicer

logger = logging.getLogger(__name__)

__all__ = ["NodeServer"]


class _ShardServicer(pb2_grpc.ShardServiceServicer):
    """gRPC servicer backed by a CommitmentNode."""

    def __init__(self, node: "CommitmentNode") -> None:
        self._node = node

    def StoreShard(self, request: pb2.StoreShardRequest, context) -> pb2.StoreShardResponse:
        ok = self._node.store_shard(request.entity_id, request.shard_index, request.encrypted_data)
        if not ok:
            return pb2.StoreShardResponse(success=False, error="node evicted")
        return pb2.StoreShardResponse(success=True)

    def FetchShard(self, request: pb2.FetchShardRequest, context) -> pb2.FetchShardResponse:
        data = self._node.fetch_shard(request.entity_id, request.shard_index)
        if data is None:
            return pb2.FetchShardResponse(found=False)
        return pb2.FetchShardResponse(found=True, encrypted_data=data)

    def AuditChallenge(self, request: pb2.AuditChallengeRequest, context) -> pb2.AuditChallengeResponse:
        proof = self._node.respond_to_audit(
            request.entity_id, request.shard_index, request.nonce,
        )
        if proof is None:
            return pb2.AuditChallengeResponse(found=False)
        return pb2.AuditChallengeResponse(found=True, proof_hash=proof)

    def RemoveShard(self, request: pb2.RemoveShardRequest, context) -> pb2.RemoveShardResponse:
        removed = self._node.remove_shard(request.entity_id, request.shard_index)
        return pb2.RemoveShardResponse(removed=removed)

    def GetNodeInfo(self, request: pb2.NodeInfoRequest, context) -> pb2.NodeInfoResponse:
        return pb2.NodeInfoResponse(
            node_id=self._node.node_id,
            region=self._node.region,
            shard_count=self._node.shard_count,
            evicted=self._node.evicted,
            reputation_score=self._node.reputation_score,
        )

    def FetchShardsBatch(self, request: pb2.FetchShardsBatchRequest, context) -> pb2.FetchShardsBatchResponse:
        responses = []
        for req in request.requests:
            data = self._node.fetch_shard(req.entity_id, req.shard_index)
            if data is None:
                responses.append(pb2.FetchShardResponse(found=False))
            else:
                responses.append(pb2.FetchShardResponse(found=True, encrypted_data=data))
        return pb2.FetchShardsBatchResponse(responses=responses)

    def StoreShardsStream(self, request_iterator: Iterator, context) -> pb2.StoreShardsStreamResponse:
        stored = 0
        failed = 0
        for req in request_iterator:
            ok = self._node.store_shard(req.entity_id, req.shard_index, req.encrypted_data)
            if ok:
                stored += 1
            else:
                failed += 1
        return pb2.StoreShardsStreamResponse(stored_count=stored, failed_count=failed)


class NodeServer:
    """gRPC server wrapping a CommitmentNode.

    Usage:
        node = CommitmentNode("n1", "US-East")
        server = NodeServer(node, port=50051)
        server.start()
        # ... server is running ...
        server.stop()
    """

    def __init__(
        self,
        node: "CommitmentNode",
        port: int = 50051,
        host: str = "0.0.0.0",
        max_workers: int = 10,
        node_servicer: "NodeServicer | None" = None,
        transfer_servicer: "TransferServicer | None" = None,
        tls_config=None,
        interceptors: list | None = None,
    ) -> None:
        self._node = node
        self._port = port
        self._host = host
        self._tls_config = tls_config
        # LTP-A-019: bound message size and concurrent streams so a single
        # client can't OOM the server with a deeply nested protobuf or pin
        # 10k streams open.
        server_opts: dict = {
            "options": [
                ("grpc.max_receive_message_length", 4 * 1024 * 1024),
                ("grpc.max_send_message_length", 4 * 1024 * 1024),
                ("grpc.max_concurrent_streams", 100),
            ],
        }
        if interceptors:
            server_opts["interceptors"] = interceptors
        self._server = grpc.server(
            futures.ThreadPoolExecutor(max_workers=max_workers),
            **server_opts,
        )
        pb2_grpc.add_ShardServiceServicer_to_server(
            _ShardServicer(node), self._server,
        )
        if node_servicer is not None:
            ns_pb2_grpc.add_NodeServiceServicer_to_server(
                node_servicer, self._server,
            )
        if transfer_servicer is not None:
            from . import transfer_service_pb2_grpc as ts_pb2_grpc
            ts_pb2_grpc.add_TransferServiceServicer_to_server(
                transfer_servicer, self._server,
            )
        # Bind port: secure if TLS configured, insecure otherwise
        if tls_config is not None and tls_config.enabled:
            from .credentials import load_server_credentials
            try:
                server_creds = load_server_credentials(tls_config)
            except (FileNotFoundError, PermissionError, ValueError) as e:
                logger.error("TLS credential loading failed: %s — falling back to insecure", e)
                server_creds = None
            if server_creds is not None:
                try:
                    bound_port = self._server.add_secure_port(
                        f"{host}:{port}", server_creds,
                    )
                    self._port = bound_port
                    logger.info("gRPC secure port bound (mTLS=%s)", tls_config.require_client_cert)
                except RuntimeError as e:
                    logger.error("Secure port binding failed: %s — falling back to insecure", e)
                    bound_port = self._server.add_insecure_port(f"{host}:{port}")
                    self._port = bound_port
            else:
                bound_port = self._server.add_insecure_port(f"{host}:{port}")
                self._port = bound_port
        else:
            bound_port = self._server.add_insecure_port(f"{host}:{port}")
            self._port = bound_port

    @property
    def node(self) -> "CommitmentNode":
        return self._node

    @property
    def port(self) -> int:
        return self._port

    @property
    def address(self) -> str:
        return f"{self._host}:{self._port}"

    def start(self) -> None:
        """Start serving (non-blocking)."""
        self._server.start()
        logger.info("NodeServer %s listening on %s:%d", self._node.node_id, self._host, self._port)

    def stop(self, grace: float = 1.0) -> None:
        """Stop the server."""
        self._server.stop(grace)
        logger.info("NodeServer %s stopped", self._node.node_id)

    def wait_for_termination(self, timeout: float | None = None) -> None:
        """Block until the server terminates."""
        self._server.wait_for_termination(timeout=timeout)
