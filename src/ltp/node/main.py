"""
ETP Node — main process that bootstraps from config, discovers peers,
and completes post-quantum authenticated handshakes over gRPC.

Usage:
    python -m ltp.node --config node.toml
    python -m ltp.node  # env vars only
"""

from __future__ import annotations

import argparse
import logging
import signal
import time
from typing import Optional

from ..commitment import CommitmentNetwork, CommitmentNode
from ..keypair import KeyPair, KeyRegistry
from ..primitives import assert_real_crypto
from .audit_scheduler import AuditScheduler
from .config import NodeConfig
from .handshake import (
    PROTOCOL_VERSION,
    HandshakePayload,
    create_handshake_envelope,
    deserialize_envelope,
    serialize_envelope,
    verify_handshake_envelope,
)
from .health import HealthServer
from .network_bridge import NetworkBridge
from .peer_manager import PeerManager

logger = logging.getLogger(__name__)

__all__ = ["ETPNode", "main"]


class ETPNode:
    """Main ETP node process.

    Wires together:
      - CommitmentNode (shard storage)
      - NodeServer (gRPC: ShardService + NodeService)
      - HealthServer (REST /health)
      - PeerManager (peer tracking)
      - Handshake protocol (ML-DSA-65 authenticated)
    """

    def __init__(self, config: NodeConfig) -> None:
        self.config = config
        self.keypair: Optional[KeyPair] = None
        self.commitment_node: Optional[CommitmentNode] = None
        self.commitment_network = None
        self.protocol = None
        self.peer_manager = PeerManager()
        self._grpc_server = None
        self._health_server: Optional[HealthServer] = None
        self._network_bridge: Optional[NetworkBridge] = None
        self._audit_scheduler: Optional[AuditScheduler] = None
        # Per-chain anchor pipelines: list of (label, tracker, scheduler, verifier)
        self._anchor_pipelines: list[tuple[str, object, object, object]] = []
        self._anchor_rest_server = None
        self._diagnostics_server = None
        self._gateway_server = None
        self._gossip_protocol = None
        self._bridge_operator = None
        self._observability = None
        self._start_time = time.time()
        self._running = False

    def start(self) -> None:
        """Bootstrap and start the node.

        If any step after server startup fails, previously started
        servers are shut down before the exception propagates.
        """
        # Configure logging
        logging.basicConfig(
            level=getattr(logging, self.config.log_level.upper(), logging.INFO),
            format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        )

        # 1. Assert real crypto if required
        if self.config.require_real_crypto:
            try:
                assert_real_crypto()
            except Exception:
                logger.warning(
                    "Real crypto not available; set require_real_crypto=false for PoC mode"
                )
                raise

        # 2. Initialize KMS backend (if configured)
        self._kms_backend = None
        if self.config.kms_backend == "aws" and self.config.kms_key_arn:
            try:
                from ..cloud.aws_kms import AWSKMSBackend

                self._kms_backend = AWSKMSBackend(
                    key_arn=self.config.kms_key_arn,
                    region=self.config.kms_region,
                    endpoint_url=self.config.kms_endpoint,
                )
                logger.info("AWS KMS initialized (region=%s)", self.config.kms_region)
            except Exception:
                logger.warning("AWS KMS initialization failed", exc_info=True)
        elif self.config.kms_backend == "memory":
            from ..cloud.kms import InMemoryKMSBackend

            self._kms_backend = InMemoryKMSBackend()
            logger.info("In-memory KMS initialized")

        # 2.5. Load or generate keypair
        self.keypair = KeyPair.generate(self.config.node_id)
        logger.info(
            "Node %s keypair ready (vk=%s...)",
            self.config.node_id,
            self.keypair.vk[:8].hex(),
        )

        # 3. Create CommitmentNode for shard storage (with configured backend)
        shard_store = _create_shard_store(self.config)
        self.commitment_node = CommitmentNode(
            self.config.node_id,
            self.config.region,
            shard_store=shard_store,
        )

        # 3.5. CommitmentNetwork (thread-safe) with self as first node
        from ..network.safe_network import SafeCommitmentNetwork

        log_store = _create_log_store(self.config)
        inner_network = CommitmentNetwork(log_store=log_store)
        inner_network.add_existing_node(self.commitment_node)
        self.commitment_network = SafeCommitmentNetwork(inner_network)

        # 3.6. LTPProtocol
        from ..protocol import LTPProtocol

        key_registry = KeyRegistry()
        self.protocol = LTPProtocol(self.commitment_network, key_registry=key_registry)

        # 3.7. NetworkBridge (wires peers ↔ network)
        self._network_bridge = NetworkBridge(self.commitment_network, self.peer_manager)

        # 4. Create NodeServicer (with bridge callback)
        from ..network.node_servicer import NodeServicer

        node_servicer = NodeServicer(
            node_id=self.config.node_id,
            region=self.config.region,
            keypair=self.keypair,
            peer_manager=self.peer_manager,
            shard_count_fn=lambda: self.commitment_node.shard_count,
            start_time=self._start_time,
            on_peer_connected=self._network_bridge.add_peer,
        )

        # 4.5. Create TransferServicer
        from ..network.transfer_servicer import TransferServicer

        transfer_servicer = TransferServicer(self.protocol, self.keypair)

        # 4.8. Build TLS config (if enabled)
        tls_config = None
        if self.config.tls_enabled:
            from ..observability.tls import TLSConfig

            tls_config = TLSConfig(
                enabled=True,
                cert_path=self.config.tls_cert_path,
                key_path=self.config.tls_key_path,
                ca_path=self.config.tls_ca_path,
                require_client_cert=self.config.tls_require_client_cert,
            )
            logger.info(
                "TLS enabled (cert=%s, mTLS=%s)",
                self.config.tls_cert_path,
                self.config.tls_require_client_cert,
            )
        self._tls_config = tls_config

        # 4.9. Initialize observability early (before gateway needs it)
        if self.config.observability_enabled:
            try:
                from ..observability.endpoint import ETPObservability

                self._observability = ETPObservability(
                    node_id=self.config.node_id,
                    region=self.config.region,
                )
                logger.info("Observability initialized (16 metrics + logging + alerts)")
            except Exception:
                logger.warning("Observability failed to initialize", exc_info=True)

        # From this point on, failures must roll back started servers
        try:
            # 5. Start gRPC server (ShardService + NodeService)
            from ..network.server import NodeServer

            self._grpc_server = NodeServer(
                node=self.commitment_node,
                port=self.config.listen_port,
                host=self.config.listen_host,
                max_workers=self.config.max_workers,
                node_servicer=node_servicer,
                transfer_servicer=transfer_servicer,
                tls_config=tls_config,
            )
            self._grpc_server.start()

            # 6. Start REST health server (+ CT log API on same port)
            self._health_server = HealthServer(
                health_fn=self._health_data,
                host=self.config.listen_host,
                port=self.config.rest_port,
                commitment_log=self.commitment_network.log,
            )
            self._health_server.start()
            logger.info(
                "REST health+ct at http://%s:%d/health",
                self.config.listen_host,
                self._health_server.port,
            )
        except Exception:
            # Roll back any servers that managed to start
            self.stop()
            raise

        # 7. Register signal handlers
        self._running = True
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        # 8. Register seed peers and handshake
        # Individual handshake failures are non-fatal — we log and continue
        for addr in self.config.seed_peers:
            self.peer_manager.add_seed_peer(addr)

        for addr in self.config.seed_peers:
            try:
                self._handshake_with_peer(addr)
            except Exception as e:
                logger.warning("Handshake with %s failed: %s", addr, e)
                self.peer_manager.mark_rejected(addr)

        # 9. Sync connected peers into commitment network
        self._network_bridge.sync_peers()

        # 10. Start PDP audit scheduler
        self._audit_scheduler = AuditScheduler(
            self.commitment_network,
            self.config.node_id,
            interval_seconds=self.config.audit_interval_seconds,
            strike_threshold=self.config.strike_threshold,
        )
        self._audit_scheduler.start()

        # 11. Start per-chain anchor pipelines (if on-chain anchoring is enabled)
        if self.config.anchor_enabled:
            from ..anchor.chain_config import create_anchor_client
            from .anchor_scheduler import AnchorScheduler
            from .anchor_status import AnchorStatusTracker
            from .anchor_verifier import AnchorVerifier, reconcile_on_startup

            chain_configs = self.config.get_chain_configs()
            if not chain_configs:
                raise ValueError("anchor_enabled=True but no chain configuration found")

            logger.info(
                "Initializing anchor pipelines for %d chain(s): %s",
                len(chain_configs),
                ", ".join(c.label or str(c.chain_id) for c in chain_configs),
            )

            for chain_cfg in chain_configs:
                label = chain_cfg.label or str(chain_cfg.chain_id)
                tracker = AnchorStatusTracker()
                anchor_client = create_anchor_client(chain_cfg)

                # Reconcile in-flight anchors from prior run
                reconciled_count = 0
                try:
                    reconciled_count = reconcile_on_startup(
                        self.commitment_network,
                        anchor_client,
                        tracker,
                    )
                    if reconciled_count:
                        logger.info(
                            "Reconciled %d anchors from chain %s",
                            reconciled_count,
                            label,
                        )
                except Exception:
                    logger.warning(
                        "Anchor reconciliation failed for chain %s — continuing",
                        label,
                        exc_info=True,
                    )

                scheduler = AnchorScheduler(
                    network=self.commitment_network,
                    client=anchor_client,
                    tracker=tracker,
                    config=self.config,
                    signer_vk=self.keypair.vk,
                    chain_label=label,
                    chain_id=chain_cfg.chain_id,
                )
                # Seed poll position so it doesn't re-scan reconciled records
                if reconciled_count:
                    try:
                        log_len = len(self.commitment_network.records_since(0))
                        scheduler._last_seen_index = log_len
                    except Exception:
                        pass  # Non-fatal — idempotency guard handles duplicates
                scheduler.start()

                verifier = AnchorVerifier(
                    client=anchor_client,
                    tracker=tracker,
                    config=self.config,
                    chain_label=label,
                )
                verifier.start()

                self._anchor_pipelines.append((label, tracker, scheduler, verifier))

            # 13. Start AnchorStatusServer (REST endpoint — uses primary chain)
            if self._anchor_pipelines:
                primary_label, primary_tracker, primary_scheduler, primary_verifier = (
                    self._anchor_pipelines[0]
                )
                from .anchor_rest import AnchorStatusServer

                self._anchor_rest_server = AnchorStatusServer(
                    tracker=primary_tracker,
                    scheduler=primary_scheduler,
                    verifier=primary_verifier,
                    host=self.config.listen_host,
                    port=self.config.anchor_rest_port,
                )
                self._anchor_rest_server.start()
                logger.info(
                    "Anchor REST at http://%s:%d/anchor/stats (primary: %s)",
                    self.config.listen_host,
                    self._anchor_rest_server.port,
                    primary_label,
                )

        # 14. Start NodeDiagnosticsServer (consolidated operational REST)
        try:
            from .node_diagnostics import NodeDiagnosticsServer

            self._diagnostics_server = NodeDiagnosticsServer(
                peer_manager=self.peer_manager,
                commitment_network=self.commitment_network,
                protocol=self.protocol,
                audit_scheduler=self._audit_scheduler,
                commitment_node=self.commitment_node,
                host=self.config.listen_host,
                port=self.config.diagnostics_port,
                public_mode=self.config.diagnostics_public_mode,
            )
            self._diagnostics_server.start()
            logger.info(
                "Diagnostics REST at http://%s:%d/node/peers",
                self.config.listen_host,
                self._diagnostics_server.port,
            )
        except Exception:
            logger.warning("Diagnostics server failed to start", exc_info=True)
            self.stop()
            raise

        # 15. Start gateway (unified REST) if enabled
        if self.config.gateway_enabled:
            try:
                from ..gateway.app import GatewayConfig, GatewayServer

                gw_config = GatewayConfig(
                    host=self.config.listen_host,
                    port=self.config.gateway_port,
                    jwt_enabled=self.config.gateway_jwt_enabled,
                    jwt_token_ttl_seconds=self.config.gateway_jwt_ttl_seconds,
                    rate_limit_enabled=self.config.gateway_rate_limit_per_minute > 0,
                    rate_limit_per_minute=self.config.gateway_rate_limit_per_minute,
                )
                primary_tracker = self._anchor_pipelines[0][1] if self._anchor_pipelines else None
                primary_scheduler = self._anchor_pipelines[0][2] if self._anchor_pipelines else None
                primary_verifier = self._anchor_pipelines[0][3] if self._anchor_pipelines else None
                self._gateway_server = GatewayServer(
                    config=gw_config,
                    health_fn=self._health_data,
                    commitment_log=self.commitment_network.log,
                    anchor_tracker=primary_tracker,
                    anchor_scheduler=primary_scheduler,
                    anchor_verifier=primary_verifier,
                    peer_manager=self.peer_manager,
                    commitment_network=self.commitment_network,
                    protocol=self.protocol,
                    audit_scheduler=self._audit_scheduler,
                    commitment_node=self.commitment_node,
                    public_mode=self.config.diagnostics_public_mode,
                    keypair=self.keypair,
                )
                # Wire observability into gateway for /metrics endpoint
                if self._observability:
                    self._gateway_server.app.state.observability = self._observability
                self._gateway_server.start()
                logger.info("Gateway at %s", self._gateway_server.url)
            except Exception:
                logger.warning("Gateway failed to start", exc_info=True)

        # 16. Start gossip peer discovery if enabled
        if self.config.gossip_enabled:
            try:
                from .gossip import GossipConfig, GossipProtocol

                gossip_config = GossipConfig(
                    enabled=True,
                    interval_seconds=self.config.gossip_interval_seconds,
                    max_peers=self.config.gossip_max_peers,
                    liveness_timeout_seconds=self.config.gossip_liveness_timeout_seconds,
                )
                self._gossip_protocol = GossipProtocol(
                    peer_manager=self.peer_manager,
                    keypair=self.keypair,
                    node_id=self.config.node_id,
                    region=self.config.region,
                    config=gossip_config,
                    send_fn=self._gossip_send_fn,
                )
                # Wire gossip into NodeServicer for incoming ExchangePeers RPCs
                node_servicer._gossip = self._gossip_protocol
                self._gossip_protocol.start()
                logger.info(
                    "Gossip started (interval=%.1fs, gRPC wired)",
                    self.config.gossip_interval_seconds,
                )
            except Exception:
                logger.warning("Gossip failed to start", exc_info=True)

        # 17. Start bridge operator if enabled
        if self.config.bridge_operator_enabled:
            try:
                from ..bridge.operator import BridgeOperatorService

                self._bridge_operator = BridgeOperatorService(
                    network=self.commitment_network,
                    live_bridge=None,  # Requires LiveBridge setup (see scripts/bridge_live.py)
                    source_chain=self.config.bridge_operator_direction.split("_to_")[0]
                    if "_to_" in self.config.bridge_operator_direction
                    else "gsx_testnet",
                    dest_chain=self.config.bridge_operator_direction.split("_to_")[1]
                    if "_to_" in self.config.bridge_operator_direction
                    else "base_sepolia",
                    interval_seconds=self.config.bridge_operator_interval_seconds,
                    max_retries=self.config.bridge_operator_max_retries,
                )
                logger.info("BridgeOperator configured (requires LiveBridge for full operation)")
            except Exception:
                logger.warning("Bridge operator failed to initialize", exc_info=True)

        logger.info(
            "Node %s started — %d peers connected",
            self.config.node_id,
            self.peer_manager.connected_count,
        )

    def _create_channel(self, address: str):
        """Create a gRPC channel, using mTLS if TLS is configured."""
        import grpc

        if self._tls_config is not None and getattr(self._tls_config, "enabled", False):
            from ..network.credentials import load_channel_credentials

            credentials = load_channel_credentials(self._tls_config)
            if credentials is not None:
                return grpc.secure_channel(address, credentials)
        return grpc.insecure_channel(address)

    def _gossip_send_fn(self, address: str, msg_bytes: bytes, sig: bytes, sender_vk: bytes) -> None:
        """Send gossip peer exchange to a peer via gRPC ExchangePeers RPC (mTLS-aware)."""
        import grpc

        from ..network import node_service_pb2 as ns_pb2
        from ..network import node_service_pb2_grpc as ns_pb2_grpc

        channel = self._create_channel(address)
        try:
            stub = ns_pb2_grpc.NodeServiceStub(channel)
            request = ns_pb2.PeerExchangeRequest(
                signed_message=msg_bytes,
                signature=sig,
                sender_vk=sender_vk,
                protocol_version=1,
            )
            response = stub.ExchangePeers(request, timeout=5.0)
            if response.accepted and response.signed_message:
                from .gossip import PeerExchangeMessage

                resp_msg = PeerExchangeMessage.from_bytes(response.signed_message)
                if self._gossip_protocol:
                    self._gossip_protocol.handle_peer_exchange(
                        resp_msg,
                        response.sender_vk,
                        response.signature,
                    )
        except Exception as e:
            logger.debug("Gossip send to %s failed: %s", address, e)
        finally:
            channel.close()

    def _handshake_with_peer(self, address: str) -> None:
        """Perform ML-DSA-65 authenticated handshake with a peer."""
        import grpc

        from ..network import node_service_pb2 as ns_pb2
        from ..network import node_service_pb2_grpc as ns_pb2_grpc

        # Use actual bound port (may differ from config when port=0)
        actual_port = self._grpc_server.port if self._grpc_server else self.config.listen_port
        listen_addr = f"{self.config.listen_host}:{actual_port}"

        # Build handshake payload + signed envelope
        payload = HandshakePayload(
            node_id=self.config.node_id,
            listen_address=listen_addr,
            region=self.config.region,
            protocol_version=PROTOCOL_VERSION,
            timestamp=time.time(),
        )
        envelope = create_handshake_envelope(self.keypair, payload)
        envelope_bytes = serialize_envelope(envelope)

        # Send via gRPC (mTLS-aware)
        channel = self._create_channel(address)
        try:
            stub = ns_pb2_grpc.NodeServiceStub(channel)
            response = stub.Handshake(
                ns_pb2.HandshakeRequest(
                    signed_envelope=envelope_bytes,
                    protocol_version=PROTOCOL_VERSION,
                ),
                timeout=10.0,
            )
        finally:
            channel.close()

        if not response.accepted:
            raise RuntimeError(f"Handshake rejected: {response.reject_reason}")

        # Verify response envelope
        resp_env = deserialize_envelope(response.signed_envelope)
        ok, resp_payload = verify_handshake_envelope(resp_env)
        if not ok or resp_payload is None:
            raise RuntimeError("Peer response envelope verification failed")

        # Register peer
        self.peer_manager.mark_connected(
            node_id=resp_payload.node_id,
            public_key=resp_env.signer_vk,
            address=address,
            region=resp_payload.region,
        )
        logger.info(
            "Handshake complete with %s (%s)",
            resp_payload.node_id,
            resp_payload.region,
        )

    def _health_data(self) -> dict:
        """Build health response dict."""
        return {
            "status": "ok",
            "node_id": self.config.node_id,
            "region": self.config.region,
            "uptime_seconds": round(time.time() - self._start_time, 2),
            "peer_count": self.peer_manager.connected_count,
            "shard_count": self.commitment_node.shard_count if self.commitment_node else 0,
        }

    def _signal_handler(self, signum, frame):
        logger.info("Received signal %d, shutting down...", signum)
        self.stop()

    def stop(self) -> None:
        """Graceful shutdown.

        Order: optional components first, then REST servers (stop accepting queries),
        then daemons, then bridge (close gRPC channels), then gRPC last.
        """
        self._running = False
        if self._bridge_operator:
            try:
                self._bridge_operator.stop()
            except Exception:
                logger.warning("Bridge operator stop failed", exc_info=True)
            self._bridge_operator = None
        if self._gossip_protocol:
            try:
                self._gossip_protocol.stop()
            except Exception:
                logger.warning("Gossip stop failed", exc_info=True)
            self._gossip_protocol = None
        if self._gateway_server:
            try:
                self._gateway_server.stop()
            except Exception:
                logger.warning("Gateway stop failed", exc_info=True)
            self._gateway_server = None
        if self._diagnostics_server:
            self._diagnostics_server.stop()
            self._diagnostics_server = None
        if self._anchor_rest_server:
            self._anchor_rest_server.stop()
            self._anchor_rest_server = None
        if self._health_server:
            self._health_server.stop()
            self._health_server = None
        for label, tracker, scheduler, verifier in reversed(self._anchor_pipelines):
            try:
                verifier.stop()
            except Exception:
                logger.warning("Failed to stop verifier for chain %s", label)
            try:
                scheduler.stop()
            except Exception:
                logger.warning("Failed to stop scheduler for chain %s", label)
        self._anchor_pipelines.clear()
        if self._audit_scheduler:
            self._audit_scheduler.stop()
            self._audit_scheduler = None
        if self._network_bridge:
            self._network_bridge.close_all()
        if self._grpc_server:
            self._grpc_server.stop(grace=2.0)
            self._grpc_server = None
        logger.info("Node %s stopped", self.config.node_id)

    def wait(self) -> None:
        """Block until shutdown."""
        if self._grpc_server:
            self._grpc_server.wait_for_termination()


def _create_shard_store(config: NodeConfig):
    """Factory: create a ShardStore from node config."""
    backend = config.storage_backend.lower()
    if backend == "memory" or not backend:
        from ..storage import MemoryShardStore

        return MemoryShardStore()
    if backend == "sqlite":
        from ..storage import SQLiteShardStore

        path = config.storage_path or "shards.db"
        return SQLiteShardStore(db_path=path, node_id=config.node_id)
    if backend == "filesystem":
        from ..storage import FileShardStore

        path = config.storage_path or "shard_data"
        return FileShardStore(base_dir=path)
    if backend == "rocksdb":
        from ..storage import RocksDBShardStore

        path = config.storage_path or "rocksdb_shards"
        return RocksDBShardStore(path=path)
    raise ValueError(f"Unknown storage_backend: {config.storage_backend!r}")


def _create_log_store(config: NodeConfig):
    """Factory: create a CommitmentLogStore from node config.

    Returns None for memory backend (in-memory MerkleLog only).
    For sqlite/filesystem backends, creates a SQLite log store alongside
    the shard data.
    """
    backend = config.storage_backend.lower()
    if backend == "memory" or not backend:
        return None
    from ..storage import CommitmentLogStore

    if backend == "sqlite":
        import os

        base = config.storage_path or "shards.db"
        root, ext = os.path.splitext(base)
        log_path = root + "_log" + (ext or ".db")
        return CommitmentLogStore(db_path=log_path)
    if backend == "filesystem":
        import os

        base = config.storage_path or "shard_data"
        log_path = os.path.join(base, "commitment_log.db")
        os.makedirs(base, exist_ok=True)
        return CommitmentLogStore(db_path=log_path)
    return None


def main():
    """CLI entrypoint for `python -m ltp.node` or `etp-node`."""
    parser = argparse.ArgumentParser(
        prog="etp-node",
        description="ETP Node — post-quantum secure network node",
    )
    parser.add_argument(
        "--config",
        "-c",
        help="Path to TOML configuration file",
        default=None,
    )
    args = parser.parse_args()

    if args.config:
        config = NodeConfig.from_toml_with_env_overlay(args.config)
    else:
        config = NodeConfig.from_env()

    node = ETPNode(config)
    try:
        node.start()
        node.wait()
    except KeyboardInterrupt:
        pass
    finally:
        node.stop()


if __name__ == "__main__":
    main()
