"""
Node Diagnostics REST server — consolidated operational visibility.

Exposes read-only REST endpoints for subsystems that lack REST coverage:
peers, transfers, audit scheduler, network nodes, endowment, storage,
and commitment log summary.

Follows the HealthServer/AnchorStatusServer pattern: stdlib http.server
in a daemon thread, start()/stop(), port=0 for ephemeral test ports.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING, Optional
from urllib.parse import parse_qs, urlparse

if TYPE_CHECKING:
    from ..protocol import LTPProtocol
    from .audit_scheduler import AuditScheduler
    from .peer_manager import PeerManager

logger = logging.getLogger(__name__)

__all__ = ["NodeDiagnosticsServer"]


class _DiagnosticsHandler(BaseHTTPRequestHandler):
    """Handle node diagnostics REST API requests."""

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        raw_path = parsed.path
        path = raw_path.rstrip("/")

        # Dynamic routes checked FIRST (before trailing-slash stripping
        # collapses "/node/peers/" into the static "/node/peers" route).
        for prefix, handler, param_name in [
            ("/node/peers/", self._handle_peer_detail, "peer_id"),
            ("/node/transfers/", self._handle_transfer_detail, "entity_id"),
            ("/node/network/nodes/", self._handle_network_node_detail, "node_id"),
        ]:
            if raw_path.startswith(prefix):
                param = raw_path[len(prefix) :].rstrip("/")
                if not param:
                    self._send_json({"error": f"missing {param_name}"}, 400)
                    return
                try:
                    handler(param)
                except Exception:
                    logger.exception("Handler error: %s %s", prefix, param)
                    self._send_json({"error": "internal error"}, 500)
                return

        # Static routes
        routes = {
            "/node/peers": self._handle_peers,
            "/node/transfers": self._handle_transfers,
            "/node/audit": self._handle_audit,
            "/node/network": self._handle_network,
            "/node/network/endowment": self._handle_endowment,
            "/node/storage": self._handle_storage,
            "/node/log": self._handle_log,
        }

        handler = routes.get(path)
        if handler:
            try:
                handler()
            except Exception:
                logger.exception("Handler error: %s", path)
                self._send_json({"error": "internal error"}, 500)
            return

        self._send_json({"error": "not found"}, 404)

    def _send_json(self, data: dict | list, status: int = 200) -> None:
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _parse_params(self) -> dict[str, str]:
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        return {k: v[0] for k, v in params.items()}

    # ------------------------------------------------------------------
    # Peers
    # ------------------------------------------------------------------

    def _handle_peers(self) -> None:
        """GET /node/peers — connected peer list + summary."""
        pm = self.server.peer_manager
        if pm is None:
            self._send_json({"error": "peer manager not available"}, 503)
            return
        peers = pm.get_connected_peers()
        self._send_json(
            {
                "connected_count": pm.connected_count,
                "peers": [self._peer_dict(p) for p in peers],
            }
        )

    def _handle_peer_detail(self, node_id: str) -> None:
        """GET /node/peers/<node_id> — single peer lookup."""
        pm = self.server.peer_manager
        if pm is None:
            self._send_json({"error": "peer manager not available"}, 503)
            return
        peer = pm.get_peer_by_id(node_id)
        if peer is None:
            self._send_json({"error": "not found"}, 404)
            return
        self._send_json(self._peer_dict(peer))

    def _peer_dict(self, peer) -> dict:
        d = {
            "node_id": peer.node_id,
            "region": peer.region,
            "state": peer.state.value,
            "last_seen": peer.last_seen,
            "handshake_failures": peer.handshake_failures,
        }
        if not self.server.public_mode:
            d["address"] = peer.address
        return d

    # ------------------------------------------------------------------
    # Transfers (LTPProtocol sessions)
    # ------------------------------------------------------------------

    def _handle_transfers(self) -> None:
        """GET /node/transfers[?state=COMMITTED] — session list."""
        protocol = self.server.protocol
        if protocol is None:
            self._send_json({"error": "protocol not available"}, 503)
            return
        params = self._parse_params()
        state_filter = params.get("state")
        if state_filter:
            from ..protocol import TransferState

            try:
                state_enum = TransferState[state_filter.strip().upper()]
            except KeyError:
                valid = [s.name for s in TransferState]
                self._send_json(
                    {
                        "error": "invalid state",
                        "valid_states": valid,
                    },
                    400,
                )
                return
            sessions = protocol.list_sessions(state=state_enum)
        else:
            sessions = protocol.list_sessions()
        self._send_json(
            {
                "count": len(sessions),
                "sessions": [self._session_dict(s) for s in sessions],
            }
        )

    def _handle_transfer_detail(self, entity_id: str) -> None:
        """GET /node/transfers/<entity_id> — single session lookup."""
        protocol = self.server.protocol
        if protocol is None:
            self._send_json({"error": "protocol not available"}, 503)
            return
        session = protocol.get_session(entity_id)
        if session is None:
            self._send_json({"error": "not found"}, 404)
            return
        self._send_json(self._session_dict(session))

    @staticmethod
    def _session_dict(session) -> dict:
        return {
            "entity_id": session.entity_id,
            "state": session.state.value,
            "started_at": session.started_at,
            "phase_started_at": session.phase_started_at,
            "retry_count": session.retry_count,
            "error": session.error,
            "elapsed_seconds": session.elapsed_seconds(),
        }

    # ------------------------------------------------------------------
    # Audit scheduler
    # ------------------------------------------------------------------

    def _handle_audit(self) -> None:
        """GET /node/audit — audit scheduler status."""
        scheduler = self.server.audit_scheduler
        if scheduler is None:
            self._send_json({"error": "audit scheduler not available"}, 503)
            return
        self._send_json(
            {
                "epoch": scheduler.epoch,
                "running": scheduler.running,
            }
        )

    # ------------------------------------------------------------------
    # Network (CommitmentNetwork nodes)
    # ------------------------------------------------------------------

    def _handle_network(self) -> None:
        """GET /node/network — node registry summary."""
        network = self.server.commitment_network
        if network is None:
            self._send_json({"error": "network not available"}, 503)
            return
        nodes = network.nodes
        self._send_json(
            {
                "active_node_count": network.active_node_count,
                "total_node_count": len(nodes),
                "nodes": [self._node_summary(n) for n in nodes],
            }
        )

    def _handle_network_node_detail(self, node_id: str) -> None:
        """GET /node/network/nodes/<node_id> — single node details."""
        network = self.server.commitment_network
        if network is None:
            self._send_json({"error": "network not available"}, 503)
            return
        nodes = network.nodes
        node = next((n for n in nodes if n.node_id == node_id), None)
        if node is None:
            self._send_json({"error": "not found"}, 404)
            return
        self._send_json(self._node_detail(node))

    def _node_summary(self, node) -> dict:
        return {
            "node_id": node.node_id,
            "region": node.region,
            "shard_count": node.shard_count,
            "evicted": node.evicted,
            "reputation_score": node.reputation_score,
            "strikes": node.strikes,
            "audit_passes": node.audit_passes,
        }

    def _node_detail(self, node) -> dict:
        d = {
            "node_id": node.node_id,
            "region": node.region,
            "shard_count": node.shard_count,
            "evicted": node.evicted,
            "reputation_score": node.reputation_score,
            "strikes": node.strikes,
            "audit_passes": node.audit_passes,
            "stake_locked_until": node.stake_locked_until,
            "registered_at": node.registered_at,
            "evicted_at": node.evicted_at,
            "eviction_count": node.eviction_count,
        }
        if not self.server.public_mode:
            d["stake"] = node.stake
            d["withheld_earnings"] = node.withheld_earnings
            d["total_earnings"] = node.total_earnings
        return d

    # ------------------------------------------------------------------
    # Endowment
    # ------------------------------------------------------------------

    _BURN_HISTORY_DEFAULT = 50
    _BURN_HISTORY_MAX = 200

    def _handle_endowment(self) -> None:
        """GET /node/network/endowment[?limit=N] — endowment balance + burn history.

        ``limit`` caps burn_history entries returned (default 50, max 200).
        Most recent entries are returned first.
        """
        network = self.server.commitment_network
        if network is None:
            self._send_json({"error": "network not available"}, 503)
            return
        endowment = network.endowment
        params = self._parse_params()
        try:
            limit = int(params.get("limit", str(self._BURN_HISTORY_DEFAULT)))
        except (ValueError, TypeError):
            limit = self._BURN_HISTORY_DEFAULT
        limit = max(1, min(limit, self._BURN_HISTORY_MAX))
        history = endowment.burn_history
        capped = history[-limit:] if len(history) > limit else history
        self._send_json(
            {
                "balance": endowment.balance,
                "total_burned": endowment.total_burned,
                "burn_count": len(history),
                "burn_history": capped,
            }
        )

    # ------------------------------------------------------------------
    # Storage
    # ------------------------------------------------------------------

    def _handle_storage(self) -> None:
        """GET /node/storage — local shard store metrics."""
        cnode = self.server.commitment_node
        if cnode is None:
            self._send_json({"error": "commitment node not available"}, 503)
            return
        self._send_json(
            {
                "node_id": cnode.node_id,
                "shard_count": cnode.shard_count,
                "evicted": cnode.evicted,
            }
        )

    # ------------------------------------------------------------------
    # Commitment log summary
    # ------------------------------------------------------------------

    def _handle_log(self) -> None:
        """GET /node/log — commitment log summary with STH age."""
        network = self.server.commitment_network
        if network is None:
            self._send_json({"error": "network not available"}, 503)
            return
        log = network.log
        sth = log.latest_sth
        sth_dict = None
        sth_age = None
        if sth is not None:
            sth_dict = {
                "sequence": sth.sequence,
                "tree_size": sth.tree_size,
                "timestamp": sth.timestamp,
                "root_hash": sth.root_hash.hex(),
            }
            sth_age = round(max(0, time.time() - sth.timestamp), 2)
        self._send_json(
            {
                "length": log.length,
                "head_hash": log.head_hash,
                "latest_sth": sth_dict,
                "sth_age_seconds": sth_age,
            }
        )

    def log_message(self, format, *args):
        """Suppress default request logging."""
        pass


class NodeDiagnosticsServer:
    """Background REST server exposing node diagnostics endpoints.

    Usage:
        server = NodeDiagnosticsServer(peer_manager=pm, port=8081)
        server.start()
        # GET http://localhost:8081/node/peers
        server.stop()
    """

    def __init__(
        self,
        peer_manager: Optional["PeerManager"] = None,
        commitment_network=None,
        protocol: Optional["LTPProtocol"] = None,
        audit_scheduler: Optional["AuditScheduler"] = None,
        commitment_node=None,
        host: str = "0.0.0.0",
        port: int = 8081,
        public_mode: bool = False,
    ) -> None:
        self._peer_manager = peer_manager
        self._commitment_network = commitment_network
        self._protocol = protocol
        self._audit_scheduler = audit_scheduler
        self._commitment_node = commitment_node
        self._host = host
        self._port = port
        self._public_mode = public_mode
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start the diagnostics server in a background daemon thread."""
        self._server = HTTPServer((self._host, self._port), _DiagnosticsHandler)
        self._port = self._server.server_address[1]
        self._server.peer_manager = self._peer_manager
        self._server.commitment_network = self._commitment_network
        self._server.protocol = self._protocol
        self._server.audit_scheduler = self._audit_scheduler
        self._server.commitment_node = self._commitment_node
        self._server.public_mode = self._public_mode

        def _serve():
            try:
                self._server.serve_forever()
            except Exception:
                logger.exception("NodeDiagnosticsServer crashed")

        self._thread = threading.Thread(target=_serve, daemon=True)
        self._thread.start()
        logger.info("NodeDiagnosticsServer listening on %s:%d", self._host, self._port)

    def stop(self) -> None:
        """Stop the diagnostics server."""
        if self._server:
            self._server.shutdown()
            self._server = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    @property
    def port(self) -> int:
        return self._port

    @property
    def url(self) -> str:
        return f"http://{self._host}:{self._port}"
