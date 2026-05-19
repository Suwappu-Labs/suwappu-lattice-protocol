"""
REST API for querying anchor subsystem status.

Read-only endpoints for operators and monitoring systems to inspect
anchor lifecycle state without touching gRPC.  Follows the HealthServer
pattern: stdlib http.server in a daemon thread, start()/stop().
"""

from __future__ import annotations

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING, Optional
from urllib.parse import parse_qs, urlparse

if TYPE_CHECKING:
    from .anchor_scheduler import AnchorScheduler
    from .anchor_status import AnchorStatusTracker
    from .anchor_verifier import AnchorVerifier

logger = logging.getLogger(__name__)

__all__ = ["AnchorStatusServer"]


class _AnchorHandler(BaseHTTPRequestHandler):
    """Handle anchor REST API requests."""

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        # Static routes
        routes = {
            "/anchor/stats": self._handle_stats,
            "/anchor/by-status": self._handle_by_status,
            "/anchor/health": self._handle_health,
        }
        handler = routes.get(path)
        if handler:
            try:
                handler()
            except Exception:
                logger.exception("Handler error: %s", path)
                self._send_json({"error": "internal error"}, 500)
            return

        # Dynamic route: /anchor/status/<entity_id>
        if path.startswith("/anchor/status/") or path == "/anchor/status":
            entity_id = path[len("/anchor/status/") :] if path.startswith("/anchor/status/") else ""
            if not entity_id:
                self._send_json({"error": "missing entity_id"}, 400)
                return
            try:
                self._handle_status(entity_id)
            except Exception:
                logger.exception("Handler error: /anchor/status/%s", entity_id)
                self._send_json({"error": "internal error"}, 500)
            return

        self._send_json({"error": "not found"}, 404)

    def _send_json(self, data: dict, status: int = 200) -> None:
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
    # Endpoint handlers
    # ------------------------------------------------------------------

    def _handle_status(self, entity_id: str) -> None:
        """GET /anchor/status/<entity_id> — single entity lookup."""
        tracker = self.server.tracker
        rec = tracker.get(entity_id)
        if rec is None:
            self._send_json({"error": "not found"}, 404)
            return
        self._send_json(
            {
                "entity_id": rec.entity_id,
                "status": rec.status.name,
                "tx_hash": rec.tx_hash,
                "block_number": rec.block_number,
                "gas_used": rec.gas_used,
                "submitted_at": rec.submitted_at,
                "retry_count": rec.retry_count,
                "error": rec.error,
            }
        )

    def _handle_stats(self) -> None:
        """GET /anchor/stats — aggregate counts + component metadata."""
        tracker = self.server.tracker
        counts = tracker.stats()
        # Uppercase the keys to match AnchorStatus enum names
        upper_counts = {k.upper(): v for k, v in counts.items()}
        total = sum(upper_counts.values())
        data: dict = {
            "counts": upper_counts,
            "total": total,
        }
        scheduler = self.server.scheduler
        if scheduler is not None:
            data["scheduler"] = {
                "epoch": scheduler.epoch,
                "running": scheduler.running,
                "pending_batch_size": scheduler.pending_batch_size,
                "last_seen_index": scheduler.last_seen_index,
            }
        verifier = self.server.verifier
        if verifier is not None:
            data["verifier"] = {
                "epoch": verifier.epoch,
                "running": verifier.running,
            }
        self._send_json(data)

    def _handle_by_status(self) -> None:
        """GET /anchor/by-status?status=X — filter by AnchorStatus."""
        from .anchor_status import AnchorStatus

        params = self._parse_params()
        status_str = params.get("status", "")
        if not status_str:
            self._send_json({"error": "invalid status"}, 400)
            return

        # Validate status name
        try:
            status = AnchorStatus[status_str.upper()]
        except KeyError:
            self._send_json({"error": "invalid status"}, 400)
            return

        tracker = self.server.tracker
        records = tracker.get_by_status(status)
        entities = [
            {
                "entity_id": r.entity_id,
                "tx_hash": r.tx_hash,
                "block_number": r.block_number,
                "gas_used": r.gas_used,
                "submitted_at": r.submitted_at,
                "retry_count": r.retry_count,
                "error": r.error,
            }
            for r in records
        ]
        self._send_json(
            {
                "status": status.name,
                "count": len(entities),
                "entities": entities,
            }
        )

    def _handle_health(self) -> None:
        """GET /anchor/health — subsystem health check.

        Always includes scheduler_running and verifier_running (null when
        the component is not wired) so monitoring dashboards get a stable
        schema regardless of deployment configuration.
        """
        tracker = self.server.tracker
        counts = tracker.stats()
        total = sum(counts.values())
        scheduler = self.server.scheduler
        verifier = self.server.verifier
        self._send_json(
            {
                "status": "ok",
                "tracker_total": total,
                "scheduler_running": scheduler.running if scheduler is not None else None,
                "verifier_running": verifier.running if verifier is not None else None,
            }
        )

    def log_message(self, format, *args):
        """Suppress default request logging."""
        pass


class AnchorStatusServer:
    """Background REST server exposing anchor status endpoints.

    Usage:
        server = AnchorStatusServer(tracker, scheduler, verifier, port=8082)
        server.start()
        # GET http://localhost:8082/anchor/stats
        server.stop()
    """

    def __init__(
        self,
        tracker: "AnchorStatusTracker",
        scheduler: Optional["AnchorScheduler"] = None,
        verifier: Optional["AnchorVerifier"] = None,
        host: str = "0.0.0.0",
        port: int = 8082,
    ) -> None:
        self._tracker = tracker
        self._scheduler = scheduler
        self._verifier = verifier
        self._host = host
        self._port = port
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start the anchor REST server in a background daemon thread."""
        self._server = HTTPServer((self._host, self._port), _AnchorHandler)
        self._port = self._server.server_address[1]
        self._server.tracker = self._tracker
        self._server.scheduler = self._scheduler
        self._server.verifier = self._verifier

        def _serve():
            try:
                self._server.serve_forever()
            except Exception:
                logger.exception("AnchorStatusServer crashed")

        self._thread = threading.Thread(target=_serve, daemon=True)
        self._thread.start()
        logger.info("AnchorStatusServer listening on %s:%d", self._host, self._port)

    def stop(self) -> None:
        """Stop the anchor REST server."""
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
