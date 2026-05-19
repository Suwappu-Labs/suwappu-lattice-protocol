"""
Minimal REST health endpoint for ETP nodes.

Runs a stdlib http.server in a daemon thread. Used by load balancers
and monitoring systems.

When ``commitment_log`` is provided, the server also exposes the
RFC 6962 CT log API (``/ct/v1/*``) on the same port, avoiding the
need for a separate ``CommitmentLogRestServer`` process.
"""

from __future__ import annotations

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable, Optional

logger = logging.getLogger(__name__)

__all__ = ["HealthServer"]


class _HealthHandler(BaseHTTPRequestHandler):
    """Handle /health GET requests."""

    def do_GET(self) -> None:
        path = self.path.rstrip("/")
        if path == "/health":
            data = self.server.health_fn()
            body = json.dumps(data, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        """Suppress default request logging."""
        pass


def _make_combined_handler():
    """Lazy factory — avoids top-level import of rest_server.

    Returns a handler class that serves both ``/health`` and the
    RFC 6962 CT log routes (``/ct/v1/*``) on a single HTTPServer.
    """
    from ..rest_server import _CTRequestHandler

    class _CombinedHandler(_CTRequestHandler):
        """Serves /health alongside RFC 6962 CT log routes."""

        def do_GET(self) -> None:
            path = self.path.rstrip("/")
            if path == "/health":
                data = self.server.health_fn()
                self._send_json(data)
            else:
                super().do_GET()

        # do_POST inherited from _CTRequestHandler (handles /ct/v1/add-entry)

    return _CombinedHandler


class HealthServer:
    """Background REST server exposing a /health endpoint.

    When ``commitment_log`` is provided, the server also serves the
    RFC 6962 CT log API on the same port (``/ct/v1/*``).

    Usage:
        def get_health():
            return {"status": "ok", "node_id": "n1", ...}
        server = HealthServer(get_health, port=8080)
        server.start()
        # GET http://localhost:8080/health -> JSON
        server.stop()
    """

    def __init__(
        self,
        health_fn: Callable[[], dict],
        host: str = "0.0.0.0",
        port: int = 8080,
        commitment_log=None,
    ) -> None:
        self._health_fn = health_fn
        self._host = host
        self._port = port
        self._commitment_log = commitment_log
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start the health server in a background daemon thread.

        Raises:
            OSError: If the port is already in use.
        """
        if self._commitment_log is not None:
            handler_cls = _make_combined_handler()
        else:
            handler_cls = _HealthHandler

        self._server = HTTPServer((self._host, self._port), handler_cls)
        # Capture actual bound port (relevant when port=0 for dynamic allocation)
        self._port = self._server.server_address[1]
        self._server.health_fn = self._health_fn
        if self._commitment_log is not None:
            self._server.commitment_log = self._commitment_log

        def _serve():
            try:
                self._server.serve_forever()
            except Exception:
                logger.exception("HealthServer crashed")

        self._thread = threading.Thread(target=_serve, daemon=True)
        self._thread.start()
        mode = "health+ct" if self._commitment_log else "health"
        logger.info("HealthServer (%s) listening on %s:%d", mode, self._host, self._port)

    def stop(self) -> None:
        """Stop the health server."""
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
