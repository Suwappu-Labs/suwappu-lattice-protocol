"""
RFC 6962-compatible REST API for the LTP Commitment Log.

Exposes 6 HTTP endpoints matching the Certificate Transparency log server API,
enabling external monitors and auditors to interact with the commitment log.

Uses Python stdlib http.server — zero external dependencies.

Reference: RFC 6962 §4 (Log Client Messages)
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional
from urllib.parse import parse_qs, urlparse

from .commitment import CommitmentLog, CommitmentRecord
from .merkle_log.sth import SignedTreeHead
from .merkle_log.tree import verify_consistency

__all__ = ["CommitmentLogRestServer"]


# ---------------------------------------------------------------------------
# JSON Serialization Helpers
# ---------------------------------------------------------------------------


def sth_to_dict(sth: SignedTreeHead) -> dict:
    """Serialize SignedTreeHead to JSON-safe dict (binary → hex)."""
    return {
        "sequence": sth.sequence,
        "tree_size": sth.tree_size,
        "timestamp": sth.timestamp,
        "root_hash": sth.root_hash.hex(),
        "operator_vk": sth.operator_vk.hex() if sth.operator_vk else "",
        "signature": sth.signature.hex() if sth.signature else "",
    }


def record_to_dict(record: CommitmentRecord) -> dict:
    """Serialize CommitmentRecord to JSON-safe dict.

    Uses the record's own to_dict() if available, otherwise builds manually.
    """
    if hasattr(record, "to_dict"):
        d = record.to_dict()
        # Ensure binary fields are hex-encoded for JSON
        for key in ("signature", "shard_map_root", "content_hash"):
            val = d.get(key)
            if isinstance(val, bytes):
                d[key] = val.hex()
        return d
    # Fallback: manual serialization
    return {
        "entity_id": record.entity_id,
        "sender_id": record.sender_id,
        "content_hash": record.content_hash,
        "shard_map_root": record.shard_map_root,
        "timestamp": record.timestamp,
        "shape": getattr(record, "shape", ""),
        "signature": record.signature.hex()
        if isinstance(record.signature, bytes)
        else str(record.signature),
        "predecessor": getattr(record, "predecessor", ""),
    }


def proof_to_dict(proof: dict) -> dict:
    """Serialize inclusion proof to JSON-safe dict."""
    result = {
        "entity_id": proof.get("entity_id", ""),
        "position": proof.get("position", -1),
    }
    root_hash = proof.get("root_hash", "")
    if isinstance(root_hash, bytes):
        result["root_hash"] = root_hash.hex()
    else:
        result["root_hash"] = str(root_hash)

    inc_proof = proof.get("inclusion_proof")
    if inc_proof:
        result["audit_path"] = [
            h.hex() if isinstance(h, bytes) else str(h)
            for h in getattr(inc_proof, "audit_path", [])
        ]
        result["leaf_index"] = getattr(inc_proof, "leaf_index", -1)
        result["tree_size"] = getattr(inc_proof, "tree_size", 0)
    return result


def error_response(code: int, message: str) -> dict:
    """Create an RFC 6962-style error response."""
    return {"error": message, "code": code}


# ---------------------------------------------------------------------------
# HTTP Request Handler
# ---------------------------------------------------------------------------


class _CTRequestHandler(BaseHTTPRequestHandler):
    """Handle RFC 6962 CT log API requests."""

    @property
    def _log(self) -> CommitmentLog:
        return self.server.commitment_log

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

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        routes = {
            "/ct/v1/get-sth": self._handle_get_sth,
            "/ct/v1/get-entries": self._handle_get_entries,
            "/ct/v1/get-proof-by-hash": self._handle_get_proof,
            "/ct/v1/get-sth-consistency": self._handle_get_consistency,
            "/ct/v1/get-entry-and-proof": self._handle_get_entry_and_proof,
        }

        handler = routes.get(path)
        if handler:
            try:
                handler()
            except Exception:
                import logging

                logging.getLogger(__name__).exception("CT handler error: %s", path)
                self._send_json(error_response(500, "internal error"), 500)
        else:
            self._send_json(error_response(404, f"Unknown endpoint: {path}"), 404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/ct/v1/add-entry":
            try:
                self._handle_add_entry()
            except Exception:
                import logging

                logging.getLogger(__name__).exception("CT handler error: %s", path)
                self._send_json(error_response(500, "internal error"), 500)
        else:
            self._send_json(error_response(404, f"Unknown endpoint: {path}"), 404)

    # --- Endpoint Handlers ---

    def _handle_get_sth(self) -> None:
        """GET /ct/v1/get-sth — Latest Signed Tree Head."""
        sth = self._log.latest_sth
        if sth is None:
            self._send_json(
                {
                    "tree_size": 0,
                    "timestamp": 0,
                    "root_hash": "",
                    "sequence": 0,
                }
            )
        else:
            self._send_json(sth_to_dict(sth))

    def _handle_get_entries(self) -> None:
        """GET /ct/v1/get-entries?start=N&end=M — Records in range."""
        params = self._parse_params()
        start = int(params.get("start", "0"))
        end = int(params.get("end", str(self._log.length)))

        if start < 0 or end > self._log.length or start > end:
            self._send_json(error_response(400, f"Invalid range: {start}..{end}"), 400)
            return

        entries = []
        for entity_id in self._log._chain[start:end]:
            record = self._log._records.get(entity_id)
            if record:
                entries.append(record_to_dict(record))

        self._send_json({"entries": entries, "start": start, "end": end})

    def _handle_get_proof(self) -> None:
        """GET /ct/v1/get-proof-by-hash?entity_id=X — Inclusion proof."""
        params = self._parse_params()
        entity_id = params.get("entity_id", "")

        if not entity_id:
            self._send_json(error_response(400, "Missing entity_id parameter"), 400)
            return

        proof = self._log.get_inclusion_proof(entity_id)
        if proof is None:
            self._send_json(error_response(404, f"Entity {entity_id[:32]}... not found"), 404)
            return

        self._send_json(proof_to_dict(proof))

    def _handle_get_consistency(self) -> None:
        """GET /ct/v1/get-sth-consistency?first=N&second=M — Consistency proof."""
        params = self._parse_params()
        first = int(params.get("first", "0"))
        second = int(params.get("second", str(self._log.length)))

        if first < 1 or second < first or second > self._log.length:
            self._send_json(error_response(400, f"Invalid sizes: {first}..{second}"), 400)
            return

        merkle_log = self._log._merkle_log
        proof_hashes = merkle_log._tree.consistency_proof(first)

        self._send_json(
            {
                "first": first,
                "second": second,
                "consistency": [h.hex() if isinstance(h, bytes) else str(h) for h in proof_hashes],
            }
        )

    def _handle_get_entry_and_proof(self) -> None:
        """GET /ct/v1/get-entry-and-proof?entity_id=X — Record + inclusion proof."""
        params = self._parse_params()
        entity_id = params.get("entity_id", "")

        if not entity_id:
            self._send_json(error_response(400, "Missing entity_id parameter"), 400)
            return

        record = self._log.fetch(entity_id)
        if record is None:
            self._send_json(error_response(404, f"Entity {entity_id[:32]}... not found"), 404)
            return

        proof = self._log.get_inclusion_proof(entity_id)
        self._send_json(
            {
                "entry": record_to_dict(record),
                "proof": proof_to_dict(proof) if proof else None,
            }
        )

    def _handle_add_entry(self) -> None:
        """POST /ct/v1/add-entry — Append a commitment record.

        Expects JSON body with at minimum an entity_id. In practice,
        entries are added via the protocol (commit phase), not directly.
        This endpoint exists for federation and external log operators.
        """
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            self._send_json(error_response(400, "Empty request body"), 400)
            return

        body = self.rfile.read(content_length)
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            self._send_json(error_response(400, "Invalid JSON"), 400)
            return

        # For now, return the current log state (full add-entry requires
        # a valid CommitmentRecord which is protocol-constructed)
        self._send_json(
            {
                "status": "received",
                "tree_size": self._log.length,
                "note": "Direct entry addition requires a valid CommitmentRecord. "
                "Use LTPProtocol.commit() for standard entry creation.",
            },
            200,
        )

    def log_message(self, format, *args):
        """Suppress default request logging."""
        pass


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------


class CommitmentLogRestServer:
    """
    RFC 6962-compatible REST server for the LTP Commitment Log.

    Runs in a background thread. Use start()/stop() for lifecycle management.

    Usage:
        log = CommitmentLog()
        server = CommitmentLogRestServer(log, port=8080)
        server.start()
        # GET http://localhost:8080/ct/v1/get-sth
        server.stop()
    """

    def __init__(self, commitment_log: CommitmentLog, host: str = "127.0.0.1", port: int = 8080):
        self.commitment_log = commitment_log
        self.host = host
        self.port = port
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start the REST server in a background thread."""
        self._server = HTTPServer((self.host, self.port), _CTRequestHandler)
        self._server.commitment_log = self.commitment_log
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the REST server."""
        if self._server:
            self._server.shutdown()
            self._server = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"
