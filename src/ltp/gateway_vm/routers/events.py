"""Gateway event query endpoints.

GET /gateway/events?status=X - List processed events by status
GET /gateway/events/{tx_hash} - Single event lookup by submission tx hash
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/gateway", tags=["gateway"])
logger = logging.getLogger(__name__)


def _serialize_record(rec: dict) -> dict:
    """Convert internal record to JSON-safe dict."""
    out = dict(rec)
    if isinstance(out.get("digest"), bytes):
        out["digest"] = out["digest"].hex()
    return out


def _internal_error(operation: str, exc: BaseException) -> JSONResponse:
    """Log the exception and return a redacted 500.

    Never echoes the exception message to the client - that would leak
    schema, stack, or implementation details to an unauthenticated caller.
    """
    logger.error("gateway handler %s failed: %s: %s", operation, type(exc).__name__, exc)
    return JSONResponse({"error": "internal error"}, status_code=500)


@router.get("/events")
async def list_events(
    request: Request,
    status: Optional[str] = Query(None, description="Filter by status"),
) -> JSONResponse:
    """List gateway-processed events, optionally filtered by status."""
    try:
        tracker = request.app.state.gateway_tracker

        if status:
            events = tracker.get_by_status(status)
        else:
            events = []
            for s in ("pending", "submitted", "confirmed", "finalized", "failed"):
                events.extend(tracker.get_by_status(s))

        return JSONResponse({
            "events": [_serialize_record(e) for e in events],
            "count": len(events),
        })
    except Exception as exc:
        return _internal_error("list_events", exc)


@router.get("/events/{tx_hash}")
async def lookup_event(request: Request, tx_hash: str) -> JSONResponse:
    """Look up a single event by its submission transaction hash."""
    try:
        tracker = request.app.state.gateway_tracker
        rec = tracker.lookup_by_tx_hash(tx_hash)
        if rec is None:
            # LTP-A-027: do not echo the user-controlled tx_hash back in the
            # response body; an attacker would use error messages to
            # fingerprint internal data. Log it server-side for ops.
            logger.info("lookup_event miss tx_hash=%s", tx_hash)
            return JSONResponse(
                {"error": "event not found"},
                status_code=404,
            )
        return JSONResponse(_serialize_record(rec))
    except Exception as exc:
        return _internal_error("lookup_event", exc)
