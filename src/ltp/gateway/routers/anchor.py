"""Anchor subsystem status router — JWT protected."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from ..serializers import error_response

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/anchor", tags=["anchor"])


@router.get("/stats")
async def anchor_stats(request: Request) -> JSONResponse:
    """Aggregate anchor counts + scheduler/verifier metadata."""
    tracker = request.app.state.anchor_tracker
    if tracker is None:
        return JSONResponse(error_response(503, "anchor subsystem not available"), 503)

    counts = {}
    for status_name in ("PENDING", "SUBMITTED", "CONFIRMED", "FINALIZED", "FAILED"):
        entries = tracker.get_by_status(status_name)
        counts[status_name.lower()] = len(entries) if entries else 0

    result = {"counts": counts, "total": sum(counts.values())}

    scheduler = request.app.state.anchor_scheduler
    if scheduler:
        result["scheduler_epoch"] = getattr(scheduler, "epoch", 0)
        result["scheduler_running"] = getattr(scheduler, "running", False)

    verifier = request.app.state.anchor_verifier
    if verifier:
        result["verifier_running"] = getattr(verifier, "running", False)

    return JSONResponse(result)


@router.get("/by-status")
async def anchor_by_status(
    request: Request,
    status: str = Query(""),
) -> JSONResponse:
    """Filter anchors by status."""
    tracker = request.app.state.anchor_tracker
    if tracker is None:
        return JSONResponse(error_response(503, "anchor subsystem not available"), 503)

    if not status:
        return JSONResponse(error_response(400, "Missing status parameter"), 400)

    entries = tracker.get_by_status(status.upper())
    if entries is None:
        return JSONResponse(error_response(400, f"Invalid status: {status}"), 400)

    results = []
    for entry in entries:
        d = entry.to_dict() if hasattr(entry, "to_dict") else {"entity_id": str(entry)}
        results.append(d)

    return JSONResponse({"status": status.upper(), "count": len(results), "entries": results})


@router.get("/health")
async def anchor_health(request: Request) -> JSONResponse:
    """Anchor subsystem health."""
    scheduler = request.app.state.anchor_scheduler
    verifier = request.app.state.anchor_verifier

    return JSONResponse(
        {
            "scheduler_running": getattr(scheduler, "running", None) if scheduler else None,
            "verifier_running": getattr(verifier, "running", None) if verifier else None,
        }
    )


@router.get("/status/{entity_id}")
async def anchor_status(request: Request, entity_id: str) -> JSONResponse:
    """Single entity anchor status lookup."""
    tracker = request.app.state.anchor_tracker
    if tracker is None:
        return JSONResponse(error_response(503, "anchor subsystem not available"), 503)

    entry = tracker.get(entity_id)
    if entry is None:
        return JSONResponse(error_response(404, f"Entity {entity_id[:32]}... not found"), 404)

    d = (
        entry.to_dict()
        if hasattr(entry, "to_dict")
        else {"entity_id": entity_id, "status": str(entry)}
    )
    return JSONResponse(d)
