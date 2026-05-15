"""Gateway status and health endpoints.

GET /gateway/status - Current gateway state (active, degraded, stopped)
GET /gateway/health - Liveness + readiness (K8s probe compatible)
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/gateway", tags=["gateway"])
logger = logging.getLogger(__name__)

_RETRY_QUEUE_DEGRADED_THRESHOLD = 10


def _internal_error(operation: str, exc: BaseException) -> JSONResponse:
    """Log the exception and return a redacted 500. Never echo to client."""
    logger.error("gateway handler %s failed: %s: %s", operation, type(exc).__name__, exc)
    return JSONResponse({"error": "internal error"}, status_code=500)


@router.get("/status")
async def gateway_status(request: Request) -> JSONResponse:
    """Current gateway operational status."""
    try:
        svc = request.app.state.gateway_service
        config = request.app.state.gateway_config
        tracker = request.app.state.gateway_tracker

        if not svc.running:
            status = "stopped"
        elif svc.retry_queue_size >= _RETRY_QUEUE_DEGRADED_THRESHOLD:
            status = "degraded"
        else:
            status = "active"

        return JSONResponse({
            "status": status,
            "gateway_id": config.gateway_id,
            "epoch": svc.epoch,
            "source_chain_id": config.source_chain_id,
            "dest_chain_id": config.dest_chain_id,
            "challenge_mode": config.challenge_mode,
            "retry_queue_size": svc.retry_queue_size,
            "tracker": tracker.stats(),
        })
    except Exception as exc:
        return _internal_error("gateway_status", exc)


@router.get("/health")
async def gateway_health(request: Request) -> JSONResponse:
    """K8s-compatible health probe."""
    try:
        svc = request.app.state.gateway_service

        checks = {
            "service": "running" if svc.running else "stopped",
            "retry_queue": "ok" if svc.retry_queue_size < _RETRY_QUEUE_DEGRADED_THRESHOLD else "degraded",
        }

        healthy = svc.running
        return JSONResponse(
            {"status": "ok" if healthy else "unhealthy", "checks": checks},
            status_code=200 if healthy else 503,
        )
    except Exception as exc:
        return _internal_error("gateway_health", exc)
