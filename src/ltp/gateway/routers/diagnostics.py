"""Node diagnostics router — JWT protected."""

from __future__ import annotations

import logging
import time as _time

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse

from ..serializers import (
    error_response,
    peer_to_dict,
    session_to_dict,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/node", tags=["diagnostics"])


# ---------------------------------------------------------------------------
# Peers
# ---------------------------------------------------------------------------


@router.get("/peers")
async def list_peers(request: Request) -> JSONResponse:
    pm = request.app.state.peer_manager
    if pm is None:
        return JSONResponse(error_response(503, "peer manager not available"), 503)

    public = request.app.state.public_mode
    connected = pm.get_connected_peers()
    return JSONResponse(
        {
            "count": len(connected),
            "peers": [peer_to_dict(p, public) for p in connected],
        }
    )


@router.get("/peers/{node_id}")
async def get_peer(request: Request, node_id: str) -> JSONResponse:
    pm = request.app.state.peer_manager
    if pm is None:
        return JSONResponse(error_response(503, "peer manager not available"), 503)

    peer = pm.get_peer_by_id(node_id)
    if peer is None:
        return JSONResponse(error_response(404, f"Peer {node_id} not found"), 404)

    return JSONResponse(peer_to_dict(peer, request.app.state.public_mode))


# ---------------------------------------------------------------------------
# Transfers
# ---------------------------------------------------------------------------


@router.get("/transfers")
async def list_transfers(
    request: Request,
    state: str = Query(None),
) -> JSONResponse:
    protocol = request.app.state.protocol
    if protocol is None:
        return JSONResponse(error_response(503, "protocol not available"), 503)

    if state:
        from src.ltp.protocol import TransferState

        try:
            filter_state = TransferState[state.upper()]
        except KeyError:
            valid = [s.name for s in TransferState]
            return JSONResponse(error_response(400, f"Invalid state: {state}. Valid: {valid}"), 400)
        sessions = protocol.list_sessions(state=filter_state)
    else:
        sessions = protocol.list_sessions()

    return JSONResponse(
        {
            "count": len(sessions),
            "sessions": [session_to_dict(s) for s in sessions],
        }
    )


@router.get("/transfers/{entity_id}")
async def get_transfer(request: Request, entity_id: str) -> JSONResponse:
    protocol = request.app.state.protocol
    if protocol is None:
        return JSONResponse(error_response(503, "protocol not available"), 503)

    session = protocol.get_session(entity_id)
    if session is None:
        return JSONResponse(error_response(404, f"Session {entity_id[:32]}... not found"), 404)

    return JSONResponse(session_to_dict(session))


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


@router.get("/audit")
async def audit_status(request: Request) -> JSONResponse:
    scheduler = request.app.state.audit_scheduler
    if scheduler is None:
        return JSONResponse({"running": False, "epoch": 0})

    return JSONResponse(
        {
            "running": getattr(scheduler, "running", False),
            "epoch": getattr(scheduler, "epoch", 0),
        }
    )


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------


@router.get("/network")
async def network_summary(request: Request) -> JSONResponse:
    cn = request.app.state.commitment_network
    if cn is None:
        return JSONResponse(error_response(503, "commitment network not available"), 503)

    nodes = cn.nodes if hasattr(cn, "nodes") else {}
    return JSONResponse(
        {
            "node_count": len(nodes),
            "nodes": list(nodes.keys()) if isinstance(nodes, dict) else [str(n) for n in nodes],
        }
    )


@router.get("/network/nodes/{node_id}")
async def get_network_node(request: Request, node_id: str) -> JSONResponse:
    cn = request.app.state.commitment_network
    if cn is None:
        return JSONResponse(error_response(503, "commitment network not available"), 503)

    nodes = cn.nodes if hasattr(cn, "nodes") else {}
    node = nodes.get(node_id) if isinstance(nodes, dict) else None
    if node is None:
        return JSONResponse(error_response(404, f"Node {node_id} not found"), 404)

    # Serialize node metadata
    if hasattr(node, "__dict__"):
        d = {k: v for k, v in node.__dict__.items() if not k.startswith("_")}
        # Convert non-serializable fields
        for k, v in list(d.items()):
            if isinstance(v, bytes):
                d[k] = v.hex()
            elif not isinstance(v, (str, int, float, bool, type(None), list, dict)):
                d[k] = str(v)
    else:
        d = {"node_id": node_id, "data": str(node)}

    return JSONResponse(d)


@router.get("/network/endowment")
async def get_endowment(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
) -> JSONResponse:
    cn = request.app.state.commitment_network
    if cn is None:
        return JSONResponse(error_response(503, "commitment network not available"), 503)

    inner = cn._inner if hasattr(cn, "_inner") else cn
    balance = getattr(inner, "_endowment_balance", 0.0)
    history = getattr(inner, "_burn_history", [])

    return JSONResponse(
        {
            "balance": balance,
            "burn_count": len(history),
            "burns": [
                {
                    "timestamp": b.get("timestamp", 0),
                    "amount": b.get("amount", 0),
                    "entity_id": b.get("entity_id", ""),
                    "reason": b.get("reason", ""),
                }
                for b in history[-limit:]
            ],
        }
    )


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------


@router.get("/storage")
async def storage_metrics(request: Request) -> JSONResponse:
    node = request.app.state.commitment_node
    if node is None:
        return JSONResponse(error_response(503, "commitment node not available"), 503)

    store = getattr(node, "shard_store", None) or getattr(node, "_store", None)
    if store is None:
        return JSONResponse({"shard_count": 0, "backend": "unknown"})

    count = len(store) if hasattr(store, "__len__") else 0
    backend = type(store).__name__
    return JSONResponse({"shard_count": count, "backend": backend})


# ---------------------------------------------------------------------------
# Log
# ---------------------------------------------------------------------------


@router.get("/log")
async def log_summary(request: Request) -> JSONResponse:
    log = request.app.state.commitment_log
    if log is None:
        return JSONResponse(error_response(503, "commitment log not available"), 503)

    sth = log.latest_sth
    sth_age = None
    if sth and sth.timestamp:
        sth_age = round(_time.time() - sth.timestamp, 3)

    return JSONResponse(
        {
            "length": log.length,
            "sth_age_seconds": sth_age,
            "has_sth": sth is not None,
        }
    )
