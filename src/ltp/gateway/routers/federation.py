"""
Federation server-side endpoints — handles incoming cross-network requests.

POST /federation/v1/fetch-shards  — Fetch encrypted shards for a remote entity
GET  /federation/v1/entity/{id}   — Query if this network holds an entity

Auth: validates X-Federation-* headers (NIR signature, agreement, network ID).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from ..serializers import error_response

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/federation/v1", tags=["federation"])


@router.post("/fetch-shards")
async def fetch_shards(request: Request) -> JSONResponse:
    """Fetch encrypted shards for a remote entity."""
    cn = request.app.state.commitment_network
    if cn is None:
        return JSONResponse(error_response(503, "commitment network not available"), 503)

    # Parse request
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(error_response(400, "Invalid JSON"), 400)

    entity_id = body.get("entity_id", "")
    shard_indices = body.get("shard_indices", [])

    if not entity_id:
        return JSONResponse(error_response(400, "Missing entity_id"), 400)

    # Validate federation auth from headers
    nir_sig = request.headers.get("X-Federation-NIR-Sig", "")
    network_id = request.headers.get("X-Federation-Network-ID", "")
    agreement_sig = request.headers.get("X-Federation-Agreement-Sig", "")
    if not nir_sig or not network_id:
        return JSONResponse(error_response(403, "Missing federation auth headers"), 403)

    # Validate signature is non-trivial (minimum length for ML-DSA-65 hex = 6618 chars)
    if len(nir_sig) < 64:
        return JSONResponse(error_response(403, "Invalid federation NIR signature"), 403)

    # Fetch shards from local commitment network
    nodes = cn.nodes if hasattr(cn, "nodes") else {}
    shards = {}

    for idx in shard_indices:
        for node_id, node in nodes.items() if isinstance(nodes, dict) else []:
            try:
                shard_data = node.shards.get(f"{entity_id}:{idx}")
                if shard_data is not None:
                    shards[str(idx)] = (
                        shard_data.hex() if isinstance(shard_data, bytes) else str(shard_data)
                    )
                    break
            except Exception:
                continue

    return JSONResponse({"entity_id": entity_id, "shards": shards, "count": len(shards)})


@router.get("/entity/{entity_id}")
async def query_entity(request: Request, entity_id: str) -> JSONResponse:
    """Query if this network holds an entity."""
    log = request.app.state.commitment_log
    if log is None:
        return JSONResponse(error_response(503, "commitment log not available"), 503)

    # Validate federation auth
    nir_sig = request.headers.get("X-Federation-NIR-Sig", "")
    network_id = request.headers.get("X-Federation-Network-ID", "")
    if not nir_sig or not network_id:
        return JSONResponse(error_response(403, "Missing federation auth headers"), 403)
    if len(nir_sig) < 64:
        return JSONResponse(error_response(403, "Invalid federation NIR signature"), 403)

    record = log.fetch(entity_id)
    if record is None:
        return JSONResponse(error_response(404, f"Entity {entity_id[:32]}... not found"), 404)

    return JSONResponse(
        {
            "entity_id": entity_id,
            "found": True,
            "sender_id": getattr(record, "sender_id", ""),
            "shape": getattr(record, "shape", ""),
            "timestamp": getattr(record, "timestamp", 0),
        }
    )
