"""RFC 6962 CT log router — unauthenticated per spec."""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Body, Query, Request
from fastapi.responses import JSONResponse

from ..serializers import error_response, proof_to_dict, record_to_dict, sth_to_dict

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ct/v1", tags=["ct-log"])


def _get_log(request: Request):
    return request.app.state.commitment_log


@router.get("/get-sth")
async def get_sth(request: Request) -> JSONResponse:
    """Latest Signed Tree Head."""
    log = _get_log(request)
    if log is None:
        return JSONResponse(error_response(503, "commitment log not available"), 503)
    sth = log.latest_sth
    if sth is None:
        return JSONResponse({"tree_size": 0, "timestamp": 0, "root_hash": "", "sequence": 0})
    return JSONResponse(sth_to_dict(sth))


@router.get("/get-entries")
async def get_entries(
    request: Request,
    start: int = Query(0),
    end: int = Query(None),
) -> JSONResponse:
    """Records in range."""
    log = _get_log(request)
    if log is None:
        return JSONResponse(error_response(503, "commitment log not available"), 503)

    if end is None:
        end = log.length

    if start < 0 or end > log.length or start > end:
        return JSONResponse(error_response(400, f"Invalid range: {start}..{end}"), 400)

    entries = []
    for entity_id in log._chain[start:end]:
        record = log._records.get(entity_id)
        if record:
            entries.append(record_to_dict(record))

    return JSONResponse({"entries": entries, "start": start, "end": end})


@router.get("/get-proof-by-hash")
async def get_proof_by_hash(
    request: Request,
    entity_id: str = Query(None),
) -> JSONResponse:
    """Inclusion proof by entity_id."""
    log = _get_log(request)
    if log is None:
        return JSONResponse(error_response(503, "commitment log not available"), 503)

    if not entity_id:
        return JSONResponse(error_response(400, "Missing entity_id parameter"), 400)

    proof = log.get_inclusion_proof(entity_id)
    if proof is None:
        return JSONResponse(error_response(404, f"Entity {entity_id[:32]}... not found"), 404)

    return JSONResponse(proof_to_dict(proof))


@router.get("/get-sth-consistency")
async def get_sth_consistency(
    request: Request,
    first: int = Query(0),
    second: int = Query(None),
) -> JSONResponse:
    """Consistency proof between two tree sizes."""
    log = _get_log(request)
    if log is None:
        return JSONResponse(error_response(503, "commitment log not available"), 503)

    if second is None:
        second = log.length

    if first < 1 or second < first or second > log.length:
        return JSONResponse(error_response(400, f"Invalid sizes: {first}..{second}"), 400)

    merkle_log = log._merkle_log
    proof_hashes = merkle_log._tree.consistency_proof(first)

    return JSONResponse(
        {
            "first": first,
            "second": second,
            "consistency": [h.hex() if isinstance(h, bytes) else str(h) for h in proof_hashes],
        }
    )


@router.get("/get-entry-and-proof")
async def get_entry_and_proof(
    request: Request,
    entity_id: str = Query(None),
) -> JSONResponse:
    """Record + inclusion proof combined."""
    log = _get_log(request)
    if log is None:
        return JSONResponse(error_response(503, "commitment log not available"), 503)

    if not entity_id:
        return JSONResponse(error_response(400, "Missing entity_id parameter"), 400)

    record = log.fetch(entity_id)
    if record is None:
        return JSONResponse(error_response(404, f"Entity {entity_id[:32]}... not found"), 404)

    proof = log.get_inclusion_proof(entity_id)
    return JSONResponse(
        {
            "entry": record_to_dict(record),
            "proof": proof_to_dict(proof) if proof else None,
        }
    )


@router.post("/add-entry")
async def add_entry(request: Request) -> JSONResponse:
    """Direct entry append (federation / external log operators)."""
    log = _get_log(request)
    if log is None:
        return JSONResponse(error_response(503, "commitment log not available"), 503)

    try:
        body = await request.body()
        if not body:
            return JSONResponse(error_response(400, "Empty request body"), 400)
        data = json.loads(body)
    except json.JSONDecodeError:
        return JSONResponse(error_response(400, "Invalid JSON"), 400)

    return JSONResponse(
        {
            "status": "received",
            "tree_size": log.length,
            "note": "Direct entry addition requires a valid CommitmentRecord. "
            "Use LTPProtocol.commit() for standard entry creation.",
        }
    )
