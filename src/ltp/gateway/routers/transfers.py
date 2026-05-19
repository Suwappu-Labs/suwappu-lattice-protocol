"""
REST operational endpoints for the three-phase transfer lifecycle.

POST /v1/commit      — Phase 1: COMMIT
POST /v1/lattice     — Phase 2: LATTICE
POST /v1/materialize — Phase 3: MATERIALIZE
GET  /v1/transfers   — List transfer sessions
GET  /v1/transfers/{entity_id} — Single session lookup

All routes require JWT authentication.
"""

from __future__ import annotations

import base64
import logging

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse

from ..models import (
    CommitRequest,
    CommitResponse,
    LatticeRequest,
    LatticeResponse,
    MaterializeRequest,
    MaterializeResponse,
)
from ..serializers import error_response, session_to_dict

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["transfers"])


@router.post("/commit", response_model=CommitResponse)
async def commit_entity(req: CommitRequest, request: Request):
    """PHASE 1: COMMIT — Erasure-encode, encrypt, distribute, sign."""
    protocol = request.app.state.protocol
    keypair = request.app.state.keypair
    if protocol is None or keypair is None:
        return JSONResponse(
            CommitResponse(success=False, error="protocol not available").model_dump(),
            status_code=503,
        )

    # Decode base64 content
    try:
        content = base64.b64decode(req.content)
    except Exception:
        return JSONResponse(
            CommitResponse(success=False, error="Invalid base64 content").model_dump(),
            status_code=400,
        )

    if len(content) == 0:
        return JSONResponse(
            CommitResponse(success=False, error="Empty content").model_dump(),
            status_code=400,
        )

    # Enforce maximum entity content size (100 MiB)
    if len(content) > 100 * 1024 * 1024:
        return JSONResponse(
            CommitResponse(
                success=False, error="Content exceeds maximum size (100 MiB)"
            ).model_dump(),
            status_code=413,
        )

    # Build Entity
    from src.ltp.entity import Entity

    entity = Entity(content=content, shape=req.shape)

    n = req.n if req.n > 0 else None
    k = req.k if req.k > 0 else None

    try:
        entity_id, record, cek = protocol.commit(entity, keypair, n=n, k=k)
    except Exception as e:
        logger.exception("Commit failed")
        return JSONResponse(
            CommitResponse(success=False, error="internal error").model_dump(),
            status_code=500,
        )

    # Register session so lattice can retrieve CEK
    import time as _time

    from src.ltp.protocol import TransferSession, TransferState

    with protocol._session_lock:
        session = TransferSession(
            entity_id=entity_id,
            state=TransferState.COMMITTED,
            started_at=_time.time(),
            phase_started_at=_time.time(),
            cek=cek,
        )
        protocol._sessions[entity_id] = session

    from src.ltp.primitives import canonical_hash

    commitment_ref = canonical_hash(record.to_bytes())

    return CommitResponse(
        success=True,
        entity_id=entity_id,
        commitment_ref=commitment_ref,
        cek_hex=cek.hex(),
    )


@router.post("/lattice", response_model=LatticeResponse)
async def lattice_seal(req: LatticeRequest, request: Request):
    """PHASE 2: LATTICE — Seal minimal key via ML-KEM-768 to receiver."""
    protocol = request.app.state.protocol
    keypair = request.app.state.keypair
    if protocol is None:
        return JSONResponse(
            LatticeResponse(success=False, error="protocol not available").model_dump(),
            status_code=503,
        )

    # Look up commitment record from log
    record = protocol.network.log.fetch(req.entity_id)
    if record is None:
        return JSONResponse(
            LatticeResponse(
                success=False, error=f"Entity {req.entity_id[:32]}... not found in log"
            ).model_dump(),
            status_code=404,
        )

    # Decode CEK
    try:
        cek = bytes.fromhex(req.cek_hex)
    except ValueError:
        return JSONResponse(
            LatticeResponse(success=False, error="Invalid hex in cek_hex").model_dump(),
            status_code=400,
        )

    # Decode receiver encapsulation key
    try:
        receiver_ek = bytes.fromhex(req.receiver_ek_hex)
    except ValueError:
        return JSONResponse(
            LatticeResponse(success=False, error="Invalid hex in receiver_ek_hex").model_dump(),
            status_code=400,
        )

    # Build a receiver keypair stub with only the ek (for sealing)
    from src.ltp.keypair import KeyPair

    receiver_kp = KeyPair(ek=receiver_ek, dk=b"", vk=b"", sk=b"", label="rest-receiver")

    try:
        sealed = protocol.lattice(
            entity_id=req.entity_id,
            record=record,
            cek=cek,
            receiver_keypair=receiver_kp,
            access_policy=req.access_policy,
        )
    except Exception as e:
        logger.exception("Lattice failed")
        return JSONResponse(
            LatticeResponse(success=False, error="internal error").model_dump(),
            status_code=500,
        )

    # Update session state
    session = protocol.get_session(req.entity_id)
    if session is not None:
        from src.ltp.protocol import TransferState

        session.sealed_key = sealed
        session.transition(TransferState.SEALED)

    return LatticeResponse(
        success=True,
        sealed_key_hex=sealed.hex(),
        sealed_key_size=len(sealed),
    )


@router.post("/materialize", response_model=MaterializeResponse)
async def materialize_entity(req: MaterializeRequest, request: Request):
    """PHASE 3: MATERIALIZE — Unseal, verify, fetch, decrypt, reconstruct."""
    protocol = request.app.state.protocol
    keypair = request.app.state.keypair
    if protocol is None or keypair is None:
        return JSONResponse(
            MaterializeResponse(success=False, error="protocol not available").model_dump(),
            status_code=503,
        )

    # Decode sealed key
    try:
        sealed_key = bytes.fromhex(req.sealed_key_hex)
    except ValueError:
        return JSONResponse(
            MaterializeResponse(success=False, error="Invalid hex in sealed_key_hex").model_dump(),
            status_code=400,
        )

    try:
        content = protocol.materialize(sealed_key, keypair)
    except Exception as e:
        logger.exception("Materialize failed")
        return JSONResponse(
            MaterializeResponse(success=False, error="internal error").model_dump(),
            status_code=500,
        )

    if content is None:
        return JSONResponse(
            MaterializeResponse(
                success=False, error="Materialization failed (unseal, verify, or reconstruct error)"
            ).model_dump(),
            status_code=422,
        )

    content_b64 = base64.b64encode(content).decode("ascii")

    return MaterializeResponse(
        success=True,
        content=content_b64,
        entity_id="",  # Could be extracted from lattice key, but not trivially available here
        content_size=len(content),
    )


# ---------------------------------------------------------------------------
# Session listing
# ---------------------------------------------------------------------------


@router.get("/transfers")
async def list_transfers(
    request: Request,
    state: str = Query(None),
):
    """List transfer sessions, optionally filtered by state."""
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
async def get_transfer(request: Request, entity_id: str):
    """Single transfer session lookup."""
    protocol = request.app.state.protocol
    if protocol is None:
        return JSONResponse(error_response(503, "protocol not available"), 503)

    session = protocol.get_session(entity_id)
    if session is None:
        return JSONResponse(error_response(404, f"Session {entity_id[:32]}... not found"), 404)

    return JSONResponse(session_to_dict(session))
