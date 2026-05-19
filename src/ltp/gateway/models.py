"""
Pydantic request/response models for the ETP transfer API.

Binary data conventions:
  - content: base64-encoded (arbitrary payload)
  - keys, sealed_key, hashes: hex-encoded (cryptographic material)
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Commit (Phase 1)
# ---------------------------------------------------------------------------


class CommitRequest(BaseModel):
    """Request body for POST /v1/commit."""

    content: str = Field(..., description="Base64-encoded entity content")
    shape: str = Field(default="application/octet-stream", description="Media type")
    n: int = Field(default=0, ge=0, description="Total shards (0 = default)")
    k: int = Field(default=0, ge=0, description="Reconstruction threshold (0 = default)")


class CommitResponse(BaseModel):
    """Response body for POST /v1/commit."""

    success: bool
    entity_id: str = ""
    commitment_ref: str = ""
    cek_hex: str = Field(default="", description="Hex-encoded CEK (caller must store securely)")
    error: str = ""


# ---------------------------------------------------------------------------
# Lattice (Phase 2)
# ---------------------------------------------------------------------------


class LatticeRequest(BaseModel):
    """Request body for POST /v1/lattice."""

    entity_id: str = Field(..., description="Entity ID from commit phase")
    cek_hex: str = Field(..., description="Hex-encoded CEK from commit phase")
    receiver_ek_hex: str = Field(
        ..., description="Hex-encoded ML-KEM encapsulation key of receiver"
    )
    access_policy: dict = Field(default_factory=lambda: {"type": "unrestricted"})


class LatticeResponse(BaseModel):
    """Response body for POST /v1/lattice."""

    success: bool
    sealed_key_hex: str = Field(default="", description="Hex-encoded sealed lattice key")
    sealed_key_size: int = 0
    error: str = ""


# ---------------------------------------------------------------------------
# Materialize (Phase 3)
# ---------------------------------------------------------------------------


class MaterializeRequest(BaseModel):
    """Request body for POST /v1/materialize."""

    sealed_key_hex: str = Field(..., description="Hex-encoded sealed lattice key")


class MaterializeResponse(BaseModel):
    """Response body for POST /v1/materialize."""

    success: bool
    content: str = Field(default="", description="Base64-encoded entity content")
    entity_id: str = ""
    content_size: int = 0
    error: str = ""


# ---------------------------------------------------------------------------
# Transfer Sessions
# ---------------------------------------------------------------------------


class TransferSessionResponse(BaseModel):
    """Single transfer session."""

    entity_id: str
    state: str
    started_at: float
    phase_started_at: float
    retry_count: int
    error: str
    elapsed_seconds: float


class TransferListResponse(BaseModel):
    """List of transfer sessions."""

    count: int
    sessions: list[TransferSessionResponse]
