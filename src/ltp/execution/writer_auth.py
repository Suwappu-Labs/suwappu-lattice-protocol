"""WriterAuthorizer protocol — custom VM override (Spec C2 §7)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional, Protocol, runtime_checkable

from .types import OperationType
from .writer import WriterRecord, WriterState

__all__ = ["AuthorizationResult", "DispatchDecision", "WriterAuthorizer"]


@dataclass(frozen=True)
class AuthorizationResult:
    """Result from a custom VM WriterAuthorizer."""

    allowed: bool
    reason: Optional[str] = None
    fee_multiplier: float = 1.0
    metadata: Optional[dict[str, Any]] = None


@dataclass(frozen=True)
class DispatchDecision:
    """Result from the WriterGate dispatch check."""

    allowed: bool
    reason: Optional[str] = None
    fee_multiplier: float = 1.0
    writer_record: Optional[WriterRecord] = None


@runtime_checkable
class WriterAuthorizer(Protocol):
    def authorize_writer(
        self,
        writer: WriterRecord,
        operation: OperationType,
        tx_bytes: bytes,
    ) -> AuthorizationResult: ...

    def on_writer_state_change(
        self,
        writer: WriterRecord,
        old_state: WriterState,
        new_state: WriterState,
    ) -> None: ...
