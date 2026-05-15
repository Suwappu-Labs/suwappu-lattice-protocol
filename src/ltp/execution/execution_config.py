"""Execution pipeline configuration (Spec D1c §2)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ExecutionConfig:
    """Configuration for the execution pipeline."""

    failure_threshold_pct: float = 50.0
    halt_on_catastrophic: bool = True
    failure_window: int = 100
    attestation_mode: str = "dual"  # "dual" | "bls_only" | "mldsa_only"
