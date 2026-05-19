"""
ETP API Gateway — FastAPI-based unified REST layer.

Consolidates health, CT log, anchor status, diagnostics, and operational
endpoints behind a single production-grade HTTP server with ML-DSA-65
JWT authentication and rate limiting.
"""

from __future__ import annotations

__all__ = ["GatewayServer", "GatewayConfig"]


def __getattr__(name: str):
    if name == "GatewayServer":
        from .app import GatewayServer

        return GatewayServer
    if name == "GatewayConfig":
        from .app import GatewayConfig

        return GatewayConfig
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
