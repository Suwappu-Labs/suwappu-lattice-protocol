"""FastAPI application factory for the Gateway VM.

create_app() takes pre-constructed dependencies (no env/RPC knowledge).
Production wiring lives in __main__.py. Tests inject mocks.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from .config import GatewayVMConfig
from .middleware import (
    BodySizeLimitMiddleware,
    JWTAuthMiddleware,
    RateLimitMiddleware,
)
from .routers.events import router as events_router
from .routers.status import router as status_router
from .service import GatewayVMService
from .tracker import GatewayTracker


def create_app(
    config: GatewayVMConfig,
    service: GatewayVMService,
    tracker: GatewayTracker,
) -> FastAPI:
    """Create the Gateway VM FastAPI application.

    Mounts the status and events routers, wires app.state for
    dependency injection, and registers a lifespan that starts
    the service on boot and stops it on shutdown.
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.gateway_service.start()
        try:
            yield
        finally:
            app.state.gateway_service.stop()

    app = FastAPI(
        title="ETP Gateway VM",
        version="1.0.0",
        lifespan=lifespan,
    )

    app.state.gateway_service = service
    app.state.gateway_config = config
    app.state.gateway_tracker = tracker

    # Hardening middleware (LTP-A-010 / -011 in
    # docs/security/audits/internal/SECURITY_AUDIT_2026-05-15.md). Order matters: body size first
    # (cheapest), then rate limit, then JWT (most expensive). Starlette
    # runs them in reverse-add order so the last added is outermost.
    app.add_middleware(JWTAuthMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(BodySizeLimitMiddleware)

    app.include_router(status_router)
    app.include_router(events_router)

    return app
