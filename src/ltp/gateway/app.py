"""
ETP API Gateway — FastAPI application factory and server.

Consolidates health, CT log, anchor, diagnostics, and (future) operational
endpoints behind a single production-grade HTTP server.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time as _time
from dataclasses import dataclass, field
from typing import Callable, Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .auth import JWTClaims, verify_jwt
from .middleware import RateLimiter

logger = logging.getLogger(__name__)


@dataclass
class GatewayConfig:
    """Configuration for the API gateway."""

    host: str = "0.0.0.0"
    port: int = 8080
    log_level: str = "info"
    # Auth
    jwt_enabled: bool = False
    jwt_token_ttl_seconds: int = 3600
    # Rate limiting
    rate_limit_enabled: bool = False
    rate_limit_per_minute: int = 60


def create_app(config: Optional[GatewayConfig] = None) -> FastAPI:
    """Create the FastAPI application with all routers mounted."""
    if config is None:
        config = GatewayConfig()

    app = FastAPI(
        title="ETP API Gateway",
        description="Entanglement Transfer Protocol — unified REST API",
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
    )

    # Store config and subsystem references on app.state
    app.state.config = config
    app.state.health_fn = None
    app.state.commitment_log = None
    app.state.anchor_tracker = None
    app.state.anchor_scheduler = None
    app.state.anchor_verifier = None
    app.state.peer_manager = None
    app.state.commitment_network = None
    app.state.protocol = None
    app.state.audit_scheduler = None
    app.state.commitment_node = None
    app.state.public_mode = False
    app.state.keypair = None
    app.state.known_vks = {}
    app.state.key_registry = None
    app.state.rate_limiter = None
    app.state.observability = None

    if config.rate_limit_enabled:
        app.state.rate_limiter = RateLimiter(config.rate_limit_per_minute)

    # --- Middleware ---

    @app.middleware("http")
    async def auth_and_rate_limit(request: Request, call_next):
        path = request.url.path

        # Unauthenticated paths: health, CT log, metrics, federation (own auth)
        unauthenticated = (
            path == "/health"
            or path.startswith("/ct/v1/")
            or path == "/metrics"
            or path.startswith("/federation/v1/")
        )

        caller_id = "anonymous"

        if config.jwt_enabled and not unauthenticated:
            auth_header = request.headers.get("authorization", "")
            if not auth_header.startswith("Bearer "):
                return JSONResponse(
                    {"error": "Missing or invalid Authorization header"},
                    status_code=401,
                )
            token = auth_header[7:]
            claims = verify_jwt(
                token,
                key_registry=app.state.key_registry,
                known_vks=app.state.known_vks,
            )
            if claims is None:
                return JSONResponse(
                    {"error": "Invalid or expired token"},
                    status_code=401,
                )
            request.state.jwt_claims = claims
            caller_id = claims.sub

        # Rate limiting
        if app.state.rate_limiter is not None:
            if not app.state.rate_limiter.allow(caller_id):
                return JSONResponse(
                    {"error": "Rate limit exceeded"},
                    status_code=429,
                )

        response = await call_next(request)
        return response

    # --- Routers ---
    from .routers.anchor import router as anchor_router
    from .routers.ct_log import router as ct_log_router
    from .routers.diagnostics import router as diagnostics_router
    from .routers.federation import router as federation_router
    from .routers.health import router as health_router
    from .routers.metrics import router as metrics_router
    from .routers.transfers import router as transfers_router

    app.include_router(health_router)
    app.include_router(ct_log_router)
    app.include_router(anchor_router)
    app.include_router(diagnostics_router)
    app.include_router(transfers_router)
    app.include_router(federation_router)
    app.include_router(metrics_router)

    # Catch-all for unknown endpoints
    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
    async def catch_all(request: Request, path: str):
        return JSONResponse(
            {"error": f"Unknown endpoint: /{path}", "code": 404},
            status_code=404,
        )

    return app


class GatewayServer:
    """Production-grade HTTP server wrapping FastAPI + Uvicorn.

    Runs in a daemon thread matching the existing ETP server pattern.
    Supports port=0 for ephemeral port allocation in tests.
    """

    def __init__(
        self,
        config: Optional[GatewayConfig] = None,
        health_fn: Optional[Callable[[], dict]] = None,
        commitment_log=None,
        anchor_tracker=None,
        anchor_scheduler=None,
        anchor_verifier=None,
        peer_manager=None,
        commitment_network=None,
        protocol=None,
        audit_scheduler=None,
        commitment_node=None,
        public_mode: bool = False,
        keypair=None,
        key_registry=None,
    ) -> None:
        self._config = config or GatewayConfig()
        self._app = create_app(self._config)

        # Wire subsystem references
        self._app.state.health_fn = health_fn
        self._app.state.commitment_log = commitment_log
        self._app.state.anchor_tracker = anchor_tracker
        self._app.state.anchor_scheduler = anchor_scheduler
        self._app.state.anchor_verifier = anchor_verifier
        self._app.state.peer_manager = peer_manager
        self._app.state.commitment_network = commitment_network
        self._app.state.protocol = protocol
        self._app.state.audit_scheduler = audit_scheduler
        self._app.state.commitment_node = commitment_node
        self._app.state.public_mode = public_mode
        self._app.state.keypair = keypair
        self._app.state.key_registry = key_registry

        # Build known_vks from keypair for self-issued token verification
        if keypair is not None:
            from ..domain import signer_fingerprint

            kid = signer_fingerprint(keypair.vk).hex()
            self._app.state.known_vks[kid] = keypair.vk

        self._thread: Optional[threading.Thread] = None
        self._server = None
        self._started = threading.Event()
        self._actual_port: Optional[int] = None

    @property
    def app(self) -> FastAPI:
        return self._app

    @property
    def port(self) -> int:
        if self._actual_port is not None:
            return self._actual_port
        return self._config.port

    @property
    def url(self) -> str:
        return f"http://{self._config.host}:{self.port}"

    def start(self) -> None:
        """Start the gateway in a daemon thread."""
        import uvicorn

        uvi_config = uvicorn.Config(
            app=self._app,
            host=self._config.host,
            port=self._config.port,
            log_level=self._config.log_level,
            access_log=False,
        )
        self._server = uvicorn.Server(uvi_config)

        def _run():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            # Capture actual port after socket bind
            original_startup = self._server.startup

            async def _patched_startup(sockets=None):
                await original_startup(sockets=sockets)
                # Extract bound port from server sockets
                if self._server.servers:
                    for server in self._server.servers:
                        for sock in server.sockets:
                            addr = sock.getsockname()
                            if isinstance(addr, tuple) and len(addr) >= 2:
                                self._actual_port = addr[1]
                                break
                        if self._actual_port:
                            break
                self._started.set()

            self._server.startup = _patched_startup
            loop.run_until_complete(self._server.serve())

        self._thread = threading.Thread(target=_run, daemon=True, name="etp-gateway")
        self._thread.start()
        self._started.wait(timeout=10.0)
        if not self._started.is_set():
            raise RuntimeError("Gateway server failed to start within 10s")
        logger.info("Gateway started on %s:%d", self._config.host, self.port)

    def stop(self) -> None:
        """Stop the gateway server."""
        if self._server:
            self._server.should_exit = True
        if self._thread:
            self._thread.join(timeout=5.0)
            self._thread = None
        self._server = None
        logger.info("Gateway stopped")
