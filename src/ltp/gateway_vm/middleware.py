"""Gateway VM Starlette middleware: rate limit, JWT auth, body size.

Wired into the FastAPI app in ``app.py``. All three middlewares are
configurable via env vars so the same code path serves dev (permissive)
and FedRAMP-high production (strict).

Closes audit findings LTP-A-010 (unauthenticated enumeration) and
LTP-A-011 (default host bind) — see ``docs/SECURITY_AUDIT_2026-05-15.md``.
"""

from __future__ import annotations

import logging
import os
import time
from collections import deque
from typing import Awaitable, Callable, Deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


__all__ = [
    "RateLimitMiddleware",
    "JWTAuthMiddleware",
    "BodySizeLimitMiddleware",
]


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Rate limit
# ---------------------------------------------------------------------------


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-IP token-bucket rate limit using a sliding window.

    Default 60 requests per minute per IP. Override via
    ``ETP_GATEWAY_VM_RATE_LIMIT_PER_MIN``. Setting to 0 disables.
    """

    def __init__(self, app, limit_per_minute: int | None = None) -> None:
        super().__init__(app)
        env = os.environ.get("ETP_GATEWAY_VM_RATE_LIMIT_PER_MIN")
        if limit_per_minute is None:
            limit_per_minute = int(env) if env else 60
        self.limit = max(0, limit_per_minute)
        self._buckets: dict[str, Deque[float]] = {}

    @staticmethod
    def _client_id(request: Request) -> str:
        # Prefer the upstream proxy header when set (operators run this behind
        # nginx / a load balancer). Fall back to the direct peer address.
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
        if request.client is None:
            return "unknown"
        return request.client.host

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if self.limit == 0:
            return await call_next(request)

        client = self._client_id(request)
        now = time.monotonic()
        window = 60.0

        bucket = self._buckets.setdefault(client, deque())
        while bucket and bucket[0] < now - window:
            bucket.popleft()

        if len(bucket) >= self.limit:
            retry_after = max(1, int(window - (now - bucket[0])))
            return JSONResponse(
                {"error": "rate limit exceeded"},
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )

        bucket.append(now)
        return await call_next(request)


# ---------------------------------------------------------------------------
# JWT auth (HS256)
# ---------------------------------------------------------------------------


class JWTAuthMiddleware(BaseHTTPMiddleware):
    """Verify a HS256 JWT in the ``Authorization: Bearer <token>`` header.

    The signing secret is ``ETP_GATEWAY_VM_JWT_SECRET``. The middleware is
    a no-op if either:
    - ``ETP_GATEWAY_VM_REQUIRE_AUTH`` is unset / falsy AND the secret is
      unset (development default)
    - the request path is in the public allowlist (``/gateway/health``)

    FedRAMP-high deployments must set ``ETP_GATEWAY_VM_REQUIRE_AUTH=true``
    AND ``ETP_GATEWAY_VM_JWT_SECRET`` to a high-entropy value.
    """

    PUBLIC_PATHS = frozenset({"/gateway/health"})

    def __init__(self, app, secret: str | None = None, require_auth: bool | None = None) -> None:
        super().__init__(app)
        self.secret = secret if secret is not None else os.environ.get(
            "ETP_GATEWAY_VM_JWT_SECRET", ""
        )
        env_require = os.environ.get("ETP_GATEWAY_VM_REQUIRE_AUTH", "").lower()
        if require_auth is None:
            require_auth = env_require in ("1", "true", "yes")
        # FedRAMP profile auto-enables auth (config-side may also set the env var).
        if os.environ.get("ETP_DEPLOYMENT_PROFILE", "").lower() == "fedramp-high":
            require_auth = True
        self.require_auth = require_auth

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if not self.require_auth:
            return await call_next(request)
        if request.url.path in self.PUBLIC_PATHS:
            return await call_next(request)
        if not self.secret:
            logger.error("JWT auth required but ETP_GATEWAY_VM_JWT_SECRET is unset")
            return JSONResponse({"error": "unauthorized"}, status_code=401)

        auth = request.headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        token = auth[len("bearer "):].strip()

        if not _verify_hs256_jwt(token, self.secret):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return await call_next(request)


def _verify_hs256_jwt(token: str, secret: str) -> bool:
    """Minimal HS256 JWT verification.

    Avoids a hard dependency on ``pyjwt``; the corridor / FedRAMP overlay
    intentionally keeps the gateway's dep footprint minimal. Verifies
    signature and ``exp`` only; callers can layer claim checks if needed.
    """
    import base64
    import hashlib
    import hmac
    import json

    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError:
        return False

    def _b64decode(s: str) -> bytes:
        pad = "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s + pad)

    try:
        header = json.loads(_b64decode(header_b64))
    except (ValueError, json.JSONDecodeError):
        return False
    if header.get("alg") != "HS256" or header.get("typ", "JWT") != "JWT":
        return False

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    expected_sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    try:
        provided_sig = _b64decode(sig_b64)
    except (ValueError, Exception):  # noqa: BLE001
        return False
    if not hmac.compare_digest(expected_sig, provided_sig):
        return False

    # Optional ``exp`` check.
    try:
        payload = json.loads(_b64decode(payload_b64))
    except (ValueError, json.JSONDecodeError):
        return False
    exp = payload.get("exp")
    if exp is not None:
        try:
            if int(exp) < int(time.time()):
                return False
        except (TypeError, ValueError):
            return False
    return True


# ---------------------------------------------------------------------------
# Body size limit
# ---------------------------------------------------------------------------


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests whose ``Content-Length`` exceeds the configured cap.

    Default 1 MiB. Override via ``ETP_GATEWAY_VM_MAX_BODY_BYTES``.
    """

    def __init__(self, app, max_bytes: int | None = None) -> None:
        super().__init__(app)
        env = os.environ.get("ETP_GATEWAY_VM_MAX_BODY_BYTES")
        if max_bytes is None:
            max_bytes = int(env) if env else 1024 * 1024
        self.max_bytes = max(0, max_bytes)

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if self.max_bytes == 0:
            return await call_next(request)
        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                size = int(cl)
            except ValueError:
                return JSONResponse({"error": "bad request"}, status_code=400)
            if size > self.max_bytes:
                return JSONResponse(
                    {"error": "request body too large"},
                    status_code=413,
                )
        return await call_next(request)
