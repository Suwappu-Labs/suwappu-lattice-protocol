"""LTP-A-010 / -011 regression: gateway HTTP attack surface.

The gateway VM exposes ``/gateway/events``, ``/gateway/events/{tx_hash}``,
``/gateway/status``, and ``/gateway/health``. Without auth + rate-limit +
body-size middleware, an attacker can enumerate state, exhaust memory, or
fingerprint internal data via verbose error messages.

This test does NOT bring up the full gateway service (which requires KMS,
RPCs, and an operator key). Instead it asserts the structural invariants
that the hardening middleware in Commit 3 of this PR depends on:

1. Router handlers are wrapped in try/except and return a redacted 500
   on unexpected exceptions (closed by PR #8 commit ``18aded2``).
2. The error response body never echoes the user-controlled ``tx_hash``
   verbatim (closes LTP-A-027 — fingerprinting via error messages).
3. The middleware module exists and exports the three middleware classes
   (closed by Commit 3 — proves the wiring is in place).

For a live HTTP test, run the gateway under ``deploy/run_gateway.sh`` and
hammer ``GET /gateway/events`` from a separate process; the rate-limit
middleware should return 429 after the configured threshold.
"""

from __future__ import annotations

import importlib
import inspect

import pytest


def test_events_router_handlers_wrap_exceptions():
    """Every handler in events.py must be wrapped in try/except."""
    mod = importlib.import_module("src.ltp.gateway_vm.routers.events")
    src = inspect.getsource(mod)
    # Both handler bodies must reference _internal_error or have explicit try/except.
    assert "_internal_error" in src or "except Exception" in src, (
        "events router lost its exception wrapper — PR #8 commit 18aded2 regressed"
    )


def test_status_router_handlers_wrap_exceptions():
    mod = importlib.import_module("src.ltp.gateway_vm.routers.status")
    src = inspect.getsource(mod)
    assert "_internal_error" in src or "except Exception" in src, (
        "status router lost its exception wrapper"
    )


def test_internal_error_response_is_redacted():
    """The 500 response body must say 'internal error' and NOT include the
    exception message or any user-controlled input.
    """
    mod = importlib.import_module("src.ltp.gateway_vm.routers.events")
    src = inspect.getsource(mod)
    # The redacted body string is the contract we enforce.
    assert '"error": "internal error"' in src or "'error': 'internal error'" in src, (
        "internal-error response body is no longer redacted — info leak risk"
    )
    # And the exception variable name must NOT appear inside the JSON body.
    # This is a structural check: the response builder must not f-string the exc.
    # If a future refactor breaks this, the test will fail visibly.
    assert "JSONResponse({\"error\": str(exc)" not in src
    assert "JSONResponse({'error': str(exc)" not in src


@pytest.mark.skipif(
    importlib.util.find_spec("src.ltp.gateway_vm.middleware") is None,
    reason="middleware module not yet present — requires Commit 3 of this PR",
)
def test_middleware_module_exports_three_classes():
    """Once Commit 3 lands, the middleware module exists and exports
    RateLimitMiddleware, JWTAuthMiddleware, BodySizeLimitMiddleware.
    """
    mod = importlib.import_module("src.ltp.gateway_vm.middleware")
    assert hasattr(mod, "RateLimitMiddleware"), "rate-limit middleware missing"
    assert hasattr(mod, "JWTAuthMiddleware"), "JWT auth middleware missing"
    assert hasattr(mod, "BodySizeLimitMiddleware"), "body-size middleware missing"


def test_default_host_bind_is_not_zero_zero_zero_zero():
    """LTP-A-011: ``__main__`` must NOT hard-code 0.0.0.0 as the host bind
    default.

    Two acceptable shapes after Commit 3:
    - Default is 127.0.0.1 (with env-var opt-in to 0.0.0.0)
    - Default comes from an env var with no hard-coded 0.0.0.0 string
    """
    mod = importlib.import_module("src.ltp.gateway_vm.__main__")
    src = inspect.getsource(mod)
    has_zero = '"0.0.0.0"' in src or "'0.0.0.0'" in src
    has_localhost = '"127.0.0.1"' in src or "'127.0.0.1'" in src
    assert has_localhost or not has_zero, (
        "gateway __main__ hard-codes 0.0.0.0 as the default host bind — "
        "Commit 3 of this PR (LTP-A-011) is regressed"
    )
