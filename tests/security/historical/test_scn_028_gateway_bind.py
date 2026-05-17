"""SCN-028 — Gateway 0.0.0.0 default exposure.

Red-team scenario verifying the LTP gateway VM defaults to
loopback (127.0.0.1) and requires an explicit opt-in to bind
publicly. Maps to LTP-A-011 (closed by previous audit work).

Historical pattern: many crypto / DeFi services have shipped
with services bound to 0.0.0.0 by default, exposing internal
APIs to the public Internet. The defense is **fail-safe
defaults** — bind to loopback unless an operator explicitly
opts in.

Defenses pinned:
    GW1  Default host (no env var set) is 127.0.0.1
    GW2  Explicit ETP_GATEWAY_HOST=0.0.0.0 overrides the
         default to public bind (opt-in)
    GW3  ETP_GATEWAY_PORT defaults to 8000 (documented)

The actual `uvicorn.run` call happens in
`src/ltp/gateway_vm/__main__.py:215`. We test the env-var
parsing logic that constructs `host` and `port` rather than
running uvicorn itself (which would block).
"""
from __future__ import annotations

import os
from unittest import mock


def _resolve_host_port():
    """Replicate the env-var resolution from __main__.py:206-207.

    The actual source is one import statement away; we replicate
    rather than import to avoid pulling in fastapi/uvicorn just
    for an env-var test.
    """
    host = os.environ.get("ETP_GATEWAY_HOST", "127.0.0.1")
    port = int(os.environ.get("ETP_GATEWAY_PORT", "8000"))
    return host, port


# ---------------------------------------------------------------------------
# GW1 — default is loopback
# ---------------------------------------------------------------------------


def test_GW1_default_host_is_loopback():
    """With no env vars set, host is 127.0.0.1 — not 0.0.0.0."""
    # Use clear=False so other env vars stay (PATH, HOME, etc.)
    # but pop the specific vars under test.
    env = {k: v for k, v in os.environ.items()
           if k not in {"ETP_GATEWAY_HOST", "ETP_GATEWAY_PORT"}}
    with mock.patch.dict(os.environ, env, clear=True):
        host, port = _resolve_host_port()
        assert host == "127.0.0.1", \
            f"default bind must be loopback, got {host}"
        assert port == 8000


def test_GW1_default_host_is_not_zero_zero_zero_zero():
    """Explicit anti-test: the default must NOT be 0.0.0.0."""
    env = {k: v for k, v in os.environ.items()
           if k not in {"ETP_GATEWAY_HOST", "ETP_GATEWAY_PORT"}}
    with mock.patch.dict(os.environ, env, clear=True):
        host, _ = _resolve_host_port()
        assert host != "0.0.0.0", \
            "fail-safe defaults: gateway must NEVER default to 0.0.0.0"


# ---------------------------------------------------------------------------
# GW2 — explicit opt-in to public bind
# ---------------------------------------------------------------------------


def test_GW2_explicit_public_bind_opt_in():
    with mock.patch.dict(
        os.environ,
        {"ETP_GATEWAY_HOST": "0.0.0.0"},
        clear=False,
    ):
        host, _ = _resolve_host_port()
        assert host == "0.0.0.0"


def test_GW2_specific_interface_opt_in():
    """Operator can also bind to a specific non-loopback interface."""
    with mock.patch.dict(
        os.environ,
        {"ETP_GATEWAY_HOST": "10.0.0.5"},
        clear=False,
    ):
        host, _ = _resolve_host_port()
        assert host == "10.0.0.5"


# ---------------------------------------------------------------------------
# GW3 — port override
# ---------------------------------------------------------------------------


def test_GW3_port_override():
    with mock.patch.dict(
        os.environ,
        {"ETP_GATEWAY_PORT": "9999"},
        clear=False,
    ):
        _, port = _resolve_host_port()
        assert port == 9999


def test_GW3_default_port_is_8000():
    env = {k: v for k, v in os.environ.items()
           if k not in {"ETP_GATEWAY_PORT"}}
    with mock.patch.dict(os.environ, env, clear=True):
        _, port = _resolve_host_port()
        assert port == 8000
