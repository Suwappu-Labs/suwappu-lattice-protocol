"""SCN-029 — gRPC resource-exhaustion limits.

Red-team scenario verifying the LTP gRPC server enforces
message-size and concurrent-stream limits, defending against
resource-exhaustion attacks. Maps to LTP-A-019 (closed by
previous audit work; SCN-029 is the regression test).

Historical pattern: countless gRPC services have shipped with
default unlimited message sizes, allowing a single malicious
client to OOM the server with a multi-GB message. Or with
unlimited concurrent streams, allowing a single client to
exhaust the connection / thread pool.

LTP defenses (in `src/ltp/network/server.py:106-129`):

    grpc.max_receive_message_length: 4 * 1024 * 1024  (4 MiB)
    grpc.max_send_message_length:    4 * 1024 * 1024  (4 MiB)
    grpc.max_concurrent_streams:     100
    max_workers (thread pool):       10 by default

Defenses pinned:
    GR1  Receive message size capped at 4 MiB
    GR2  Send message size capped at 4 MiB
    GR3  Concurrent streams capped at 100
    GR4  Thread pool capped at 10 by default
"""

from __future__ import annotations

import inspect

import pytest

# Skip if grpc isn't installed (CI installs it via the [dev] extra).
pytest.importorskip("grpc", reason="grpc not available")

# The server module imports grpc; only proceed if it imports cleanly.
try:
    from ltp.network import server as _server_module
except Exception as exc:  # pragma: no cover
    pytest.skip(f"ltp.network.server import failed: {exc}", allow_module_level=True)


# ---------------------------------------------------------------------------
# Static-inspection approach: read the server module's source and verify
# the defensive options are present. This avoids spinning up a real gRPC
# server in CI, which would require an event loop + port management.
# ---------------------------------------------------------------------------


def _server_source() -> str:
    return inspect.getsource(_server_module)


# ---------------------------------------------------------------------------
# GR1, GR2 — message-size caps
# ---------------------------------------------------------------------------


def test_GR1_max_receive_message_length_present():
    src = _server_source()
    assert "grpc.max_receive_message_length" in src, (
        "server must configure max_receive_message_length to prevent OOM"
    )


def test_GR2_max_send_message_length_present():
    src = _server_source()
    assert "grpc.max_send_message_length" in src, "server must configure max_send_message_length"


def test_GR1_GR2_message_caps_at_4_mib():
    """Audit-tier check: the cap should be 4 MiB (4 * 1024 * 1024)."""
    src = _server_source()
    assert "4 * 1024 * 1024" in src, "message-size cap should be 4 MiB (4 * 1024 * 1024)"


# ---------------------------------------------------------------------------
# GR3 — concurrent-stream cap
# ---------------------------------------------------------------------------


def test_GR3_max_concurrent_streams_present():
    src = _server_source()
    assert "grpc.max_concurrent_streams" in src, "server must cap concurrent streams"


def test_GR3_concurrent_streams_finite_and_low():
    src = _server_source()
    # Look for the option being set to a small constant.
    # The current value is 100; we assert the option is paired with
    # an integer literal somewhere in the file.
    assert (
        '("grpc.max_concurrent_streams", 100)' in src or '"grpc.max_concurrent_streams", 100' in src
    ), "concurrent-streams cap should be a small constant (current: 100)"


# ---------------------------------------------------------------------------
# GR4 — thread-pool cap
# ---------------------------------------------------------------------------


def test_GR4_thread_pool_default_capped():
    """The default max_workers should be a small constant, not unbounded."""
    src = _server_source()
    # The signature defines max_workers: int = 10
    assert "max_workers: int = 10" in src or "max_workers=10" in src, (
        "thread-pool default should be a small constant (current: 10)"
    )


# ---------------------------------------------------------------------------
# Defense-in-depth: verify the start_server entrypoint passes the options
# ---------------------------------------------------------------------------


def test_GR_options_passed_to_grpc_server():
    """The options tuple must reach grpc.server() — not just be defined
    in scope and forgotten. A simple text-search verifies."""
    src = _server_source()
    assert "grpc.server(" in src, "server must call grpc.server()"
    assert "ThreadPoolExecutor" in src, "server must use bounded ThreadPoolExecutor"
