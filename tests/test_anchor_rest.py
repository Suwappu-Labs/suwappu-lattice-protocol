"""Tests for AnchorStatusServer — REST API for anchor subsystem status."""

from __future__ import annotations

import json
import urllib.error
import urllib.request

import pytest

from ltp.node.anchor_rest import AnchorStatusServer
from ltp.node.anchor_status import AnchorStatus, AnchorStatusTracker

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get(server: AnchorStatusServer, path: str) -> tuple[int, dict]:
    """Issue a GET request and return (status_code, json_body)."""
    url = f"http://127.0.0.1:{server.port}{path}"
    try:
        resp = urllib.request.urlopen(url, timeout=5)
        body = json.loads(resp.read())
        return resp.status, body
    except urllib.error.HTTPError as exc:
        body = json.loads(exc.read())
        return exc.code, body


class _MockScheduler:
    """Duck-typed scheduler exposing the 4 properties the REST server reads."""

    def __init__(self, epoch=5, running=True, pending_batch_size=2, last_seen_index=16):
        self._epoch = epoch
        self._running = running
        self._pending_batch_size = pending_batch_size
        self._last_seen_index = last_seen_index

    @property
    def epoch(self):
        return self._epoch

    @property
    def running(self):
        return self._running

    @property
    def pending_batch_size(self):
        return self._pending_batch_size

    @property
    def last_seen_index(self):
        return self._last_seen_index


class _MockVerifier:
    """Duck-typed verifier exposing epoch and running."""

    def __init__(self, epoch=3, running=True):
        self._epoch = epoch
        self._running = running

    @property
    def epoch(self):
        return self._epoch

    @property
    def running(self):
        return self._running


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tracker() -> AnchorStatusTracker:
    """Tracker pre-populated with entities in various statuses."""
    t = AnchorStatusTracker()
    # PENDING
    t.mark_pending("ent-pending", b"\x01" * 32)
    # SUBMITTED
    t.mark_pending("ent-submitted", b"\x02" * 32)
    t.mark_submitted("ent-submitted", "0xaabbcc")
    # CONFIRMED
    t.mark_pending("ent-confirmed", b"\x03" * 32)
    t.mark_submitted("ent-confirmed", "0xddeeff")
    t.mark_confirmed("ent-confirmed", block_number=42, gas_used=21000)
    # FINALIZED
    t.mark_pending("ent-finalized", b"\x04" * 32)
    t.mark_submitted("ent-finalized", "0x112233")
    t.mark_confirmed("ent-finalized", block_number=10, gas_used=21000)
    t.mark_finalized("ent-finalized")
    # FAILED
    t.mark_pending("ent-failed", b"\x05" * 32)
    t.mark_failed("ent-failed", "transaction reverted")
    return t


@pytest.fixture()
def server(tracker: AnchorStatusTracker):
    """AnchorStatusServer on an ephemeral port, started and stopped."""
    srv = AnchorStatusServer(tracker, port=0)
    srv.start()
    yield srv
    srv.stop()


# ---------------------------------------------------------------------------
# Status endpoint
# ---------------------------------------------------------------------------


class TestStatusEndpoint:
    def test_status_found(self, server, tracker):
        code, body = _get(server, "/anchor/status/ent-submitted")
        assert code == 200
        assert body["entity_id"] == "ent-submitted"
        assert body["status"] == "SUBMITTED"
        assert body["tx_hash"] == "0xaabbcc"

    def test_status_not_found(self, server):
        code, body = _get(server, "/anchor/status/nonexistent")
        assert code == 404
        assert body["error"] == "not found"

    def test_status_shows_all_fields(self, server):
        code, body = _get(server, "/anchor/status/ent-confirmed")
        assert code == 200
        assert body["block_number"] == 42
        assert body["gas_used"] == 21000
        assert body["retry_count"] == 0
        assert isinstance(body["submitted_at"], float)
        assert "error" in body

    def test_status_missing_entity_id(self, server):
        """GET /anchor/status/ with no entity_id returns 400."""
        code, body = _get(server, "/anchor/status/")
        assert code == 400
        assert body["error"] == "missing entity_id"


# ---------------------------------------------------------------------------
# Stats endpoint
# ---------------------------------------------------------------------------


class TestStatsEndpoint:
    def test_stats_counts(self, server):
        code, body = _get(server, "/anchor/stats")
        assert code == 200
        counts = body["counts"]
        assert counts["PENDING"] == 1
        assert counts["SUBMITTED"] == 1
        assert counts["CONFIRMED"] == 1
        assert counts["FINALIZED"] == 1
        assert counts["FAILED"] == 1

    def test_stats_total(self, server):
        code, body = _get(server, "/anchor/stats")
        assert body["total"] == sum(body["counts"].values())

    def test_stats_no_scheduler(self, server):
        """When scheduler=None, no 'scheduler' key in response."""
        code, body = _get(server, "/anchor/stats")
        assert "scheduler" not in body

    def test_stats_with_scheduler(self, tracker):
        """When scheduler is provided, its properties appear in stats."""
        sched = _MockScheduler(epoch=5, running=True, pending_batch_size=2, last_seen_index=16)
        verifier = _MockVerifier(epoch=3, running=True)
        srv = AnchorStatusServer(tracker, scheduler=sched, verifier=verifier, port=0)
        srv.start()
        try:
            code, body = _get(srv, "/anchor/stats")
            assert code == 200
            assert body["scheduler"]["epoch"] == 5
            assert body["scheduler"]["running"] is True
            assert body["scheduler"]["pending_batch_size"] == 2
            assert body["scheduler"]["last_seen_index"] == 16
            assert body["verifier"]["epoch"] == 3
            assert body["verifier"]["running"] is True
        finally:
            srv.stop()


# ---------------------------------------------------------------------------
# By-status endpoint
# ---------------------------------------------------------------------------


class TestByStatusEndpoint:
    def test_by_status_submitted(self, server):
        code, body = _get(server, "/anchor/by-status?status=SUBMITTED")
        assert code == 200
        assert body["status"] == "SUBMITTED"
        assert body["count"] == 1
        assert len(body["entities"]) == 1
        ent = body["entities"][0]
        assert ent["entity_id"] == "ent-submitted"
        # Verify full field set (consistency with /anchor/status/<id>)
        assert "tx_hash" in ent
        assert "block_number" in ent
        assert "gas_used" in ent
        assert "retry_count" in ent
        assert "error" in ent

    def test_by_status_failed_shows_error(self, server):
        """FAILED entities expose the error field."""
        code, body = _get(server, "/anchor/by-status?status=FAILED")
        assert code == 200
        assert body["count"] == 1
        assert body["entities"][0]["error"] == "transaction reverted"

    def test_by_status_empty(self, server):
        """Status with 0 entities returns count=0, entities=[]."""
        # Use a status we didn't populate — all entities pass through PENDING
        # but none remain there except "ent-pending", so FINALIZED has exactly 1.
        # We need a filter that yields 0. Since we have PENDING=1, SUBMITTED=1,
        # CONFIRMED=1, FINALIZED=1, FAILED=1, we test filtering for a status
        # after marking all of that status as transitioned. Simplest: just create
        # a fresh server with an empty tracker.
        empty_tracker = AnchorStatusTracker()
        srv = AnchorStatusServer(empty_tracker, port=0)
        srv.start()
        try:
            code, body = _get(srv, "/anchor/by-status?status=FAILED")
            assert code == 200
            assert body["count"] == 0
            assert body["entities"] == []
        finally:
            srv.stop()

    def test_by_status_missing_param(self, server):
        code, body = _get(server, "/anchor/by-status")
        assert code == 400
        assert body["error"] == "invalid status"

    def test_by_status_invalid_status(self, server):
        code, body = _get(server, "/anchor/by-status?status=BOGUS")
        assert code == 400
        assert body["error"] == "invalid status"

    def test_by_status_case_insensitive(self, server):
        """?status=submitted (lowercase) works the same as ?status=SUBMITTED."""
        code, body = _get(server, "/anchor/by-status?status=submitted")
        assert code == 200
        assert body["status"] == "SUBMITTED"
        assert body["count"] == 1


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------


class TestHealthEndpoint:
    def test_health_ok(self, server):
        code, body = _get(server, "/anchor/health")
        assert code == 200
        assert body["status"] == "ok"
        assert body["tracker_total"] == 5

    def test_health_reflects_daemon_states(self, tracker):
        """Health always includes scheduler_running and verifier_running (Gap 1)."""
        # With daemons wired — values reflect component state
        sched = _MockScheduler(running=True)
        verifier = _MockVerifier(running=False)
        srv = AnchorStatusServer(tracker, scheduler=sched, verifier=verifier, port=0)
        srv.start()
        try:
            code, body = _get(srv, "/anchor/health")
            assert code == 200
            assert body["scheduler_running"] is True
            assert body["verifier_running"] is False
        finally:
            srv.stop()

        # Without daemons — keys still present, values are null
        srv2 = AnchorStatusServer(tracker, port=0)
        srv2.start()
        try:
            code, body = _get(srv2, "/anchor/health")
            assert code == 200
            assert "scheduler_running" in body
            assert body["scheduler_running"] is None
            assert "verifier_running" in body
            assert body["verifier_running"] is None
        finally:
            srv2.stop()


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------


class TestServerLifecycle:
    def test_start_stop(self, tracker):
        srv = AnchorStatusServer(tracker, port=0)
        srv.start()
        # Should respond
        code, body = _get(srv, "/anchor/health")
        assert code == 200
        srv.stop()

    def test_port_zero_assigns_ephemeral(self, tracker):
        srv = AnchorStatusServer(tracker, port=0)
        srv.start()
        try:
            assert srv.port > 0
        finally:
            srv.stop()

    def test_invalid_route_404(self, server):
        """Unknown path returns 404 JSON error."""
        code, body = _get(server, "/anchor/bogus")
        assert code == 404
        assert body["error"] == "not found"

    def test_500_does_not_leak_exception(self, server):
        """Internal error returns generic message, not raw exception."""
        # Force an exception by breaking the tracker
        original = server._server.tracker
        server._server.tracker = None  # will cause AttributeError
        try:
            code, body = _get(server, "/anchor/stats")
            assert code == 500
            assert body["error"] == "internal error"
            assert "AttributeError" not in body["error"]
        finally:
            server._server.tracker = original
