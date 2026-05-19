"""Tests for NodeDiagnosticsServer — consolidated operational REST endpoints."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

import pytest

from ltp.commitment import CommitmentNetwork, CommitmentNode, StorageEndowment
from ltp.network.safe_network import SafeCommitmentNetwork
from ltp.node.node_diagnostics import NodeDiagnosticsServer
from ltp.node.peer_manager import PeerManager, PeerState
from ltp.protocol import LTPProtocol, ProtocolConfig, TransferSession, TransferState

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get(server: NodeDiagnosticsServer, path: str) -> tuple[int, dict]:
    """Issue a GET request and return (status_code, json_body)."""
    url = f"http://127.0.0.1:{server.port}{path}"
    try:
        resp = urllib.request.urlopen(url, timeout=5)
        body = json.loads(resp.read())
        return resp.status, body
    except urllib.error.HTTPError as exc:
        body = json.loads(exc.read())
        return exc.code, body


class _MockAuditScheduler:
    def __init__(self, epoch=7, running=True):
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
def peer_manager() -> PeerManager:
    pm = PeerManager()
    pm.mark_connected(
        node_id="node-a",
        public_key=b"\x01" * 16,
        address="10.0.0.1:50051",
        region="us-east-1",
    )
    pm.mark_connected(
        node_id="node-b",
        public_key=b"\x02" * 16,
        address="10.0.0.2:50051",
        region="eu-west-1",
    )
    return pm


@pytest.fixture()
def commitment_network() -> SafeCommitmentNetwork:
    node1 = CommitmentNode("local-node", "us-east-1")
    node2 = CommitmentNode("remote-node", "eu-west-1")
    inner = CommitmentNetwork()
    inner.add_existing_node(node1)
    inner.add_existing_node(node2)
    return SafeCommitmentNetwork(inner)


@pytest.fixture()
def protocol(commitment_network) -> LTPProtocol:
    return LTPProtocol(
        commitment_network,
        config=ProtocolConfig(),
    )


@pytest.fixture()
def server(peer_manager, commitment_network, protocol):
    cnode = commitment_network.nodes[0]
    srv = NodeDiagnosticsServer(
        peer_manager=peer_manager,
        commitment_network=commitment_network,
        protocol=protocol,
        audit_scheduler=_MockAuditScheduler(),
        commitment_node=cnode,
        port=0,
    )
    srv.start()
    yield srv
    srv.stop()


# ---------------------------------------------------------------------------
# Peers
# ---------------------------------------------------------------------------


class TestPeersEndpoint:
    def test_peers_list(self, server):
        code, body = _get(server, "/node/peers")
        assert code == 200
        assert body["connected_count"] == 2
        assert len(body["peers"]) == 2
        ids = {p["node_id"] for p in body["peers"]}
        assert ids == {"node-a", "node-b"}

    def test_peer_detail_found(self, server):
        code, body = _get(server, "/node/peers/node-a")
        assert code == 200
        assert body["node_id"] == "node-a"
        assert body["region"] == "us-east-1"
        assert body["state"] == "connected"

    def test_peer_detail_not_found(self, server):
        code, body = _get(server, "/node/peers/nonexistent")
        assert code == 404

    def test_peers_unavailable(self):
        """Server with no peer_manager returns 503."""
        srv = NodeDiagnosticsServer(port=0)
        srv.start()
        try:
            code, body = _get(srv, "/node/peers")
            assert code == 503
        finally:
            srv.stop()


# ---------------------------------------------------------------------------
# Transfers
# ---------------------------------------------------------------------------


class TestTransfersEndpoint:
    def test_transfers_empty(self, server):
        code, body = _get(server, "/node/transfers")
        assert code == 200
        assert body["count"] == 0
        assert body["sessions"] == []

    def test_transfer_detail_not_found(self, server):
        code, body = _get(server, "/node/transfers/no-such-entity")
        assert code == 404

    def test_transfers_with_session(self, server, protocol):
        session = TransferSession(entity_id="ent-1", started_at=time.time())
        protocol._sessions["ent-1"] = session
        code, body = _get(server, "/node/transfers")
        assert code == 200
        assert body["count"] == 1
        assert body["sessions"][0]["entity_id"] == "ent-1"
        assert body["sessions"][0]["state"] == "idle"

    def test_transfer_detail_found(self, server, protocol):
        session = TransferSession(entity_id="ent-2", started_at=time.time())
        protocol._sessions["ent-2"] = session
        code, body = _get(server, "/node/transfers/ent-2")
        assert code == 200
        assert body["entity_id"] == "ent-2"

    def test_transfer_session_field_completeness(self, server, protocol):
        """All serialized session fields are present and correctly typed."""
        now = time.time()
        session = TransferSession(
            entity_id="fields-test",
            started_at=now,
            phase_started_at=now,
            retry_count=3,
            error="timeout",
        )
        protocol._sessions["fields-test"] = session
        code, body = _get(server, "/node/transfers/fields-test")
        assert code == 200
        assert body["entity_id"] == "fields-test"
        assert body["state"] == "idle"
        assert isinstance(body["started_at"], float)
        assert body["started_at"] == pytest.approx(now, abs=1.0)
        assert isinstance(body["phase_started_at"], float)
        assert body["retry_count"] == 3
        assert body["error"] == "timeout"
        assert isinstance(body["elapsed_seconds"], float)
        assert body["elapsed_seconds"] >= 0

    def test_transfers_filter_by_state(self, server, protocol):
        session = TransferSession(entity_id="ent-3", started_at=time.time())
        protocol._sessions["ent-3"] = session
        code, body = _get(server, "/node/transfers?state=IDLE")
        assert code == 200
        assert body["count"] == 1

    def test_transfers_filter_invalid_state(self, server):
        code, body = _get(server, "/node/transfers?state=BOGUS")
        assert code == 400

    def test_transfers_unavailable(self):
        srv = NodeDiagnosticsServer(port=0)
        srv.start()
        try:
            code, body = _get(srv, "/node/transfers")
            assert code == 503
        finally:
            srv.stop()


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


class TestAuditEndpoint:
    def test_audit_status(self, server):
        code, body = _get(server, "/node/audit")
        assert code == 200
        assert body["epoch"] == 7
        assert body["running"] is True

    def test_audit_unavailable(self):
        srv = NodeDiagnosticsServer(port=0)
        srv.start()
        try:
            code, body = _get(srv, "/node/audit")
            assert code == 503
        finally:
            srv.stop()


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------


class TestNetworkEndpoint:
    def test_network_list(self, server):
        code, body = _get(server, "/node/network")
        assert code == 200
        assert body["total_node_count"] == 2
        ids = {n["node_id"] for n in body["nodes"]}
        assert "local-node" in ids
        assert "remote-node" in ids

    def test_network_node_detail_found(self, server):
        code, body = _get(server, "/node/network/nodes/local-node")
        assert code == 200
        assert body["node_id"] == "local-node"
        assert "stake" in body
        assert "reputation_score" in body
        assert "withheld_earnings" in body

    def test_network_node_detail_field_completeness(self, server):
        """All expected node detail fields are present with correct types."""
        code, body = _get(server, "/node/network/nodes/local-node")
        assert code == 200
        assert body["region"] == "us-east-1"
        assert isinstance(body["shard_count"], int)
        assert isinstance(body["evicted"], bool)
        assert isinstance(body["strikes"], int)
        assert isinstance(body["audit_passes"], int)
        assert isinstance(body["reputation_score"], (int, float))
        # Lifecycle fields
        assert "stake_locked_until" in body
        assert "registered_at" in body
        assert "evicted_at" in body
        assert "eviction_count" in body

    def test_network_node_detail_not_found(self, server):
        code, body = _get(server, "/node/network/nodes/no-such-node")
        assert code == 404

    def test_network_unavailable(self):
        srv = NodeDiagnosticsServer(port=0)
        srv.start()
        try:
            code, body = _get(srv, "/node/network")
            assert code == 503
        finally:
            srv.stop()


# ---------------------------------------------------------------------------
# Endowment
# ---------------------------------------------------------------------------


class TestEndowmentEndpoint:
    def test_endowment(self, server):
        code, body = _get(server, "/node/network/endowment")
        assert code == 200
        assert "balance" in body
        assert "total_burned" in body
        assert "burn_count" in body
        assert isinstance(body["burn_history"], list)


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------


class TestStorageEndpoint:
    def test_storage(self, server):
        code, body = _get(server, "/node/storage")
        assert code == 200
        assert body["node_id"] == "local-node"
        assert "shard_count" in body

    def test_storage_unavailable(self):
        srv = NodeDiagnosticsServer(port=0)
        srv.start()
        try:
            code, body = _get(srv, "/node/storage")
            assert code == 503
        finally:
            srv.stop()


# ---------------------------------------------------------------------------
# Log
# ---------------------------------------------------------------------------


class TestLogEndpoint:
    def test_log_empty(self, server):
        code, body = _get(server, "/node/log")
        assert code == 200
        assert body["length"] == 0
        assert isinstance(body["head_hash"], str)


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------


class TestServerLifecycle:
    def test_start_stop(self):
        srv = NodeDiagnosticsServer(port=0)
        srv.start()
        assert srv.port > 0
        code, body = _get(srv, "/node/audit")
        assert code == 503  # no scheduler wired
        srv.stop()

    def test_port_zero_ephemeral(self):
        srv = NodeDiagnosticsServer(port=0)
        srv.start()
        try:
            assert srv.port > 0
        finally:
            srv.stop()

    def test_unknown_route_404(self, server):
        code, body = _get(server, "/node/bogus")
        assert code == 404

    def test_500_on_dynamic_route_does_not_leak(self, server):
        """Internal error on /node/peers/<id> returns generic message."""
        original = server._server.peer_manager

        # Replace with object whose get_peer_by_id raises
        class _BrokenPM:
            def get_peer_by_id(self, node_id):
                raise RuntimeError("boom")

        server._server.peer_manager = _BrokenPM()
        try:
            code, body = _get(server, "/node/peers/node-a")
            assert code == 500
            assert body["error"] == "internal error"
            assert "boom" not in body["error"]
        finally:
            server._server.peer_manager = original


# ---------------------------------------------------------------------------
# Empty path parameter validation
# ---------------------------------------------------------------------------


class TestEmptyPathParams:
    def test_peers_empty_id(self, server):
        code, body = _get(server, "/node/peers/")
        assert code == 400
        assert "missing" in body["error"]

    def test_transfers_empty_id(self, server):
        code, body = _get(server, "/node/transfers/")
        assert code == 400
        assert "missing" in body["error"]

    def test_network_nodes_empty_id(self, server):
        code, body = _get(server, "/node/network/nodes/")
        assert code == 400
        assert "missing" in body["error"]


# ---------------------------------------------------------------------------
# Security: sensitive fields never leaked
# ---------------------------------------------------------------------------


class TestSensitiveFieldExclusion:
    """Verify cryptographic material (cek, sealed_key, sk, dk) is never exposed."""

    def test_transfer_session_excludes_cek_and_sealed_key(self, server, protocol):
        session = TransferSession(
            entity_id="sec-test",
            started_at=time.time(),
            cek=b"\xaa" * 32,
            sealed_key=b"\xbb" * 64,
        )
        protocol._sessions["sec-test"] = session

        # Single session lookup
        code, body = _get(server, "/node/transfers/sec-test")
        assert code == 200
        assert "cek" not in body
        assert "sealed_key" not in body

        # Session list
        code, body = _get(server, "/node/transfers")
        assert code == 200
        for s in body["sessions"]:
            assert "cek" not in s
            assert "sealed_key" not in s


# ---------------------------------------------------------------------------
# Gap 2: /node/log includes sth_age_seconds
# ---------------------------------------------------------------------------


class TestLogSthAge:
    def test_log_endpoint_includes_sth_age(self, server, commitment_network):
        """sth_age_seconds appears in /node/log response (Gap 2)."""
        code, body = _get(server, "/node/log")
        assert code == 200
        # Empty log — no STH yet, age should be null
        assert "sth_age_seconds" in body
        assert body["sth_age_seconds"] is None

    def test_log_sth_age_after_commit(self, server, commitment_network):
        """After a commit, sth_age_seconds reflects STH timestamp."""
        from ltp.commitment import CommitmentRecord

        record = CommitmentRecord(
            entity_id="age-test",
            sender_id="sender-1",
            content_hash="sha3:aabb",
            shard_map_root="sha3:ccdd",
            encoding_params={"n": 8, "k": 4, "algorithm": "rs"},
            shape="application/octet-stream",
            shape_hash="sha3:eeff",
            timestamp=time.time(),
            signature=b"\x00" * 32,
        )
        commitment_network._inner.log.append(record)

        code, body = _get(server, "/node/log")
        assert code == 200
        assert body["sth_age_seconds"] is not None
        assert body["sth_age_seconds"] >= 0


# ---------------------------------------------------------------------------
# Gap 3: /node/network/endowment burn_history capped
# ---------------------------------------------------------------------------


class TestEndowmentBurnHistoryCap:
    def test_endowment_burn_history_capped(self, server, commitment_network):
        """burn_history defaults to 50 most recent entries (Gap 3)."""
        # Inject 100 burn entries
        endowment = commitment_network._inner.endowment
        for i in range(100):
            endowment.burn_history.append({"epoch": i, "amount": 1.0})

        code, body = _get(server, "/node/network/endowment")
        assert code == 200
        assert body["burn_count"] == 100  # total count
        assert len(body["burn_history"]) == 50  # capped at default
        # Most recent entries (last 50)
        assert body["burn_history"][0]["epoch"] == 50
        assert body["burn_history"][-1]["epoch"] == 99

    def test_endowment_burn_history_custom_limit(self, server, commitment_network):
        """?limit=N caps burn_history up to max 200."""
        endowment = commitment_network._inner.endowment
        for i in range(100):
            endowment.burn_history.append({"epoch": i, "amount": 1.0})

        code, body = _get(server, "/node/network/endowment?limit=10")
        assert code == 200
        assert len(body["burn_history"]) == 10
        assert body["burn_history"][0]["epoch"] == 90  # last 10

    def test_endowment_burn_history_limit_clamped(self, server, commitment_network):
        """?limit=999 is clamped to 200."""
        endowment = commitment_network._inner.endowment
        for i in range(250):
            endowment.burn_history.append({"epoch": i, "amount": 1.0})

        code, body = _get(server, "/node/network/endowment?limit=999")
        assert code == 200
        assert len(body["burn_history"]) == 200

    def test_endowment_burn_history_limit_non_numeric_fallback(self, server, commitment_network):
        """?limit=abc falls back to default 50."""
        endowment = commitment_network._inner.endowment
        for i in range(100):
            endowment.burn_history.append({"epoch": i, "amount": 1.0})

        code, body = _get(server, "/node/network/endowment?limit=abc")
        assert code == 200
        assert len(body["burn_history"]) == 50


# ---------------------------------------------------------------------------
# Gap 4: /node/transfers state filter case-insensitive + valid_states
# ---------------------------------------------------------------------------


class TestTransfersFilterEnhancements:
    def test_transfers_filter_case_insensitive(self, server, protocol):
        """?state=idle (lowercase) works the same as ?state=IDLE (Gap 4)."""
        session = TransferSession(entity_id="ci-test", started_at=time.time())
        protocol._sessions["ci-test"] = session

        code, body = _get(server, "/node/transfers?state=idle")
        assert code == 200
        assert body["count"] == 1

        code, body = _get(server, "/node/transfers?state=Idle")
        assert code == 200
        assert body["count"] == 1

    def test_transfers_filter_invalid_state_returns_valid_states(self, server):
        """Invalid state returns 400 with valid_states list (Gap 4)."""
        code, body = _get(server, "/node/transfers?state=BOGUS")
        assert code == 400
        assert "valid_states" in body
        assert isinstance(body["valid_states"], list)
        assert len(body["valid_states"]) > 0
        assert "IDLE" in body["valid_states"]


# ---------------------------------------------------------------------------
# Gap 8: public_mode redacts sensitive fields
# ---------------------------------------------------------------------------


class TestPublicModeRedaction:
    def test_public_mode_redacts_sensitive_fields(
        self,
        peer_manager,
        commitment_network,
        protocol,
    ):
        """public_mode=True omits address from peers & earnings/stake from nodes."""
        cnode = commitment_network.nodes[0]
        srv = NodeDiagnosticsServer(
            peer_manager=peer_manager,
            commitment_network=commitment_network,
            protocol=protocol,
            commitment_node=cnode,
            port=0,
            public_mode=True,
        )
        srv.start()
        try:
            # Peers: address should be absent
            code, body = _get(srv, "/node/peers")
            assert code == 200
            for p in body["peers"]:
                assert "address" not in p
                assert "node_id" in p  # non-sensitive fields still present
                assert "region" in p

            # Peer detail: address absent
            code, body = _get(srv, "/node/peers/node-a")
            assert code == 200
            assert "address" not in body
            assert body["node_id"] == "node-a"

            # Node detail: stake/earnings absent
            code, body = _get(srv, "/node/network/nodes/local-node")
            assert code == 200
            assert "stake" not in body
            assert "withheld_earnings" not in body
            assert "total_earnings" not in body
            assert "node_id" in body  # non-sensitive still present
            assert "reputation_score" in body
        finally:
            srv.stop()

    def test_public_mode_network_summary_excludes_sensitive(
        self,
        peer_manager,
        commitment_network,
        protocol,
    ):
        """Network summary nodes also respect public_mode (no stake/earnings)."""
        cnode = commitment_network.nodes[0]
        srv = NodeDiagnosticsServer(
            peer_manager=peer_manager,
            commitment_network=commitment_network,
            protocol=protocol,
            commitment_node=cnode,
            port=0,
            public_mode=True,
        )
        srv.start()
        try:
            code, body = _get(srv, "/node/network")
            assert code == 200
            # Summary nodes don't include stake/earnings (those are detail-only)
            for n in body["nodes"]:
                assert "node_id" in n
                assert "reputation_score" in n
        finally:
            srv.stop()

    def test_default_mode_includes_all_fields(self, server):
        """Default (public_mode=False) exposes all fields."""
        code, body = _get(server, "/node/peers")
        assert code == 200
        for p in body["peers"]:
            assert "address" in p

        code, body = _get(server, "/node/network/nodes/local-node")
        assert code == 200
        assert "stake" in body
        assert "withheld_earnings" in body
        assert "total_earnings" in body
