"""
Tests for REST operational endpoints: commit, lattice, materialize.
"""

from __future__ import annotations

import base64
import time

import pytest
from fastapi.testclient import TestClient

from src.ltp.commitment import CommitmentNetwork
from src.ltp.domain import signer_fingerprint
from src.ltp.gateway.app import GatewayConfig, create_app
from src.ltp.gateway.auth import create_jwt
from src.ltp.keypair import KeyPair, KeyRegistry
from src.ltp.protocol import LTPProtocol, TransferState

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def alice():
    return KeyPair.generate("alice")


@pytest.fixture
def bob():
    return KeyPair.generate("bob")


@pytest.fixture
def network(alice):
    kr = KeyRegistry()
    kr.register(alice)
    cn = CommitmentNetwork()
    # Register at least 3 nodes with minimum stake so shard placement works
    for i in range(3):
        cn.register_node(f"node-{i}", f"region-{i}", stake=1000.0)
    return cn


@pytest.fixture
def protocol(network, alice):
    kr = KeyRegistry()
    kr.register(alice)
    return LTPProtocol(network=network, key_registry=kr)


@pytest.fixture
def app(protocol, alice):
    config = GatewayConfig(jwt_enabled=True)
    application = create_app(config)
    application.state.protocol = protocol
    application.state.keypair = alice
    application.state.health_fn = lambda: {"status": "ok"}
    kid = signer_fingerprint(alice.vk).hex()
    application.state.known_vks = {kid: alice.vk}
    return application


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def headers(alice):
    token = create_jwt(alice, "alice-node")
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Auth enforcement
# ---------------------------------------------------------------------------


class TestTransferAuth:
    def test_commit_requires_auth(self, client):
        resp = client.post("/v1/commit", json={"content": base64.b64encode(b"hello").decode()})
        assert resp.status_code == 401

    def test_lattice_requires_auth(self, client):
        resp = client.post(
            "/v1/lattice", json={"entity_id": "test", "cek_hex": "aa", "receiver_ek_hex": "bb"}
        )
        assert resp.status_code == 401

    def test_materialize_requires_auth(self, client):
        resp = client.post("/v1/materialize", json={"sealed_key_hex": "aa"})
        assert resp.status_code == 401

    def test_transfers_list_requires_auth(self, client):
        resp = client.get("/v1/transfers")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Commit
# ---------------------------------------------------------------------------


class TestCommit:
    def test_commit_returns_entity_id(self, client, headers):
        content = base64.b64encode(b"hello world").decode()
        resp = client.post("/v1/commit", json={"content": content}, headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert len(data["entity_id"]) > 0
        assert len(data["commitment_ref"]) > 0
        assert len(data["cek_hex"]) > 0

    def test_commit_invalid_base64(self, client, headers):
        resp = client.post("/v1/commit", json={"content": "!!!not-base64!!!"}, headers=headers)
        assert resp.status_code == 400
        assert resp.json()["success"] is False

    def test_commit_empty_content(self, client, headers):
        content = base64.b64encode(b"").decode()
        resp = client.post("/v1/commit", json={"content": content}, headers=headers)
        assert resp.status_code == 400

    def test_commit_custom_shape(self, client, headers):
        content = base64.b64encode(b"test data").decode()
        resp = client.post(
            "/v1/commit",
            json={"content": content, "shape": "text/plain"},
            headers=headers,
        )
        assert resp.status_code == 200
        assert resp.json()["success"] is True

    def test_commit_creates_session(self, client, headers, protocol):
        content = base64.b64encode(b"session test").decode()
        resp = client.post("/v1/commit", json={"content": content}, headers=headers)
        entity_id = resp.json()["entity_id"]
        session = protocol.get_session(entity_id)
        assert session is not None
        assert session.state == TransferState.COMMITTED
        assert len(session.cek) > 0


# ---------------------------------------------------------------------------
# Lattice
# ---------------------------------------------------------------------------


class TestLattice:
    def _commit(self, client, headers):
        content = base64.b64encode(b"lattice test payload").decode()
        resp = client.post("/v1/commit", json={"content": content}, headers=headers)
        return resp.json()

    def test_lattice_valid(self, client, headers, bob):
        commit = self._commit(client, headers)
        resp = client.post(
            "/v1/lattice",
            json={
                "entity_id": commit["entity_id"],
                "cek_hex": commit["cek_hex"],
                "receiver_ek_hex": bob.ek.hex(),
            },
            headers=headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["sealed_key_size"] > 0
        assert len(data["sealed_key_hex"]) > 0

    def test_lattice_unknown_entity(self, client, headers):
        resp = client.post(
            "/v1/lattice",
            json={
                "entity_id": "nonexistent",
                "cek_hex": "aa" * 32,
                "receiver_ek_hex": "bb" * 32,
            },
            headers=headers,
        )
        assert resp.status_code == 404

    def test_lattice_invalid_cek_hex(self, client, headers):
        # First commit so entity exists, then use bad cek hex
        content = base64.b64encode(b"cek test").decode()
        commit = client.post("/v1/commit", json={"content": content}, headers=headers).json()
        resp = client.post(
            "/v1/lattice",
            json={
                "entity_id": commit["entity_id"],
                "cek_hex": "not-hex",
                "receiver_ek_hex": "aa" * 32,
            },
            headers=headers,
        )
        assert resp.status_code == 400

    def test_lattice_invalid_receiver_ek_hex(self, client, headers):
        content = base64.b64encode(b"ek test").decode()
        commit = client.post("/v1/commit", json={"content": content}, headers=headers).json()
        resp = client.post(
            "/v1/lattice",
            json={
                "entity_id": commit["entity_id"],
                "cek_hex": "aa" * 32,
                "receiver_ek_hex": "not-hex",
            },
            headers=headers,
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Materialize
# ---------------------------------------------------------------------------


class TestMaterialize:
    def test_materialize_invalid_hex(self, client, headers):
        resp = client.post(
            "/v1/materialize",
            json={
                "sealed_key_hex": "not-hex",
            },
            headers=headers,
        )
        assert resp.status_code == 400

    def test_materialize_bad_sealed_key(self, client, headers):
        """Random bytes won't unseal."""
        resp = client.post(
            "/v1/materialize",
            json={
                "sealed_key_hex": "aa" * 100,
            },
            headers=headers,
        )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Full Roundtrip
# ---------------------------------------------------------------------------


class TestFullRoundtrip:
    def test_commit_lattice_materialize(self, client, headers, alice):
        """Full three-phase transfer via REST: commit → lattice → materialize."""
        original = b"The quick brown fox jumps over the lazy dog"
        content_b64 = base64.b64encode(original).decode()

        # Phase 1: COMMIT
        resp = client.post("/v1/commit", json={"content": content_b64}, headers=headers)
        assert resp.status_code == 200
        commit_data = resp.json()
        assert commit_data["success"] is True

        # Phase 2: LATTICE (seal to self — alice→alice)
        resp = client.post(
            "/v1/lattice",
            json={
                "entity_id": commit_data["entity_id"],
                "cek_hex": commit_data["cek_hex"],
                "receiver_ek_hex": alice.ek.hex(),
            },
            headers=headers,
        )
        assert resp.status_code == 200
        lattice_data = resp.json()
        assert lattice_data["success"] is True

        # Phase 3: MATERIALIZE
        resp = client.post(
            "/v1/materialize",
            json={
                "sealed_key_hex": lattice_data["sealed_key_hex"],
            },
            headers=headers,
        )
        assert resp.status_code == 200
        mat_data = resp.json()
        assert mat_data["success"] is True
        assert mat_data["content_size"] == len(original)

        # Verify content matches
        recovered = base64.b64decode(mat_data["content"])
        assert recovered == original


# ---------------------------------------------------------------------------
# Session listing
# ---------------------------------------------------------------------------


class TestSessionListing:
    def test_list_transfers_empty(self, client, headers):
        resp = client.get("/v1/transfers", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["count"] == 0

    def test_list_transfers_after_commit(self, client, headers):
        content = base64.b64encode(b"session listing test").decode()
        client.post("/v1/commit", json={"content": content}, headers=headers)
        resp = client.get("/v1/transfers", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["count"] == 1

    def test_list_transfers_filter_by_state(self, client, headers):
        content = base64.b64encode(b"filter test").decode()
        client.post("/v1/commit", json={"content": content}, headers=headers)
        resp = client.get("/v1/transfers?state=COMMITTED", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["count"] == 1

        resp = client.get("/v1/transfers?state=MATERIALIZED", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["count"] == 0

    def test_list_transfers_invalid_state(self, client, headers):
        resp = client.get("/v1/transfers?state=INVALID", headers=headers)
        assert resp.status_code == 400

    def test_get_transfer_not_found(self, client, headers):
        resp = client.get("/v1/transfers/nonexistent", headers=headers)
        assert resp.status_code == 404

    def test_get_transfer_found(self, client, headers):
        content = base64.b64encode(b"lookup test").decode()
        commit_resp = client.post("/v1/commit", json={"content": content}, headers=headers)
        entity_id = commit_resp.json()["entity_id"]

        resp = client.get(f"/v1/transfers/{entity_id}", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["entity_id"] == entity_id
        assert data["state"] == "COMMITTED"
