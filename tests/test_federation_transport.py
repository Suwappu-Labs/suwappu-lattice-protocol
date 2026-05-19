"""
Federation transport + authentication tests.

Tests FederationAuth verification, InMemoryFederationTransport shard
fetching and entity querying, and auth enforcement on the transport layer.
"""

from __future__ import annotations

import pytest

from src.ltp import CommitmentNetwork, KeyPair, LTPProtocol
from src.ltp.entity import Entity
from src.ltp.federation import (
    FederationAgreement,
    FederationAuth,
    InMemoryFederationTransport,
    NetworkIdentityRecord,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def net_a_kp() -> KeyPair:
    return KeyPair.generate("transport-a")


@pytest.fixture(scope="session")
def net_b_kp() -> KeyPair:
    return KeyPair.generate("transport-b")


@pytest.fixture
def nir_a(net_a_kp):
    return NetworkIdentityRecord.create(
        net_a_kp,
        b"\xaa" * 32,
        0,
        "Net A",
        "https://a.example.com",
    )


@pytest.fixture
def nir_b(net_b_kp):
    return NetworkIdentityRecord.create(
        net_b_kp,
        b"\xbb" * 32,
        0,
        "Net B",
        "https://b.example.com",
    )


@pytest.fixture
def valid_auth(net_a_kp, net_b_kp, nir_a, nir_b):
    """Fully signed auth credentials from A requesting data from B."""
    half = FederationAgreement.initiate(net_a_kp, nir_a, nir_b)
    full = FederationAgreement.countersign(half, net_b_kp)
    return FederationAuth(requester_nir=nir_a, agreement=full)


@pytest.fixture
def network_b():
    """A CommitmentNetwork representing Net B with committed data."""
    net = CommitmentNetwork()
    for i in range(6):
        net.add_node(f"b-node-{i}", ["US-East", "US-West", "EU-West"][i % 3])
    return net


# ---------------------------------------------------------------------------
# FederationAuth
# ---------------------------------------------------------------------------


class TestFederationAuth:
    def test_valid_auth_verifies(self, valid_auth):
        assert valid_auth.verify() is True

    def test_tampered_nir_fails(self, net_a_kp, net_b_kp, nir_a, nir_b):
        half = FederationAgreement.initiate(net_a_kp, nir_a, nir_b)
        full = FederationAgreement.countersign(half, net_b_kp)

        # Tamper the NIR
        tampered_nir = NetworkIdentityRecord(
            network_id=nir_a.network_id,
            operator_vk=nir_a.operator_vk,
            genesis_sth_root=nir_a.genesis_sth_root,
            genesis_sth_sequence=nir_a.genesis_sth_sequence,
            display_name="TAMPERED",
            discovery_endpoint=nir_a.discovery_endpoint,
            created_at=nir_a.created_at,
            signature=nir_a.signature,
        )
        auth = FederationAuth(requester_nir=tampered_nir, agreement=full)
        assert auth.verify() is False

    def test_half_signed_agreement_fails(self, net_a_kp, nir_a, nir_b):
        half = FederationAgreement.initiate(net_a_kp, nir_a, nir_b)
        # Don't countersign
        auth = FederationAuth(requester_nir=nir_a, agreement=half)
        assert auth.verify() is False


# ---------------------------------------------------------------------------
# InMemoryFederationTransport
# ---------------------------------------------------------------------------


class TestInMemoryTransport:
    def test_fetch_shards_returns_data(self, valid_auth, network_b, net_b_kp):
        """Fetch shards from a registered network with valid auth."""
        protocol = LTPProtocol(network_b)
        entity = Entity(content=b"cross-network test data " * 10, shape="text/plain")
        entity_id, record, cek = protocol.commit(entity, net_b_kp, n=6, k=3)

        transport = InMemoryFederationTransport()
        transport.register_network("https://b.example.com", network_b)

        shards = transport.fetch_shards(
            "https://b.example.com",
            entity_id,
            [0, 1, 2],
            valid_auth,
        )
        assert len(shards) >= 1
        # Shards should be bytes (encrypted)
        for idx, data in shards.items():
            assert isinstance(data, bytes)
            assert len(data) > 0

    def test_query_entity_found(self, valid_auth, network_b, net_b_kp):
        protocol = LTPProtocol(network_b)
        entity = Entity(content=b"query test " * 5, shape="text/plain")
        entity_id, _, _ = protocol.commit(entity, net_b_kp)

        transport = InMemoryFederationTransport()
        transport.register_network("https://b.example.com", network_b)

        result = transport.query_entity("https://b.example.com", entity_id, valid_auth)
        assert result is not None
        assert result["found"] is True
        assert result["entity_id"] == entity_id

    def test_query_entity_not_found(self, valid_auth, network_b):
        transport = InMemoryFederationTransport()
        transport.register_network("https://b.example.com", network_b)

        result = transport.query_entity("https://b.example.com", "nonexistent-entity", valid_auth)
        assert result is None

    def test_unregistered_endpoint_returns_empty(self, valid_auth):
        transport = InMemoryFederationTransport()
        shards = transport.fetch_shards("https://unknown.com", "eid", [0], valid_auth)
        assert shards == {}

    def test_unregistered_endpoint_query_returns_none(self, valid_auth):
        transport = InMemoryFederationTransport()
        result = transport.query_entity("https://unknown.com", "eid", valid_auth)
        assert result is None


# ---------------------------------------------------------------------------
# Transport Auth Enforcement
# ---------------------------------------------------------------------------


class TestTransportAuth:
    def test_invalid_auth_fetch_rejected(self, net_a_kp, nir_a, nir_b, network_b, net_b_kp):
        """Fetch with half-signed (invalid) auth returns empty."""
        half = FederationAgreement.initiate(net_a_kp, nir_a, nir_b)
        bad_auth = FederationAuth(requester_nir=nir_a, agreement=half)

        protocol = LTPProtocol(network_b)
        entity = Entity(content=b"auth test " * 5, shape="text/plain")
        entity_id, _, _ = protocol.commit(entity, net_b_kp)

        transport = InMemoryFederationTransport()
        transport.register_network("https://b.example.com", network_b)

        shards = transport.fetch_shards("https://b.example.com", entity_id, [0], bad_auth)
        assert shards == {}

    def test_invalid_auth_query_rejected(self, net_a_kp, nir_a, nir_b, network_b):
        """Query with invalid auth returns None."""
        half = FederationAgreement.initiate(net_a_kp, nir_a, nir_b)
        bad_auth = FederationAuth(requester_nir=nir_a, agreement=half)

        transport = InMemoryFederationTransport()
        transport.register_network("https://b.example.com", network_b)

        result = transport.query_entity("https://b.example.com", "any-entity", bad_auth)
        assert result is None
