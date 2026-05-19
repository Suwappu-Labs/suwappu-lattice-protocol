"""
CrossNetworkFetcher + remote resolution tests.

Tests resolve_entity() with transport, CrossNetworkFetcher shard
fetching, and auth integration.
"""

from __future__ import annotations

import struct

import pytest

from src.ltp import CommitmentNetwork, KeyPair, LTPProtocol
from src.ltp.entity import Entity
from src.ltp.federation import (
    CrossNetworkFetcher,
    FederationAgreement,
    FederationAuth,
    FederationConfig,
    FederationRegistry,
    InMemoryFederationTransport,
    NetworkIdentityRecord,
    TrustLevel,
)
from src.ltp.primitives import MLDSA


def _make_signed_sth(sk, seq=1, root="x", ts=1.0, count=1):
    """Create an STH dict with a real ML-DSA-65 signature."""
    sth = {"sequence": seq, "root_hash": root, "timestamp": ts, "record_count": count}
    payload = struct.pack(">Qd", seq, ts) + str(root).encode()
    sth["signable_payload"] = payload
    sth["signature"] = MLDSA.sign(sk, payload)
    return sth


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def kp_a() -> KeyPair:
    return KeyPair.generate("fetcher-a")


@pytest.fixture(scope="session")
def kp_b() -> KeyPair:
    return KeyPair.generate("fetcher-b")


@pytest.fixture
def nir_a(kp_a):
    return NetworkIdentityRecord.create(kp_a, b"\xaa" * 32, 0, "Net A", "https://a.net")


@pytest.fixture
def nir_b(kp_b):
    return NetworkIdentityRecord.create(kp_b, b"\xbb" * 32, 0, "Net B", "https://b.net")


@pytest.fixture
def network_b():
    net = CommitmentNetwork()
    for i in range(6):
        net.add_node(f"b-{i}", ["US-East", "US-West", "EU-West"][i % 3])
    return net


@pytest.fixture
def agreement(kp_a, kp_b, nir_a, nir_b):
    half = FederationAgreement.initiate(kp_a, nir_a, nir_b)
    return FederationAgreement.countersign(half, kp_b)


@pytest.fixture
def auth(nir_a, agreement):
    return FederationAuth(requester_nir=nir_a, agreement=agreement)


# ---------------------------------------------------------------------------
# resolve_entity with transport
# ---------------------------------------------------------------------------


class TestResolveEntityWithTransport:
    def test_remote_resolution_finds_entity(self, kp_a, kp_b, nir_a, nir_b, network_b, auth):
        """With transport, remote entity resolution works."""
        # Commit on network B
        protocol = LTPProtocol(network_b)
        entity = Entity(content=b"remote resolution test " * 5, shape="text/plain")
        entity_id, _, _ = protocol.commit(entity, kp_b)

        # Set up registry from A's perspective
        reg = FederationRegistry(FederationConfig(enabled=True))
        reg.set_local_network_id(nir_a.network_id)
        reg.register_from_nir(nir_b)
        reg.verify_sth(nir_b.network_id, _make_signed_sth(kp_b.sk), current_epoch=1)

        # Set up transport
        transport = InMemoryFederationTransport()
        transport.register_network("https://b.net", network_b)

        # Resolve
        result = reg.resolve_entity(entity_id, transport=transport, auth=auth)
        assert result.found is True
        assert result.home_network_id == nir_b.network_id
        assert result.resolution_hops == 1

    def test_resolution_caches_result(self, kp_a, kp_b, nir_a, nir_b, network_b, auth):
        """Second resolution for same entity uses cache."""
        protocol = LTPProtocol(network_b)
        entity = Entity(content=b"cache test " * 5, shape="text/plain")
        entity_id, _, _ = protocol.commit(entity, kp_b)

        reg = FederationRegistry(FederationConfig(enabled=True))
        reg.set_local_network_id(nir_a.network_id)
        reg.register_from_nir(nir_b)
        reg.verify_sth(nir_b.network_id, _make_signed_sth(kp_b.sk), current_epoch=1)

        transport = InMemoryFederationTransport()
        transport.register_network("https://b.net", network_b)

        # First resolution
        reg.resolve_entity(entity_id, transport=transport, auth=auth)
        # Second resolution — should hit cache (resolution_hops=0)
        result2 = reg.resolve_entity(entity_id, transport=transport, auth=auth)
        assert result2.found is True
        assert result2.resolution_hops == 0  # Cached

    def test_backward_compat_without_transport(self, kp_b, nir_a, nir_b, network_b):
        """Without transport, remote resolution returns not-found (backward compat)."""
        protocol = LTPProtocol(network_b)
        entity = Entity(content=b"compat test " * 5, shape="text/plain")
        entity_id, _, _ = protocol.commit(entity, kp_b)

        reg = FederationRegistry()
        reg.set_local_network_id(nir_a.network_id)
        reg.register_from_nir(nir_b)

        # No transport — remote query skipped
        result = reg.resolve_entity(entity_id)
        assert result.found is False


# ---------------------------------------------------------------------------
# CrossNetworkFetcher
# ---------------------------------------------------------------------------


class TestCrossNetworkFetcher:
    def test_fetch_from_federated_network(self, kp_a, kp_b, nir_a, nir_b, network_b, agreement):
        """Fetch shards from a federated network."""
        protocol = LTPProtocol(network_b)
        entity = Entity(content=b"cross-network fetch test " * 8, shape="text/plain")
        entity_id, _, _ = protocol.commit(entity, kp_b, n=6, k=3)

        reg = FederationRegistry(FederationConfig(enabled=True))
        reg.set_local_network_id(nir_a.network_id)
        reg.register_from_nir(nir_b)
        reg.verify_sth(nir_b.network_id, _make_signed_sth(kp_b.sk), current_epoch=1)

        transport = InMemoryFederationTransport()
        transport.register_network("https://b.net", network_b)

        fetcher = CrossNetworkFetcher(
            reg,
            transport,
            nir_a,
            {nir_b.network_id: agreement},
        )
        shards = fetcher.fetch_entity_shards(entity_id, [0, 1, 2])
        assert shards is not None
        assert len(shards) >= 1

    def test_unknown_entity_returns_none(self, kp_a, kp_b, nir_a, nir_b, network_b, agreement):
        reg = FederationRegistry(FederationConfig(enabled=True))
        reg.set_local_network_id(nir_a.network_id)
        reg.register_from_nir(nir_b)
        reg.verify_sth(nir_b.network_id, _make_signed_sth(kp_b.sk), current_epoch=1)

        transport = InMemoryFederationTransport()
        transport.register_network("https://b.net", network_b)

        fetcher = CrossNetworkFetcher(
            reg,
            transport,
            nir_a,
            {nir_b.network_id: agreement},
        )
        result = fetcher.fetch_entity_shards("nonexistent-entity", [0, 1])
        assert result is None

    def test_missing_agreement_returns_none(self, kp_a, kp_b, nir_a, nir_b, network_b):
        """No agreement for remote network → fetch fails."""
        protocol = LTPProtocol(network_b)
        entity = Entity(content=b"no agreement test " * 5, shape="text/plain")
        entity_id, _, _ = protocol.commit(entity, kp_b)

        reg = FederationRegistry(FederationConfig(enabled=True))
        reg.set_local_network_id(nir_a.network_id)
        reg.register_from_nir(nir_b)
        reg.verify_sth(nir_b.network_id, _make_signed_sth(kp_b.sk), current_epoch=1)

        transport = InMemoryFederationTransport()
        transport.register_network("https://b.net", network_b)

        # Empty agreements dict — no agreement for Net B
        fetcher = CrossNetworkFetcher(reg, transport, nir_a, {})
        result = fetcher.fetch_entity_shards(entity_id, [0, 1])
        assert result is None

    def test_no_agreements_at_all_returns_none(self, nir_a):
        """No agreements at all → resolution auth unavailable."""
        reg = FederationRegistry()
        reg.set_local_network_id(nir_a.network_id)
        transport = InMemoryFederationTransport()

        fetcher = CrossNetworkFetcher(reg, transport, nir_a, {})
        result = fetcher.fetch_entity_shards("any-entity", [0])
        assert result is None
