"""
Network Identity Record (NIR) + discovery service tests.

Tests NIR creation/verification, static and DNS discovery services,
and FederationRegistry NIR integration.
"""

from __future__ import annotations

import pytest

from src.ltp import KeyPair
from src.ltp.federation import (
    DNSDiscoveryService,
    FederationConfig,
    FederationRegistry,
    NetworkIdentityRecord,
    StaticDiscoveryService,
    TrustLevel,
)
from src.ltp.primitives import canonical_hash_bytes

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def operator() -> KeyPair:
    return KeyPair.generate("nir-operator")


@pytest.fixture(scope="session")
def other_operator() -> KeyPair:
    return KeyPair.generate("nir-other-operator")


def _genesis_root() -> bytes:
    return b"\xaa" * 32


# ---------------------------------------------------------------------------
# NetworkIdentityRecord
# ---------------------------------------------------------------------------


class TestNetworkIdentityRecord:
    def test_create_nir(self, operator):
        nir = NetworkIdentityRecord.create(
            operator,
            _genesis_root(),
            0,
            "GSX Testnet",
            "https://gsx.example.com",
        )
        assert nir.network_id != ""
        assert nir.operator_vk == operator.vk
        assert nir.genesis_sth_root == _genesis_root()
        assert nir.display_name == "GSX Testnet"
        assert len(nir.signature) > 0

    def test_verify_signature(self, operator):
        nir = NetworkIdentityRecord.create(
            operator,
            _genesis_root(),
            0,
            "Test Net",
            "https://test.example.com",
        )
        assert nir.verify() is True

    def test_tampered_nir_rejected(self, operator):
        nir = NetworkIdentityRecord.create(
            operator,
            _genesis_root(),
            0,
            "Test",
            "https://test.com",
        )
        # Create a tampered NIR with different display_name but same signature
        tampered = NetworkIdentityRecord(
            network_id=nir.network_id,
            operator_vk=nir.operator_vk,
            genesis_sth_root=nir.genesis_sth_root,
            genesis_sth_sequence=nir.genesis_sth_sequence,
            display_name="TAMPERED NAME",
            discovery_endpoint=nir.discovery_endpoint,
            created_at=nir.created_at,
            signature=nir.signature,
        )
        assert tampered.verify() is False

    def test_network_id_is_deterministic(self, operator):
        """Same genesis root + same operator → same network_id."""
        root = b"\xbb" * 32
        nir1 = NetworkIdentityRecord.create(operator, root, 0, "A", "http://a")
        nir2 = NetworkIdentityRecord.create(operator, root, 0, "B", "http://b")
        assert nir1.network_id == nir2.network_id

    def test_different_root_different_id(self, operator):
        nir1 = NetworkIdentityRecord.create(operator, b"\x11" * 32, 0, "A", "http://a")
        nir2 = NetworkIdentityRecord.create(operator, b"\x22" * 32, 0, "A", "http://a")
        assert nir1.network_id != nir2.network_id

    def test_different_operator_different_id(self, operator, other_operator):
        root = b"\xcc" * 32
        nir1 = NetworkIdentityRecord.create(operator, root, 0, "A", "http://a")
        nir2 = NetworkIdentityRecord.create(other_operator, root, 0, "A", "http://a")
        assert nir1.network_id != nir2.network_id

    def test_canonical_bytes_deterministic(self, operator):
        nir = NetworkIdentityRecord.create(operator, _genesis_root(), 0, "Det", "http://det")
        assert nir.canonical_bytes() == nir.canonical_bytes()


# ---------------------------------------------------------------------------
# StaticDiscoveryService
# ---------------------------------------------------------------------------


class TestStaticDiscovery:
    def test_publish_and_discover(self, operator):
        svc = StaticDiscoveryService()
        nir = NetworkIdentityRecord.create(operator, _genesis_root(), 0, "Net A", "http://a")
        assert svc.publish(nir) is True
        discovered = svc.discover()
        assert len(discovered) == 1
        assert discovered[0].network_id == nir.network_id

    def test_resolve_by_network_id(self, operator):
        svc = StaticDiscoveryService()
        nir = NetworkIdentityRecord.create(operator, _genesis_root(), 0, "Net B", "http://b")
        svc.publish(nir)
        resolved = svc.resolve(nir.network_id)
        assert resolved is not None
        assert resolved.display_name == "Net B"

    def test_resolve_unknown_returns_none(self):
        svc = StaticDiscoveryService()
        assert svc.resolve("nonexistent") is None

    def test_discover_with_query(self, operator, other_operator):
        svc = StaticDiscoveryService()
        svc.publish(
            NetworkIdentityRecord.create(operator, b"\x01" * 32, 0, "Alpha Net", "http://alpha")
        )
        svc.publish(
            NetworkIdentityRecord.create(other_operator, b"\x02" * 32, 0, "Beta Net", "http://beta")
        )
        results = svc.discover("Alpha")
        assert len(results) == 1
        assert results[0].display_name == "Alpha Net"


# ---------------------------------------------------------------------------
# DNSDiscoveryService
# ---------------------------------------------------------------------------


class TestDNSDiscovery:
    def test_publish_and_discover(self, operator):
        svc = DNSDiscoveryService()
        nir = NetworkIdentityRecord.create(
            operator, _genesis_root(), 0, "DNS Net", "dns.example.com"
        )
        assert svc.publish(nir) is True
        assert len(svc.discover()) == 1

    def test_resolve_by_network_id(self, operator):
        svc = DNSDiscoveryService()
        nir = NetworkIdentityRecord.create(operator, _genesis_root(), 0, "DNS", "dns.test.com")
        svc.publish(nir)
        resolved = svc.resolve(nir.network_id)
        assert resolved is not None

    def test_discover_by_domain(self, operator):
        svc = DNSDiscoveryService()
        svc.publish(
            NetworkIdentityRecord.create(operator, b"\x01" * 32, 0, "A", "alpha.example.com")
        )
        results = svc.discover("alpha")
        assert len(results) == 1


# ---------------------------------------------------------------------------
# FederationRegistry NIR Integration
# ---------------------------------------------------------------------------


class TestFederationRegistryNIR:
    def test_register_from_nir(self, operator):
        registry = FederationRegistry()
        nir = NetworkIdentityRecord.create(operator, _genesis_root(), 0, "NIR Net", "http://nir")
        network = registry.register_from_nir(nir)
        assert network.network_id == nir.network_id
        assert network.display_name == "NIR Net"
        assert network.public_key == operator.vk
        assert network.trust_level == TrustLevel.UNTRUSTED

    def test_invalid_nir_rejected(self, operator):
        registry = FederationRegistry()
        nir = NetworkIdentityRecord.create(operator, _genesis_root(), 0, "Bad", "http://bad")
        # Create tampered NIR
        tampered = NetworkIdentityRecord(
            network_id=nir.network_id,
            operator_vk=nir.operator_vk,
            genesis_sth_root=nir.genesis_sth_root,
            genesis_sth_sequence=nir.genesis_sth_sequence,
            display_name="TAMPERED",
            discovery_endpoint=nir.discovery_endpoint,
            created_at=nir.created_at,
            signature=nir.signature,
        )
        with pytest.raises(ValueError, match="NIR signature verification failed"):
            registry.register_from_nir(tampered)

    def test_duplicate_nir_rejected(self, operator):
        registry = FederationRegistry()
        nir = NetworkIdentityRecord.create(operator, _genesis_root(), 0, "Dup", "http://dup")
        registry.register_from_nir(nir)
        with pytest.raises(ValueError, match="already registered"):
            registry.register_from_nir(nir)


# ---------------------------------------------------------------------------
# Audit Fixes
# ---------------------------------------------------------------------------


class TestAuditFixes:
    def test_short_genesis_root_rejected(self, operator):
        """genesis_sth_root must be exactly 32 bytes."""
        with pytest.raises(ValueError, match="32 bytes"):
            NetworkIdentityRecord.create(operator, b"\xaa" * 16, 0, "Bad", "http://bad")

    def test_long_genesis_root_rejected(self, operator):
        with pytest.raises(ValueError, match="32 bytes"):
            NetworkIdentityRecord.create(operator, b"\xaa" * 64, 0, "Bad", "http://bad")

    def test_dns_no_collision_same_endpoint(self, operator, other_operator):
        """Two NIRs at the same endpoint should both be discoverable."""
        svc = DNSDiscoveryService()
        nir1 = NetworkIdentityRecord.create(operator, b"\x01" * 32, 0, "Net1", "shared.example.com")
        nir2 = NetworkIdentityRecord.create(
            other_operator, b"\x02" * 32, 0, "Net2", "shared.example.com"
        )
        svc.publish(nir1)
        svc.publish(nir2)
        all_nirs = svc.discover()
        assert len(all_nirs) == 2
        # Both resolvable by network_id
        assert svc.resolve(nir1.network_id) is not None
        assert svc.resolve(nir2.network_id) is not None
