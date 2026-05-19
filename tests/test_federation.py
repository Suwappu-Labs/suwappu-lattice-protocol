"""Tests for Cross-Deployment Federation (Open Question 7)."""

import pytest

from src.ltp.federation import (
    DiscoveryMethod,
    EntityResolution,
    FederatedNetwork,
    FederationConfig,
    FederationRegistry,
    TrustLevel,
)

# ---------------------------------------------------------------------------
# FederationConfig
# ---------------------------------------------------------------------------


class TestFederationConfig:
    def test_defaults(self):
        cfg = FederationConfig()
        assert cfg.enabled is False
        assert cfg.discovery_method == DiscoveryMethod.STATIC
        assert cfg.min_trust_for_resolution == TrustLevel.VERIFIED
        assert cfg.max_resolution_hops == 2

    def test_custom(self):
        cfg = FederationConfig(
            enabled=True,
            discovery_method=DiscoveryMethod.DNS,
            min_trust_for_resolution=TrustLevel.FEDERATED,
        )
        assert cfg.enabled is True
        assert cfg.discovery_method == DiscoveryMethod.DNS


# ---------------------------------------------------------------------------
# FederatedNetwork
# ---------------------------------------------------------------------------


class TestFederatedNetwork:
    def test_defaults(self):
        net = FederatedNetwork(
            network_id="net-1",
            display_name="Network One",
            discovery_endpoint="https://net1.example.com",
            public_key=b"pk-1",
        )
        assert net.trust_level == TrustLevel.UNTRUSTED
        assert net.is_trusted is False
        assert net.is_federated is False

    def test_verified_is_trusted(self):
        net = FederatedNetwork(
            network_id="net-1",
            display_name="Network One",
            discovery_endpoint="https://net1.example.com",
            public_key=b"pk-1",
            trust_level=TrustLevel.VERIFIED,
        )
        assert net.is_trusted is True
        assert net.is_federated is False

    def test_federated_is_trusted_and_federated(self):
        net = FederatedNetwork(
            network_id="net-1",
            display_name="Network One",
            discovery_endpoint="https://net1.example.com",
            public_key=b"pk-1",
            trust_level=TrustLevel.FEDERATED,
        )
        assert net.is_trusted is True
        assert net.is_federated is True


# ---------------------------------------------------------------------------
# EntityResolution
# ---------------------------------------------------------------------------


class TestEntityResolution:
    def test_local_resolution(self):
        r = EntityResolution(entity_id="e1", found=True)
        assert r.found is True
        assert r.is_cross_network is False

    def test_cross_network_resolution(self):
        r = EntityResolution(
            entity_id="e1",
            found=True,
            home_network_id="net-2",
        )
        assert r.is_cross_network is True

    def test_not_found(self):
        r = EntityResolution(entity_id="e1", found=False)
        assert r.is_cross_network is False


# ---------------------------------------------------------------------------
# FederationRegistry — registration
# ---------------------------------------------------------------------------


class TestFederationRegistryRegistration:
    def setup_method(self):
        self.reg = FederationRegistry(FederationConfig(enabled=True))
        self.reg.set_local_network_id("local-net")

    def test_register_network(self):
        net = self.reg.register_network("net-1", "Network One", "https://net1.example.com", b"pk-1")
        assert net.network_id == "net-1"
        assert net.trust_level == TrustLevel.UNTRUSTED
        assert len(self.reg.all_networks) == 1

    def test_duplicate_registration_fails(self):
        self.reg.register_network("net-1", "N1", "url1", b"pk")
        with pytest.raises(ValueError, match="already registered"):
            self.reg.register_network("net-1", "N1 dup", "url2", b"pk2")

    def test_self_registration_fails(self):
        with pytest.raises(ValueError, match="Cannot register self"):
            self.reg.register_network("local-net", "Self", "url", b"pk")

    def test_unregister_network(self):
        self.reg.register_network("net-1", "N1", "url", b"pk")
        assert self.reg.unregister_network("net-1") is True
        assert len(self.reg.all_networks) == 0

    def test_unregister_nonexistent(self):
        assert self.reg.unregister_network("no-such-net") is False

    def test_unregister_clears_resolution_cache(self):
        self.reg.register_network("net-1", "N1", "url", b"pk")
        self.reg.register_resolution("entity-x", "net-1")
        self.reg.unregister_network("net-1")
        # Resolution should no longer find it
        r = self.reg.resolve_entity("entity-x")
        assert r.found is False


# ---------------------------------------------------------------------------
# FederationRegistry — trust management
# ---------------------------------------------------------------------------


class TestFederationRegistryTrust:
    def setup_method(self):
        self.reg = FederationRegistry(FederationConfig(enabled=True))
        self.reg.set_local_network_id("local-net")
        self.reg.register_network("net-1", "N1", "url", b"pk")

    def test_upgrade_untrusted_to_verified(self):
        assert self.reg.upgrade_trust("net-1", TrustLevel.VERIFIED) is True
        assert self.reg.get_network("net-1").trust_level == TrustLevel.VERIFIED

    def test_upgrade_verified_to_federated(self):
        self.reg.upgrade_trust("net-1", TrustLevel.VERIFIED)
        assert self.reg.upgrade_trust("net-1", TrustLevel.FEDERATED) is True
        assert self.reg.get_network("net-1").trust_level == TrustLevel.FEDERATED

    def test_cannot_downgrade_via_upgrade(self):
        self.reg.upgrade_trust("net-1", TrustLevel.FEDERATED)
        assert self.reg.upgrade_trust("net-1", TrustLevel.VERIFIED) is False

    def test_upgrade_same_level_fails(self):
        assert self.reg.upgrade_trust("net-1", TrustLevel.UNTRUSTED) is False

    def test_upgrade_nonexistent_fails(self):
        assert self.reg.upgrade_trust("nope", TrustLevel.VERIFIED) is False

    def test_revoke_trust(self):
        self.reg.upgrade_trust("net-1", TrustLevel.FEDERATED)
        assert self.reg.revoke_trust("net-1") is True
        assert self.reg.get_network("net-1").trust_level == TrustLevel.UNTRUSTED

    def test_revoke_nonexistent(self):
        assert self.reg.revoke_trust("nope") is False

    def test_verified_networks_property(self):
        assert len(self.reg.verified_networks) == 0
        self.reg.upgrade_trust("net-1", TrustLevel.VERIFIED)
        assert len(self.reg.verified_networks) == 1

    def test_federated_networks_property(self):
        assert len(self.reg.federated_networks) == 0
        self.reg.upgrade_trust("net-1", TrustLevel.VERIFIED)
        self.reg.upgrade_trust("net-1", TrustLevel.FEDERATED)
        assert len(self.reg.federated_networks) == 1


# ---------------------------------------------------------------------------
# FederationRegistry — STH verification
# ---------------------------------------------------------------------------


class TestFederationRegistrySTH:
    def setup_method(self):
        from src.ltp.primitives import MLDSA

        self._vk, self._sk = MLDSA.keygen()
        self.reg = FederationRegistry(FederationConfig(enabled=True))
        self.reg.set_local_network_id("local-net")
        self.reg.register_network("net-1", "N1", "url", self._vk)

    def _make_sth(self, seq=1, root="abc", ts=1000.0, count=10):
        import struct

        from src.ltp.primitives import MLDSA

        sth = {
            "sequence": seq,
            "root_hash": root,
            "timestamp": ts,
            "record_count": count,
        }
        # Create real ML-DSA-65 signature over the STH payload
        payload = struct.pack(">Qd", seq, ts) + str(root).encode()
        sth["signable_payload"] = payload
        sth["signature"] = MLDSA.sign(self._sk, payload)
        return sth

    def test_verify_sth_success(self):
        sth = self._make_sth()
        assert self.reg.verify_sth("net-1", sth, current_epoch=100) is True
        net = self.reg.get_network("net-1")
        assert net.last_sth == sth
        assert net.last_sth_verified_epoch == 100
        assert net.entity_count == 10

    def test_verify_sth_auto_upgrades_trust(self):
        sth = self._make_sth()
        self.reg.verify_sth("net-1", sth, current_epoch=100)
        assert self.reg.get_network("net-1").trust_level == TrustLevel.VERIFIED

    def test_verify_sth_missing_fields(self):
        bad_sth = {"sequence": 1}
        assert self.reg.verify_sth("net-1", bad_sth, current_epoch=100) is False

    def test_verify_sth_monotonicity_sequence(self):
        self.reg.verify_sth("net-1", self._make_sth(seq=5, ts=1000), 100)
        # Same or lower sequence should fail
        assert self.reg.verify_sth("net-1", self._make_sth(seq=5, ts=1001), 101) is False
        assert self.reg.verify_sth("net-1", self._make_sth(seq=3, ts=1001), 101) is False

    def test_verify_sth_monotonicity_timestamp(self):
        self.reg.verify_sth("net-1", self._make_sth(seq=5, ts=1000), 100)
        # Higher sequence but lower timestamp should fail
        assert self.reg.verify_sth("net-1", self._make_sth(seq=6, ts=999), 101) is False

    def test_verify_sth_nonexistent_network(self):
        assert self.reg.verify_sth("nope", self._make_sth(), 100) is False

    def test_successive_sth_updates(self):
        self.reg.verify_sth("net-1", self._make_sth(seq=1, ts=100), 1)
        self.reg.verify_sth("net-1", self._make_sth(seq=2, ts=200, count=20), 2)
        net = self.reg.get_network("net-1")
        assert net.last_sth["sequence"] == 2
        assert net.entity_count == 20


# ---------------------------------------------------------------------------
# FederationRegistry — entity resolution
# ---------------------------------------------------------------------------


class TestFederationRegistryResolution:
    def setup_method(self):
        self.reg = FederationRegistry(FederationConfig(enabled=True))
        self.reg.set_local_network_id("local-net")

    def test_resolve_local_entity(self):
        self.reg.register_local_entity("entity-local")
        r = self.reg.resolve_entity("entity-local")
        assert r.found is True
        assert r.home_network_id == "local-net"
        assert r.trust_level == TrustLevel.FEDERATED

    def test_resolve_cached_entity(self):
        self.reg.register_network("net-1", "N1", "url", b"pk")
        self.reg.register_resolution("entity-remote", "net-1")
        r = self.reg.resolve_entity("entity-remote")
        assert r.found is True
        assert r.home_network_id == "net-1"

    def test_resolve_not_found(self):
        r = self.reg.resolve_entity("entity-unknown")
        assert r.found is False

    def test_register_resolution_unknown_network(self):
        assert self.reg.register_resolution("e1", "no-such-net") is False

    def test_register_resolution_known_network(self):
        self.reg.register_network("net-1", "N1", "url", b"pk")
        assert self.reg.register_resolution("e1", "net-1") is True

    def test_resolution_time_is_populated(self):
        self.reg.register_local_entity("entity-local")
        r = self.reg.resolve_entity("entity-local")
        assert r.resolution_time_ms >= 0


# ---------------------------------------------------------------------------
# FederationRegistry — default config
# ---------------------------------------------------------------------------


class TestFederationRegistryDefaults:
    def test_default_config(self):
        reg = FederationRegistry()
        assert reg.config.enabled is False
        assert len(reg.all_networks) == 0

    def test_get_nonexistent_network(self):
        reg = FederationRegistry()
        assert reg.get_network("nope") is None
