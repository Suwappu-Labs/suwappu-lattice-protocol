"""
TLS/mTLS configuration + network policy tests.

Tests TLSConfig, InMemoryCertManager certificate lifecycle,
and NetworkPolicy access control.
"""

from __future__ import annotations

import pytest

from src.ltp.observability.tls import (
    InMemoryCertManager,
    NetworkPolicy,
    NetworkPolicyRegistry,
    TLSConfig,
)

# ---------------------------------------------------------------------------
# TLSConfig
# ---------------------------------------------------------------------------


class TestTLSConfig:
    def test_default_disabled(self):
        cfg = TLSConfig()
        assert cfg.enabled is False
        assert cfg.is_mtls is False

    def test_mtls_config(self):
        cfg = TLSConfig(
            enabled=True,
            cert_path="/cert.pem",
            key_path="/key.pem",
            ca_path="/ca.pem",
            require_client_cert=True,
        )
        assert cfg.is_mtls is True
        assert cfg.min_version == "TLS1.3"

    def test_tls_without_client_cert(self):
        cfg = TLSConfig(enabled=True, require_client_cert=False)
        assert cfg.enabled is True
        assert cfg.is_mtls is False

    def test_frozen(self):
        cfg = TLSConfig(enabled=True)
        with pytest.raises(AttributeError):
            cfg.enabled = False


# ---------------------------------------------------------------------------
# InMemoryCertManager
# ---------------------------------------------------------------------------


class TestInMemoryCertManager:
    def test_provision_cert(self):
        mgr = InMemoryCertManager()
        cfg = mgr.provision("api-gateway")
        assert cfg.enabled is True
        assert cfg.service_id == "api-gateway"
        assert cfg.is_mtls is True  # Default require_client_cert=True

    def test_get_cert(self):
        mgr = InMemoryCertManager()
        mgr.provision("log-service")
        cfg = mgr.get_cert("log-service")
        assert cfg is not None
        assert cfg.service_id == "log-service"

    def test_get_unknown_returns_none(self):
        mgr = InMemoryCertManager()
        assert mgr.get_cert("unknown") is None

    def test_rotate_cert(self):
        mgr = InMemoryCertManager()
        cfg1 = mgr.provision("shard-node")
        cfg2 = mgr.rotate_cert("shard-node")
        # New cert has different path
        assert cfg1.cert_path != cfg2.cert_path
        assert cfg2.service_id == "shard-node"

    def test_rotate_unknown_raises(self):
        mgr = InMemoryCertManager()
        with pytest.raises(KeyError, match="No certificate"):
            mgr.rotate_cert("nonexistent")

    def test_list_certs(self):
        mgr = InMemoryCertManager()
        mgr.provision("svc-a")
        mgr.provision("svc-b")
        certs = mgr.list_certs()
        assert len(certs) == 2
        ids = {c["service_id"] for c in certs}
        assert ids == {"svc-a", "svc-b"}


# ---------------------------------------------------------------------------
# NetworkPolicy
# ---------------------------------------------------------------------------


class TestNetworkPolicy:
    def test_allow_list(self):
        policy = NetworkPolicy(
            service_id="shard-node",
            allowed_callers=["protocol-service", "log-service"],
        )
        assert policy.is_allowed("protocol-service") is True
        assert policy.is_allowed("log-service") is True
        assert policy.is_allowed("unknown-caller") is False

    def test_deny_list_overrides_allow(self):
        policy = NetworkPolicy(
            service_id="shard-node",
            allowed_callers=["protocol-service", "bad-actor"],
            denied_callers=["bad-actor"],
        )
        assert policy.is_allowed("protocol-service") is True
        assert policy.is_allowed("bad-actor") is False  # Deny wins

    def test_empty_allow_means_all_allowed(self):
        policy = NetworkPolicy(service_id="public-api")
        assert policy.is_allowed("anyone") is True

    def test_deny_only(self):
        policy = NetworkPolicy(
            service_id="api-gateway",
            denied_callers=["blocked-ip"],
        )
        assert policy.is_allowed("normal-client") is True
        assert policy.is_allowed("blocked-ip") is False


# ---------------------------------------------------------------------------
# NetworkPolicyRegistry
# ---------------------------------------------------------------------------


class TestNetworkPolicyRegistry:
    def test_register_and_check(self):
        reg = NetworkPolicyRegistry()
        reg.register_policy(
            NetworkPolicy(
                service_id="shard-node",
                allowed_callers=["protocol-service"],
            )
        )
        assert reg.check_access("shard-node", "protocol-service") is True
        assert reg.check_access("shard-node", "random") is False

    def test_no_policy_default_allow(self):
        reg = NetworkPolicyRegistry()
        assert reg.check_access("unmanaged-service", "anyone") is True

    def test_policy_count(self):
        reg = NetworkPolicyRegistry()
        reg.register_policy(NetworkPolicy(service_id="a"))
        reg.register_policy(NetworkPolicy(service_id="b"))
        assert reg.policy_count == 2
