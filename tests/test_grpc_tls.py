"""
Tests for gRPC TLS/mTLS credential loading, secure channels,
network policy interceptor, and NodeConfig TLS fields.
"""

from __future__ import annotations

import os
import tempfile

import pytest

from src.ltp.network.credentials import (
    load_channel_credentials,
    load_server_credentials,
)
from src.ltp.network.interceptors import NetworkPolicyInterceptor
from src.ltp.node.config import NodeConfig
from src.ltp.observability.tls import (
    NetworkPolicy,
    NetworkPolicyRegistry,
    TLSConfig,
)

# ---------------------------------------------------------------------------
# Fixtures: self-signed test certs
# ---------------------------------------------------------------------------


def _generate_self_signed_cert(directory: str, name: str = "server"):
    """Generate a real self-signed cert + key using cryptography library."""
    try:
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, f"{name}.etp.test"),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        cert_path = os.path.join(directory, f"{name}.pem")
        key_path = os.path.join(directory, f"{name}.key")
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as f:
            f.write(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
            )
        return cert_path, key_path
    except ImportError:
        # Fallback: generate via openssl subprocess
        import subprocess

        cert_path = os.path.join(directory, f"{name}.pem")
        key_path = os.path.join(directory, f"{name}.key")
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                key_path,
                "-out",
                cert_path,
                "-days",
                "1",
                "-nodes",
                "-subj",
                f"/CN={name}.etp.test",
            ],
            check=True,
            capture_output=True,
        )
        return cert_path, key_path


@pytest.fixture
def cert_dir():
    """Create a temp directory with real self-signed cert/key/CA for testing."""
    with tempfile.TemporaryDirectory() as d:
        ca_cert, ca_key = _generate_self_signed_cert(d, "ca")
        server_cert, server_key = _generate_self_signed_cert(d, "server")
        yield {"dir": d, "cert": server_cert, "key": server_key, "ca": ca_cert}


# ---------------------------------------------------------------------------
# Credential Loading
# ---------------------------------------------------------------------------


class TestLoadServerCredentials:
    def test_disabled_returns_none(self):
        config = TLSConfig(enabled=False)
        result = load_server_credentials(config)
        assert result is None

    def test_enabled_loads_credentials(self, cert_dir):
        config = TLSConfig(
            enabled=True,
            cert_path=cert_dir["cert"],
            key_path=cert_dir["key"],
            ca_path=cert_dir["ca"],
            require_client_cert=True,
        )
        creds = load_server_credentials(config)
        assert creds is not None

    def test_missing_cert_raises(self):
        config = TLSConfig(
            enabled=True,
            cert_path="/nonexistent/cert.pem",
            key_path="/nonexistent/key.pem",
        )
        with pytest.raises(FileNotFoundError):
            load_server_credentials(config)

    def test_empty_paths_raises(self):
        config = TLSConfig(enabled=True, cert_path="", key_path="")
        with pytest.raises(ValueError, match="cert_path or key_path is empty"):
            load_server_credentials(config)

    def test_no_ca_path_works(self, cert_dir):
        config = TLSConfig(
            enabled=True,
            cert_path=cert_dir["cert"],
            key_path=cert_dir["key"],
            ca_path="",
            require_client_cert=False,
        )
        creds = load_server_credentials(config)
        assert creds is not None


class TestLoadChannelCredentials:
    def test_disabled_returns_none(self):
        config = TLSConfig(enabled=False)
        result = load_channel_credentials(config)
        assert result is None

    def test_enabled_loads_credentials(self, cert_dir):
        config = TLSConfig(
            enabled=True,
            cert_path=cert_dir["cert"],
            key_path=cert_dir["key"],
            ca_path=cert_dir["ca"],
        )
        creds = load_channel_credentials(config)
        assert creds is not None

    def test_ca_only_no_client_cert(self, cert_dir):
        config = TLSConfig(
            enabled=True,
            cert_path="",
            key_path="",
            ca_path=cert_dir["ca"],
        )
        creds = load_channel_credentials(config)
        assert creds is not None


# ---------------------------------------------------------------------------
# Network Policy Interceptor
# ---------------------------------------------------------------------------


class TestNetworkPolicyInterceptor:
    def test_no_registry_allows_all(self):
        interceptor = NetworkPolicyInterceptor(policy_registry=None)
        # Mock handler_call_details
        called = [False]

        def mock_continuation(details):
            called[0] = True
            return "handler"

        class MockDetails:
            invocation_metadata = []

        result = interceptor.intercept_service(mock_continuation, MockDetails())
        assert called[0] is True
        assert result == "handler"

    def test_allowed_caller_passes(self):
        registry = NetworkPolicyRegistry()
        registry.register_policy(
            NetworkPolicy(
                service_id="etp-node",
                allowed_callers=["trusted-peer"],
            )
        )

        interceptor = NetworkPolicyInterceptor(
            policy_registry=registry,
            service_id="etp-node",
        )
        called = [False]

        def mock_continuation(details):
            called[0] = True
            return "handler"

        class MockDetails:
            invocation_metadata = [("x-caller-id", "trusted-peer")]

        result = interceptor.intercept_service(mock_continuation, MockDetails())
        assert called[0] is True

    def test_denied_caller_rejected(self):
        registry = NetworkPolicyRegistry()
        registry.register_policy(
            NetworkPolicy(
                service_id="etp-node",
                allowed_callers=["trusted-peer"],
            )
        )

        interceptor = NetworkPolicyInterceptor(
            policy_registry=registry,
            service_id="etp-node",
        )
        called = [False]

        def mock_continuation(details):
            called[0] = True
            return "handler"

        class MockDetails:
            invocation_metadata = [("x-caller-id", "untrusted")]

        result = interceptor.intercept_service(mock_continuation, MockDetails())
        assert called[0] is False  # Continuation not called

    def test_no_caller_id_with_allow_list_rejected(self):
        registry = NetworkPolicyRegistry()
        registry.register_policy(
            NetworkPolicy(
                service_id="etp-node",
                allowed_callers=["trusted-peer"],
            )
        )

        interceptor = NetworkPolicyInterceptor(
            policy_registry=registry,
            service_id="etp-node",
        )

        class MockDetails:
            invocation_metadata = []

        # Empty caller ID doesn't match allow list
        called = [False]

        def mock_continuation(details):
            called[0] = True
            return "handler"

        interceptor.intercept_service(mock_continuation, MockDetails())
        # Empty string is not in allowed_callers, so should be denied
        assert called[0] is False


# ---------------------------------------------------------------------------
# NodeConfig TLS Fields
# ---------------------------------------------------------------------------


class TestNodeConfigTLS:
    def test_defaults(self):
        config = NodeConfig()
        assert config.tls_enabled is False
        assert config.tls_cert_path == ""
        assert config.tls_key_path == ""
        assert config.tls_ca_path == ""
        assert config.tls_require_client_cert is True

    def test_from_env(self):
        env = {
            "ETP_TLS_ENABLED": "true",
            "ETP_TLS_CERT_PATH": "/certs/server.pem",
            "ETP_TLS_KEY_PATH": "/certs/server.key",
            "ETP_TLS_CA_PATH": "/certs/ca.pem",
            "ETP_TLS_REQUIRE_CLIENT_CERT": "false",
        }
        for k, v in env.items():
            os.environ[k] = v
        try:
            config = NodeConfig.from_env()
            assert config.tls_enabled is True
            assert config.tls_cert_path == "/certs/server.pem"
            assert config.tls_key_path == "/certs/server.key"
            assert config.tls_ca_path == "/certs/ca.pem"
            assert config.tls_require_client_cert is False
        finally:
            for k in env:
                os.environ.pop(k, None)


# ---------------------------------------------------------------------------
# NodeServer TLS Integration (unit level)
# ---------------------------------------------------------------------------


class TestNodeServerTLS:
    def test_insecure_port_when_tls_disabled(self):
        """NodeServer defaults to insecure port when no TLS config."""
        from src.ltp.commitment import CommitmentNode
        from src.ltp.network.server import NodeServer
        from src.ltp.storage import MemoryShardStore

        node = CommitmentNode("test-node", "test-region", MemoryShardStore())
        server = NodeServer(node, port=0)
        assert server.port >= 0  # Port bound successfully
        server.start()
        server.stop()

    def test_tls_config_accepted(self, cert_dir):
        """NodeServer accepts TLS config without crashing."""
        from src.ltp.commitment import CommitmentNode
        from src.ltp.network.server import NodeServer
        from src.ltp.storage import MemoryShardStore

        tls = TLSConfig(
            enabled=True,
            cert_path=cert_dir["cert"],
            key_path=cert_dir["key"],
            ca_path=cert_dir["ca"],
            require_client_cert=True,
        )
        node = CommitmentNode("test-node", "test-region", MemoryShardStore())
        # This will attempt to create a secure port.
        # The self-signed PEM files aren't valid crypto, but gRPC accepts
        # the credential objects — connection would fail at handshake, not creation.
        server = NodeServer(node, port=0, tls_config=tls)
        assert server.port >= 0
        server.start()
        server.stop()
