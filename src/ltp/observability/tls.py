"""
TLS/mTLS configuration and network policy abstractions for ETP.

Provides:
  - TLSConfig: Immutable TLS/mTLS settings for a service
  - CertificateManager ABC: Certificate lifecycle (get, rotate, list)
  - InMemoryCertManager: Simulated cert manager for testing
  - NetworkPolicy: Declarative caller-level access control
  - NetworkPolicyRegistry: Manages policies for all services

Production: cert-manager (Kubernetes), AWS ACM, Let's Encrypt.
Development/Test: InMemoryCertManager with simulated self-signed certs.
"""

from __future__ import annotations

import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

__all__ = [
    "TLSConfig",
    "CertificateManager",
    "InMemoryCertManager",
    "NetworkPolicy",
    "NetworkPolicyRegistry",
    "ETPSecurityConfig",
]


@dataclass(frozen=True)
class TLSConfig:
    """TLS/mTLS configuration for a service endpoint."""

    enabled: bool = False
    cert_path: str = ""
    key_path: str = ""
    ca_path: str = ""
    require_client_cert: bool = False
    min_version: str = "TLS1.3"
    service_id: str = ""

    @property
    def is_mtls(self) -> bool:
        """True if mutual TLS is configured (client cert required)."""
        return self.enabled and self.require_client_cert


class CertificateManager(ABC):
    """Abstract certificate lifecycle manager."""

    @abstractmethod
    def get_cert(self, service_id: str) -> Optional[TLSConfig]:
        """Get the current TLS config for a service. None if not managed."""
        ...

    @abstractmethod
    def rotate_cert(self, service_id: str) -> TLSConfig:
        """Rotate the certificate for a service. Returns new config."""
        ...

    @abstractmethod
    def list_certs(self) -> list[dict]:
        """List all managed certificates with metadata."""
        ...


class InMemoryCertManager(CertificateManager):
    """In-memory certificate manager for testing.

    Generates simulated self-signed TLS configs. No real crypto —
    cert_path/key_path are synthetic identifiers.
    """

    def __init__(self) -> None:
        self._certs: dict[str, TLSConfig] = {}
        self._rotations: dict[str, int] = {}

    def provision(
        self,
        service_id: str,
        require_client_cert: bool = True,
    ) -> TLSConfig:
        """Provision a new certificate for a service."""
        cert_id = str(uuid.uuid4())[:8]
        config = TLSConfig(
            enabled=True,
            cert_path=f"/certs/{service_id}/{cert_id}.pem",
            key_path=f"/certs/{service_id}/{cert_id}.key",
            ca_path="/certs/ca-bundle.pem",
            require_client_cert=require_client_cert,
            min_version="TLS1.3",
            service_id=service_id,
        )
        self._certs[service_id] = config
        self._rotations[service_id] = 1
        return config

    def get_cert(self, service_id: str) -> Optional[TLSConfig]:
        return self._certs.get(service_id)

    def rotate_cert(self, service_id: str) -> TLSConfig:
        if service_id not in self._certs:
            raise KeyError(f"No certificate for service {service_id!r}")
        self._rotations[service_id] = self._rotations.get(service_id, 0) + 1
        return self.provision(
            service_id,
            require_client_cert=self._certs[service_id].require_client_cert,
        )

    def list_certs(self) -> list[dict]:
        return [
            {
                "service_id": sid,
                "cert_path": cfg.cert_path,
                "is_mtls": cfg.is_mtls,
                "rotations": self._rotations.get(sid, 0),
            }
            for sid, cfg in self._certs.items()
        ]


@dataclass
class NetworkPolicy:
    """Declarative network access policy for a service.

    Defines which callers are allowed or denied access.
    Deny takes precedence over allow.
    """

    service_id: str
    allowed_callers: list[str] = field(default_factory=list)
    denied_callers: list[str] = field(default_factory=list)

    def is_allowed(self, caller_id: str) -> bool:
        """Check if a caller is allowed to connect.

        Logic: deny list checked first (explicit deny wins),
        then allow list (if non-empty, only listed callers allowed),
        then default allow (if allow list is empty, all allowed).
        """
        if caller_id in self.denied_callers:
            return False
        if self.allowed_callers:
            return caller_id in self.allowed_callers
        return True  # No allow list = allow all (except denied)


class NetworkPolicyRegistry:
    """Manages network policies for all services."""

    def __init__(self) -> None:
        self._policies: dict[str, NetworkPolicy] = {}

    def register_policy(self, policy: NetworkPolicy) -> None:
        """Register a network policy for a service."""
        self._policies[policy.service_id] = policy

    def check_access(self, service_id: str, caller_id: str) -> bool:
        """Check if a caller can access a service.

        Returns True if no policy exists (default-allow).
        """
        policy = self._policies.get(service_id)
        if policy is None:
            return True
        return policy.is_allowed(caller_id)

    def get_policy(self, service_id: str) -> Optional[NetworkPolicy]:
        return self._policies.get(service_id)

    @property
    def policy_count(self) -> int:
        return len(self._policies)


class ETPSecurityConfig:
    """Bundles mTLS + network policies for an ETP node.

    Provides a CertificateManager for TLS cert lifecycle and a
    NetworkPolicyRegistry with default ETP service access policies.

    Default policies (from deployment plan):
      - shard-node: accept only from protocol-service
      - log-service: accept only from protocol-service + api-gateway
      - api-gateway: accept all (public-facing)
    """

    def __init__(
        self,
        cert_manager: Optional[CertificateManager] = None,
    ) -> None:
        self.cert_manager = cert_manager or InMemoryCertManager()
        self.policies = NetworkPolicyRegistry()

    @classmethod
    def default(cls) -> "ETPSecurityConfig":
        """Create default ETP security config with standard policies."""
        config = cls()

        # Default network access policies from the deployment plan
        config.policies.register_policy(
            NetworkPolicy(
                service_id="shard-node",
                allowed_callers=["protocol-service"],
            )
        )
        config.policies.register_policy(
            NetworkPolicy(
                service_id="log-service",
                allowed_callers=["protocol-service", "api-gateway"],
            )
        )
        config.policies.register_policy(
            NetworkPolicy(
                service_id="api-gateway",
                allowed_callers=[],  # Empty = accept all
            )
        )

        return config
