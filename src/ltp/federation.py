"""
Cross-deployment federation for the Lattice Transfer Protocol.

Enables independently bootstrapped LTP networks to discover each other,
establish trust, and resolve entities across network boundaries.

Whitepaper reference: Open Question 7
Design decision: docs/design-decisions/CROSS_DEPLOYMENT_FEDERATION.md
"""

from __future__ import annotations

import struct
import threading
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

from .domain import DOMAIN_FED_AGREEMENT, DOMAIN_NIR
from .primitives import MLDSA, canonical_hash, canonical_hash_bytes, internal_hash_bytes

__all__ = [
    "TrustLevel",
    "FederationConfig",
    "FederatedNetwork",
    "EntityResolution",
    "FederationRegistry",
    "NetworkIdentityRecord",
    "DiscoveryService",
    "StaticDiscoveryService",
    "DNSDiscoveryService",
    "DNSProvider",
    "LocalCacheDNSProvider",
    "Route53DNSProvider",
    "CloudflareDNSProvider",
    "FederationAgreement",
    "FederationAuth",
    "FederationTransport",
    "InMemoryFederationTransport",
    "CrossNetworkFetcher",
    "FederationRateLimiter",
]


class TrustLevel(Enum):
    """Trust level for a federated network."""

    UNTRUSTED = "untrusted"  # Discovered but not verified
    VERIFIED = "verified"  # STH exchange successful, identity confirmed
    FEDERATED = "federated"  # Full bidirectional federation established


class DiscoveryMethod(Enum):
    """How networks discover each other."""

    STATIC = "static"  # Manually configured
    DNS = "dns"  # DNS-based discovery (like ENR)
    ONCHAIN = "onchain"  # Shared L1 registry


@dataclass
class FederationConfig:
    """Configuration for federation behavior."""

    enabled: bool = False
    discovery_method: DiscoveryMethod = DiscoveryMethod.STATIC
    min_trust_for_resolution: TrustLevel = TrustLevel.VERIFIED
    sth_exchange_interval_epochs: int = 24  # Exchange STHs every 24 epochs
    max_resolution_hops: int = 2  # Max networks to traverse


@dataclass
class FederatedNetwork:
    """
    Represents a remote LTP network in the federation.

    Each federated network has:
      - A unique network_id derived from its genesis STH
      - A discovery endpoint for entity resolution
      - A public key for STH signature verification
      - Trust level tracking for progressive trust establishment
    """

    network_id: str  # Unique identifier (H(genesis_sth))
    display_name: str  # Human-readable name
    discovery_endpoint: str  # URL or address for resolution queries
    public_key: bytes  # ML-DSA-65 public key for STH verification
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    last_sth: Optional[dict] = None
    last_sth_verified_epoch: int = -1
    registered_at: float = 0.0
    entity_count: int = 0  # Known entity count from last STH

    @property
    def is_trusted(self) -> bool:
        return self.trust_level in (TrustLevel.VERIFIED, TrustLevel.FEDERATED)

    @property
    def is_federated(self) -> bool:
        return self.trust_level == TrustLevel.FEDERATED


@dataclass
class EntityResolution:
    """
    Result of resolving an entity_id to its home network.

    Used by receivers to find which network holds the shards
    for a given entity_id when it's not in the local network.
    """

    entity_id: str
    found: bool
    home_network_id: Optional[str] = None
    home_network_name: Optional[str] = None
    shard_endpoints: list[str] = field(default_factory=list)
    resolution_hops: int = 0
    resolution_time_ms: float = 0.0
    trust_level: Optional[TrustLevel] = None

    @property
    def is_cross_network(self) -> bool:
        return self.found and self.home_network_id is not None


class FederationRegistry:
    """
    Manages the federation of LTP networks.

    Responsibilities:
      - Network discovery and registration
      - Trust level management
      - Cross-network entity resolution
      - STH exchange and verification
    """

    def __init__(self, config: FederationConfig | None = None) -> None:
        self.config = config or FederationConfig()
        self._networks: dict[str, FederatedNetwork] = {}
        self._local_network_id: Optional[str] = None
        # Local entity index: entity_id → True (for resolution)
        self._local_entities: set[str] = set()
        # Cross-network entity cache: entity_id → network_id
        self._resolution_cache: dict[str, str] = {}

    def set_local_network_id(self, network_id: str) -> None:
        """Set the local network's identifier."""
        self._local_network_id = network_id

    def register_local_entity(self, entity_id: str) -> None:
        """Register an entity as existing in the local network."""
        self._local_entities.add(entity_id)

    def register_network(
        self,
        network_id: str,
        display_name: str,
        discovery_endpoint: str,
        public_key: bytes,
    ) -> FederatedNetwork:
        """
        Register a new federated network.

        Initially registered as UNTRUSTED. Trust is escalated via
        STH verification and mutual agreement.
        """
        if network_id in self._networks:
            raise ValueError(f"Network '{network_id}' already registered")

        if network_id == self._local_network_id:
            raise ValueError("Cannot register self as federated network")

        network = FederatedNetwork(
            network_id=network_id,
            display_name=display_name,
            discovery_endpoint=discovery_endpoint,
            public_key=public_key,
            registered_at=time.time(),
        )
        self._networks[network_id] = network
        return network

    def unregister_network(self, network_id: str) -> bool:
        """Remove a network from the federation."""
        removed = self._networks.pop(network_id, None)
        if removed:
            # Clean resolution cache
            self._resolution_cache = {
                eid: nid for eid, nid in self._resolution_cache.items() if nid != network_id
            }
        return removed is not None

    def upgrade_trust(
        self,
        network_id: str,
        new_level: TrustLevel,
    ) -> bool:
        """
        Upgrade a network's trust level.

        Trust can only be escalated, never downgraded (use revoke_trust).
        UNTRUSTED → VERIFIED: requires successful STH exchange
        VERIFIED → FEDERATED: requires mutual agreement
        """
        network = self._networks.get(network_id)
        if network is None:
            return False

        current_order = [TrustLevel.UNTRUSTED, TrustLevel.VERIFIED, TrustLevel.FEDERATED]
        current_idx = current_order.index(network.trust_level)
        new_idx = current_order.index(new_level)

        if new_idx <= current_idx:
            return False  # Can't downgrade via upgrade

        network.trust_level = new_level
        return True

    def revoke_trust(self, network_id: str) -> bool:
        """Revoke trust for a network (set to UNTRUSTED)."""
        network = self._networks.get(network_id)
        if network is None:
            return False
        network.trust_level = TrustLevel.UNTRUSTED
        return True

    def verify_sth(
        self,
        network_id: str,
        sth: dict,
        current_epoch: int,
    ) -> bool:
        """
        Verify a Signed Tree Head from a federated network.

        Checks:
          1. STH is properly structured (includes signature + signable_payload)
          2. Monotonically increasing sequence/timestamp
          3. ML-DSA-65 signature valid against network's public key

        On success, updates trust to VERIFIED if currently UNTRUSTED.
        """
        network = self._networks.get(network_id)
        if network is None:
            return False

        # Validate STH structure
        required_fields = {"sequence", "root_hash", "timestamp", "record_count"}
        if not required_fields.issubset(sth.keys()):
            return False

        # Type validation for STH fields
        if not isinstance(sth["sequence"], int):
            return False
        if not isinstance(sth["timestamp"], (int, float)):
            return False
        if not isinstance(sth["root_hash"], (str, bytes)):
            return False
        if not isinstance(sth["record_count"], int):
            return False

        # Monotonicity check
        if network.last_sth is not None:
            if sth["sequence"] <= network.last_sth["sequence"]:
                return False
            if sth["timestamp"] < network.last_sth["timestamp"]:
                return False

        # Real ML-DSA-65 signature verification
        signature = sth.get("signature")
        signable_payload = sth.get("signable_payload")
        if signature is not None and signable_payload is not None:
            if not MLDSA.verify(network.public_key, signable_payload, signature):
                return False
        elif len(network.public_key) == MLDSA.VK_SIZE:
            # Network has real ML-DSA key but STH has no signature — reject
            return False
        # else: legacy STH without signature field from non-ML-DSA network — allow

        # Update network state
        network.last_sth = dict(sth)
        network.last_sth_verified_epoch = current_epoch
        network.entity_count = sth.get("record_count", 0)

        # Auto-upgrade trust if currently untrusted
        if network.trust_level == TrustLevel.UNTRUSTED:
            network.trust_level = TrustLevel.VERIFIED

        return True

    def resolve_entity(
        self,
        entity_id: str,
        transport: Optional["FederationTransport"] = None,
        auth: Optional["FederationAuth"] = None,
    ) -> EntityResolution:
        """
        Resolve an entity_id to its home network.

        Resolution order:
          1. Check local network
          2. Check resolution cache
          3. Query federated networks (in trust order)

        Only queries networks meeting min_trust_for_resolution.
        When transport and auth are provided, step 3 queries remote
        networks via the transport layer. Without them, remote
        queries are skipped (backward compat).
        """
        t0 = time.monotonic()

        # 1. Check local
        if entity_id in self._local_entities:
            elapsed = (time.monotonic() - t0) * 1000
            return EntityResolution(
                entity_id=entity_id,
                found=True,
                home_network_id=self._local_network_id,
                home_network_name="local",
                resolution_time_ms=round(elapsed, 3),
                trust_level=TrustLevel.FEDERATED,
            )

        # 2. Check cache
        cached_network_id = self._resolution_cache.get(entity_id)
        if cached_network_id and cached_network_id in self._networks:
            network = self._networks[cached_network_id]
            elapsed = (time.monotonic() - t0) * 1000
            return EntityResolution(
                entity_id=entity_id,
                found=True,
                home_network_id=network.network_id,
                home_network_name=network.display_name,
                shard_endpoints=[network.discovery_endpoint],
                resolution_hops=0,
                resolution_time_ms=round(elapsed, 3),
                trust_level=network.trust_level,
            )

        # 3. Query federated networks
        min_trust = self.config.min_trust_for_resolution
        trust_order = [TrustLevel.FEDERATED, TrustLevel.VERIFIED, TrustLevel.UNTRUSTED]
        min_idx = trust_order.index(min_trust)

        for network in sorted(
            self._networks.values(),
            key=lambda n: trust_order.index(n.trust_level),
        ):
            if trust_order.index(network.trust_level) > min_idx:
                continue

            # Query remote network via transport (if available)
            if transport is not None and auth is not None:
                result = transport.query_entity(
                    network.discovery_endpoint,
                    entity_id,
                    auth,
                )
                if result is not None and result.get("found"):
                    self._resolution_cache[entity_id] = network.network_id
                    elapsed = (time.monotonic() - t0) * 1000
                    return EntityResolution(
                        entity_id=entity_id,
                        found=True,
                        home_network_id=network.network_id,
                        home_network_name=network.display_name,
                        shard_endpoints=[network.discovery_endpoint],
                        resolution_hops=1,
                        resolution_time_ms=round(elapsed, 3),
                        trust_level=network.trust_level,
                    )

        elapsed = (time.monotonic() - t0) * 1000
        return EntityResolution(
            entity_id=entity_id,
            found=False,
            resolution_time_ms=round(elapsed, 3),
        )

    def register_resolution(
        self,
        entity_id: str,
        network_id: str,
    ) -> bool:
        """
        Manually register that an entity exists on a specific network.

        Used when resolution succeeds via out-of-band means (e.g.,
        the lattice key contains a network hint).
        """
        if network_id not in self._networks:
            return False
        self._resolution_cache[entity_id] = network_id
        return True

    def get_network(self, network_id: str) -> Optional[FederatedNetwork]:
        return self._networks.get(network_id)

    @property
    def federated_networks(self) -> list[FederatedNetwork]:
        return [n for n in self._networks.values() if n.is_federated]

    @property
    def verified_networks(self) -> list[FederatedNetwork]:
        return [n for n in self._networks.values() if n.is_trusted]

    @property
    def all_networks(self) -> list[FederatedNetwork]:
        return list(self._networks.values())

    @property
    def local_network_id(self) -> Optional[str]:
        return self._local_network_id

    def federate_with_agreement(self, agreement: "FederationAgreement") -> bool:
        """Upgrade trust to FEDERATED using a verified mutual agreement.

        Both signatures must verify. The remote network must be at least
        VERIFIED. Returns True if trust was upgraded.

        Raises ValueError if signatures are invalid.
        """
        if not agreement.verify_both():
            raise ValueError("Federation agreement signature verification failed")

        # Determine which network is the remote one
        remote_id = None
        if agreement.initiator_network_id == self._local_network_id:
            remote_id = agreement.responder_network_id
        elif agreement.responder_network_id == self._local_network_id:
            remote_id = agreement.initiator_network_id
        else:
            raise ValueError("Local network is not a party to this agreement")

        network = self._networks.get(remote_id)
        if network is None:
            raise ValueError(f"Network {remote_id!r} is not registered")

        if network.trust_level == TrustLevel.UNTRUSTED:
            raise ValueError(f"Network {remote_id!r} must be at least VERIFIED before federation")

        if network.trust_level == TrustLevel.FEDERATED:
            return True  # Already federated — idempotent

        network.trust_level = TrustLevel.FEDERATED
        return True

    def register_from_nir(self, nir: "NetworkIdentityRecord") -> FederatedNetwork:
        """Register a network from a verified NIR.

        Verifies the NIR signature before registration.
        Raises ValueError if the NIR signature is invalid.
        """
        if not nir.verify():
            raise ValueError("NIR signature verification failed")
        return self.register_network(
            network_id=nir.network_id,
            display_name=nir.display_name,
            discovery_endpoint=nir.discovery_endpoint,
            public_key=nir.operator_vk,
        )


# ---------------------------------------------------------------------------
# Network Identity Record (NIR)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NetworkIdentityRecord:
    """Globally unique network identity.

    Derived from genesis STH + operator ML-DSA key. ML-DSA-65 signed,
    unforgeable. Published via DNS TXT records or on-chain L1 registry.

    The network_id is deterministic:
      H(DOMAIN_NIR + genesis_sth_root + operator_vk)
    Changing any input changes the ID.
    """

    network_id: str
    operator_vk: bytes
    genesis_sth_root: bytes
    genesis_sth_sequence: int
    display_name: str
    discovery_endpoint: str
    created_at: float
    signature: bytes

    def canonical_bytes(self) -> bytes:
        """Deterministic canonical encoding for signing/verification."""
        return (
            DOMAIN_NIR
            + self.network_id.encode()
            + self.operator_vk
            + self.genesis_sth_root
            + struct.pack(">Q", self.genesis_sth_sequence)
            + self.display_name.encode()
            + self.discovery_endpoint.encode()
            + struct.pack(">d", self.created_at)
        )

    def verify(self) -> bool:
        """Verify the ML-DSA-65 signature on this NIR."""
        return MLDSA.verify(self.operator_vk, self.canonical_bytes(), self.signature)

    @classmethod
    def create(
        cls,
        keypair,
        genesis_sth_root: bytes,
        genesis_sth_sequence: int,
        display_name: str,
        discovery_endpoint: str,
    ) -> "NetworkIdentityRecord":
        """Create and sign a new NIR.

        Raises ValueError if genesis_sth_root is not exactly 32 bytes.
        """
        if len(genesis_sth_root) != 32:
            raise ValueError(f"genesis_sth_root must be 32 bytes, got {len(genesis_sth_root)}")
        network_id = canonical_hash_bytes(DOMAIN_NIR + genesis_sth_root + keypair.vk).hex()

        now = time.time()

        # Build unsigned record for signing
        unsigned = cls(
            network_id=network_id,
            operator_vk=keypair.vk,
            genesis_sth_root=genesis_sth_root,
            genesis_sth_sequence=genesis_sth_sequence,
            display_name=display_name,
            discovery_endpoint=discovery_endpoint,
            created_at=now,
            signature=b"",  # placeholder
        )

        sig = keypair.sign(unsigned.canonical_bytes())

        return cls(
            network_id=network_id,
            operator_vk=keypair.vk,
            genesis_sth_root=genesis_sth_root,
            genesis_sth_sequence=genesis_sth_sequence,
            display_name=display_name,
            discovery_endpoint=discovery_endpoint,
            created_at=now,
            signature=sig,
        )


# ---------------------------------------------------------------------------
# Discovery Services
# ---------------------------------------------------------------------------


class DiscoveryService(ABC):
    """Abstract discovery service for finding remote NIRs."""

    @abstractmethod
    def publish(self, nir: NetworkIdentityRecord) -> bool:
        """Publish a NIR for others to discover. Returns True on success."""
        ...

    @abstractmethod
    def discover(self, query: str = "") -> list[NetworkIdentityRecord]:
        """Discover NIRs matching a query (or all if empty)."""
        ...

    @abstractmethod
    def resolve(self, network_id: str) -> Optional[NetworkIdentityRecord]:
        """Resolve a specific network_id to its NIR. None if not found."""
        ...


class StaticDiscoveryService(DiscoveryService):
    """In-memory discovery for testing. NIRs are manually added."""

    def __init__(self) -> None:
        self._nirs: dict[str, NetworkIdentityRecord] = {}

    def publish(self, nir: NetworkIdentityRecord) -> bool:
        self._nirs[nir.network_id] = nir
        return True

    def discover(self, query: str = "") -> list[NetworkIdentityRecord]:
        if not query:
            return list(self._nirs.values())
        return [n for n in self._nirs.values() if query in n.display_name or query in n.network_id]

    def resolve(self, network_id: str) -> Optional[NetworkIdentityRecord]:
        return self._nirs.get(network_id)


class DNSProvider(ABC):
    """Abstract backend for publishing NIR records to DNS.

    Implementations handle the provider-specific details of creating and
    deleting TXT records. `query_txt` is optional — if a provider supports
    local record lookup (e.g. for tests), it can return records directly
    without traversing the real DNS hierarchy.
    """

    @abstractmethod
    def publish_txt(self, name: str, value: str) -> bool:
        """Publish a TXT record. Returns True on success."""
        ...

    @abstractmethod
    def delete_txt(self, name: str) -> bool:
        """Delete the TXT record at `name`. Returns True if removed."""
        ...

    def query_txt(self, name: str) -> list[str]:
        """Return TXT record values for `name` — default: empty list.

        Providers that can answer queries locally (e.g. in-process caches)
        should override this. The `DNSDiscoveryService` calls it in addition
        to the real-DNS path so records published to this provider remain
        discoverable without hitting external resolvers.
        """
        return []


class LocalCacheDNSProvider(DNSProvider):
    """In-process DNS provider — stores TXT records in a dict.

    The default backend for `DNSDiscoveryService`. Records published here
    are visible to the same `DNSDiscoveryService` instance but NOT to
    external DNS resolvers. Useful for tests and single-host deployments.
    """

    def __init__(self) -> None:
        self._records: dict[str, list[str]] = {}

    def publish_txt(self, name: str, value: str) -> bool:
        self._records.setdefault(name, [])
        if value not in self._records[name]:
            self._records[name].append(value)
        return True

    def delete_txt(self, name: str) -> bool:
        return self._records.pop(name, None) is not None

    def query_txt(self, name: str) -> list[str]:
        return list(self._records.get(name, []))


class Route53DNSProvider(DNSProvider):
    """AWS Route53 DNS provider.

    Requires: boto3 and AWS credentials with
    `route53:ChangeResourceRecordSets` on the hosted zone.

    Usage:
        provider = Route53DNSProvider(hosted_zone_id="Z1234EXAMPLE")
        discovery = DNSDiscoveryService(domain="etp.example.com", provider=provider)
    """

    def __init__(self, hosted_zone_id: str, ttl: int = 300) -> None:
        self._hosted_zone_id = hosted_zone_id
        self._ttl = ttl

    def _client(self):
        try:
            import boto3  # type: ignore
        except ImportError as e:
            raise RuntimeError("Route53DNSProvider requires boto3: pip install 'ltp[cloud]'") from e
        return boto3.client("route53")

    def _change(self, action: str, name: str, values: list[str]) -> bool:
        client = self._client()
        # RFC 1035: TXT values are quoted, max 255 bytes per string.
        chunks = []
        for v in values:
            encoded = v.encode("utf-8")
            pieces = [encoded[i : i + 255] for i in range(0, len(encoded), 255)]
            quoted = " ".join(
                '"' + p.decode("utf-8", "replace").replace('"', r"\"") + '"' for p in pieces
            )
            chunks.append({"Value": quoted})
        try:
            client.change_resource_record_sets(
                HostedZoneId=self._hosted_zone_id,
                ChangeBatch={
                    "Changes": [
                        {
                            "Action": action,
                            "ResourceRecordSet": {
                                "Name": name,
                                "Type": "TXT",
                                "TTL": self._ttl,
                                "ResourceRecords": chunks,
                            },
                        }
                    ]
                },
            )
            return True
        except Exception:
            return False

    def publish_txt(self, name: str, value: str) -> bool:
        return self._change("UPSERT", name, [value])

    def delete_txt(self, name: str) -> bool:
        # Route53 DELETE requires the exact current record set.
        # We look it up, then delete — best-effort.
        try:
            client = self._client()
            resp = client.list_resource_record_sets(
                HostedZoneId=self._hosted_zone_id,
                StartRecordName=name,
                StartRecordType="TXT",
            )
            for rr in resp.get("ResourceRecordSets", []):
                if rr.get("Name") == name and rr.get("Type") == "TXT":
                    client.change_resource_record_sets(
                        HostedZoneId=self._hosted_zone_id,
                        ChangeBatch={"Changes": [{"Action": "DELETE", "ResourceRecordSet": rr}]},
                    )
                    return True
        except Exception:
            return False
        return False


class CloudflareDNSProvider(DNSProvider):
    """Cloudflare DNS provider via the v4 HTTP API.

    Requires: httpx and a Cloudflare API token with the "DNS:Edit"
    permission scoped to the target zone.
    """

    API_BASE = "https://api.cloudflare.com/client/v4"

    def __init__(self, zone_id: str, api_token: str, ttl: int = 300) -> None:
        self._zone_id = zone_id
        self._api_token = api_token
        self._ttl = ttl

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_token}",
            "Content-Type": "application/json",
        }

    def _client(self):
        try:
            import httpx  # type: ignore
        except ImportError as e:
            raise RuntimeError(
                "CloudflareDNSProvider requires httpx: pip install 'ltp[federation]'"
            ) from e
        return httpx

    def publish_txt(self, name: str, value: str) -> bool:
        httpx_mod = self._client()
        url = f"{self.API_BASE}/zones/{self._zone_id}/dns_records"
        try:
            resp = httpx_mod.post(
                url,
                headers=self._headers(),
                json={"type": "TXT", "name": name, "content": value, "ttl": self._ttl},
                timeout=10.0,
            )
            return resp.status_code in (200, 201) and resp.json().get("success", False)
        except Exception:
            return False

    def delete_txt(self, name: str) -> bool:
        httpx_mod = self._client()
        try:
            # Look up the record id first.
            list_url = f"{self.API_BASE}/zones/{self._zone_id}/dns_records"
            resp = httpx_mod.get(
                list_url,
                headers=self._headers(),
                params={"type": "TXT", "name": name},
                timeout=10.0,
            )
            if resp.status_code != 200:
                return False
            deleted = False
            for rec in resp.json().get("result", []):
                rec_id = rec.get("id")
                if not rec_id:
                    continue
                d = httpx_mod.delete(
                    f"{self.API_BASE}/zones/{self._zone_id}/dns_records/{rec_id}",
                    headers=self._headers(),
                    timeout=10.0,
                )
                if d.status_code == 200:
                    deleted = True
            return deleted
        except Exception:
            return False


class DNSDiscoveryService(DiscoveryService):
    """DNS TXT record discovery for Network Identity Records.

    `publish()` routes through a pluggable `DNSProvider`
    (LocalCacheDNSProvider by default). `discover()` and `resolve()`
    consult both real DNS (via dnspython) and the provider's local
    cache, deduplicated by `network_id` and filtered to verified
    ML-DSA signatures.

    TXT record format:
      `_etp-nir.{domain}` → JSON NIR (hex-encoded byte fields, v1 schema)

    Multiple NIRs at the same domain produce multiple TXT records; all
    are returned by `discover(domain)`.

    Note: PQC operator keys are large (ML-DSA-65 ≈ 2KB). For public DNS
    deployments, operators should use a dedicated subdomain per NIR
    (e.g. `{network_id[:8]}._etp-nir.{domain}`) to stay within the 4KB
    EDNS0 response limit.
    """

    TXT_PREFIX = "_etp-nir"
    SCHEMA_VERSION = 1

    def __init__(
        self,
        domain: str = "etp.local",
        provider: Optional[DNSProvider] = None,
    ) -> None:
        self._domain = domain
        self._provider = provider if provider is not None else LocalCacheDNSProvider()
        self._local_cache: dict[str, NetworkIdentityRecord] = {}
        self._domain_index: dict[str, list[str]] = {}

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    @classmethod
    def _serialize_nir(cls, nir: NetworkIdentityRecord) -> str:
        """Serialize an NIR to a compact JSON string (hex-encoded bytes)."""
        import json

        return json.dumps(
            {
                "v": cls.SCHEMA_VERSION,
                "network_id": nir.network_id,
                "operator_vk": nir.operator_vk.hex(),
                "genesis_sth_root": nir.genesis_sth_root.hex(),
                "genesis_sth_sequence": nir.genesis_sth_sequence,
                "display_name": nir.display_name,
                "discovery_endpoint": nir.discovery_endpoint,
                "created_at": nir.created_at,
                "signature": nir.signature.hex(),
            },
            separators=(",", ":"),
        )

    @classmethod
    def _deserialize_nir(cls, txt: str) -> Optional[NetworkIdentityRecord]:
        """Parse a TXT record into an NIR. Returns None on malformed input."""
        import json

        try:
            data = json.loads(txt)
            if data.get("v") != cls.SCHEMA_VERSION:
                return None
            return NetworkIdentityRecord(
                network_id=data["network_id"],
                operator_vk=bytes.fromhex(data["operator_vk"]),
                genesis_sth_root=bytes.fromhex(data["genesis_sth_root"]),
                genesis_sth_sequence=int(data["genesis_sth_sequence"]),
                display_name=data["display_name"],
                discovery_endpoint=data["discovery_endpoint"],
                created_at=float(data["created_at"]),
                signature=bytes.fromhex(data["signature"]),
            )
        except (ValueError, KeyError, TypeError):
            return None

    # ------------------------------------------------------------------
    # DNS resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _query_real_dns(name: str, timeout: float = 5.0) -> list[str]:
        """Query TXT records at `name` via dnspython. Returns [] on failure."""
        try:
            import dns.exception  # type: ignore
            import dns.resolver  # type: ignore
        except ImportError:
            return []
        try:
            answers = dns.resolver.resolve(name, "TXT", lifetime=timeout)
        except Exception:
            return []
        out: list[str] = []
        for rdata in answers:
            # TXT rdata exposes `.strings` as a list of up-to-255-byte bytes
            # chunks; join them for chunked records.
            try:
                joined = b"".join(rdata.strings).decode("utf-8", errors="replace")
            except Exception:
                continue
            out.append(joined)
        return out

    def _fqdn(self, domain: str) -> str:
        return f"{self.TXT_PREFIX}.{domain}"

    def _txt_records_for(self, domain: str) -> list[str]:
        """Collect TXT records from both the provider and real DNS."""
        name = self._fqdn(domain)
        records: list[str] = []
        records.extend(self._provider.query_txt(name))
        records.extend(self._query_real_dns(name))
        return records

    # ------------------------------------------------------------------
    # Publish
    # ------------------------------------------------------------------

    def publish(self, nir: NetworkIdentityRecord) -> bool:
        """Publish a NIR via the configured DNS provider.

        Also caches locally so subsequent `resolve()` / `discover()` calls
        succeed without a DNS round trip.
        """
        self._local_cache[nir.network_id] = nir
        domain = nir.discovery_endpoint or self._domain
        self._domain_index.setdefault(domain, [])
        if nir.network_id not in self._domain_index[domain]:
            self._domain_index[domain].append(nir.network_id)

        txt = self._serialize_nir(nir)
        return self._provider.publish_txt(self._fqdn(domain), txt)

    # ------------------------------------------------------------------
    # Discover
    # ------------------------------------------------------------------

    def discover(self, query: str = "") -> list[NetworkIdentityRecord]:
        """Discover NIRs via provider + real DNS, deduped and verified.

        If `query` is empty, returns all known NIRs. Otherwise, interprets
        `query` as either a domain to query directly, or a substring to
        match against display_name / discovery_endpoint in the local cache.
        """
        # Always include local-cache hits for backward compatibility.
        seen: dict[str, NetworkIdentityRecord] = dict(self._local_cache)

        if query:
            domains = [query] + list(self._domain_index.keys())
        else:
            domains = list(self._domain_index.keys()) or [self._domain]

        for d in domains:
            for txt in self._txt_records_for(d):
                nir = self._deserialize_nir(txt)
                if nir is not None and nir.verify():
                    seen[nir.network_id] = nir

        results = list(seen.values())
        if query:
            filtered = [
                n
                for n in results
                if query in (n.discovery_endpoint or "") or query in n.display_name
            ]
            # Substring match wins when we have any hits; otherwise
            # fall through to all (domain query may have returned records).
            if filtered:
                return filtered
        return results

    # ------------------------------------------------------------------
    # Resolve
    # ------------------------------------------------------------------

    def resolve(self, network_id: str) -> Optional[NetworkIdentityRecord]:
        """Resolve a network_id to its NIR.

        Checks the local cache first, then queries all known domains via
        the provider and real DNS. Caches verified hits locally.
        """
        hit = self._local_cache.get(network_id)
        if hit is not None:
            return hit

        domains = list(self._domain_index.keys()) or [self._domain]
        for d in domains:
            for txt in self._txt_records_for(d):
                nir = self._deserialize_nir(txt)
                if nir is None or nir.network_id != network_id:
                    continue
                if not nir.verify():
                    continue
                self._local_cache[nir.network_id] = nir
                return nir
        return None


# ---------------------------------------------------------------------------
# Federation Mutual Agreement
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FederationAgreement:
    """Bilateral signed federation agreement between two networks.

    Both sides must sign for the agreement to be valid:
      1. Initiator signs: "I agree to federate with responder"
      2. Responder counter-signs: "I agree to federate with initiator"

    Flow:
      initiate() -> half-signed (initiator only)
      countersign() -> fully signed (both)
      verify_both() -> True if both signatures valid

    """

    initiator_network_id: str
    responder_network_id: str
    initiator_vk: bytes
    responder_vk: bytes
    initiator_signature: bytes
    responder_signature: bytes
    created_at: float
    terms: str = ""

    def canonical_bytes(self) -> bytes:
        """Deterministic payload that both parties sign."""
        return (
            DOMAIN_FED_AGREEMENT
            + self.initiator_network_id.encode()
            + self.responder_network_id.encode()
            + self.initiator_vk
            + self.responder_vk
            + struct.pack(">d", self.created_at)
            + self.terms.encode()
        )

    def verify_initiator(self) -> bool:
        """Verify the initiator's signature."""
        if not self.initiator_signature:
            return False
        return MLDSA.verify(self.initiator_vk, self.canonical_bytes(), self.initiator_signature)

    def verify_responder(self) -> bool:
        """Verify the responder's signature."""
        if not self.responder_signature:
            return False
        return MLDSA.verify(self.responder_vk, self.canonical_bytes(), self.responder_signature)

    def verify_both(self) -> bool:
        """Verify both signatures are present and valid."""
        return self.verify_initiator() and self.verify_responder()

    @classmethod
    def initiate(
        cls,
        initiator_keypair,
        initiator_nir: "NetworkIdentityRecord",
        responder_nir: "NetworkIdentityRecord",
        terms: str = "",
    ) -> "FederationAgreement":
        """Create a half-signed agreement (initiator signs, responder empty).

        Raises ValueError if initiator keypair doesn't match initiator NIR,
        or if initiator and responder are the same network.
        """
        if initiator_keypair.vk != initiator_nir.operator_vk:
            raise ValueError("Initiator keypair does not match initiator NIR operator_vk")
        if initiator_nir.network_id == responder_nir.network_id:
            raise ValueError("Cannot federate a network with itself")

        now = time.time()
        payload = (
            DOMAIN_FED_AGREEMENT
            + initiator_nir.network_id.encode()
            + responder_nir.network_id.encode()
            + initiator_keypair.vk
            + responder_nir.operator_vk
            + struct.pack(">d", now)
            + terms.encode()
        )
        sig = initiator_keypair.sign(payload)

        return cls(
            initiator_network_id=initiator_nir.network_id,
            responder_network_id=responder_nir.network_id,
            initiator_vk=initiator_keypair.vk,
            responder_vk=responder_nir.operator_vk,
            initiator_signature=sig,
            responder_signature=b"",
            created_at=now,
            terms=terms,
        )

    @classmethod
    def countersign(
        cls,
        agreement: "FederationAgreement",
        responder_keypair,
    ) -> "FederationAgreement":
        """Counter-sign an initiated agreement. Returns fully signed copy."""
        if responder_keypair.vk != agreement.responder_vk:
            raise ValueError("Responder keypair does not match agreement responder_vk")

        sig = responder_keypair.sign(agreement.canonical_bytes())

        return cls(
            initiator_network_id=agreement.initiator_network_id,
            responder_network_id=agreement.responder_network_id,
            initiator_vk=agreement.initiator_vk,
            responder_vk=agreement.responder_vk,
            initiator_signature=agreement.initiator_signature,
            responder_signature=sig,
            created_at=agreement.created_at,
            terms=agreement.terms,
        )


# ---------------------------------------------------------------------------
# Federation Transport + Authentication
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FederationAuth:
    """Authentication credentials for cross-network requests.

    The remote side verifies:
      1. requester_nir.verify() — requester identity is authentic
      2. agreement.verify_both() — bilateral federation agreement is valid
    """

    requester_nir: NetworkIdentityRecord
    agreement: FederationAgreement

    def verify(self) -> bool:
        """Verify both NIR signature and agreement signatures."""
        return self.requester_nir.verify() and self.agreement.verify_both()

    def covers_network(self, network_id: str) -> bool:
        """Check if the agreement covers a specific network."""
        return (
            self.agreement.initiator_network_id == network_id
            or self.agreement.responder_network_id == network_id
        )

    def verify_for_network(self, network_id: str) -> bool:
        """Verify auth AND that the agreement covers the target network."""
        return self.verify() and self.covers_network(network_id)


class FederationTransport(ABC):
    """Abstract transport for cross-network shard fetching.

    Production: HTTP/gRPC client calling remote network endpoints.
    Development/Test: InMemoryFederationTransport.
    """

    @abstractmethod
    def fetch_shards(
        self,
        endpoint: str,
        entity_id: str,
        shard_indices: list[int],
        auth: FederationAuth,
    ) -> dict[int, bytes]:
        """Fetch encrypted shards from a remote network.

        Returns {shard_index: encrypted_shard_bytes}.
        Empty dict if entity not found or auth fails.
        """
        ...

    @abstractmethod
    def query_entity(
        self,
        endpoint: str,
        entity_id: str,
        auth: FederationAuth,
    ) -> Optional[dict]:
        """Query if a remote network holds an entity.

        Returns metadata dict (entity_id, shard_count, etc.) or None.
        """
        ...


class InMemoryFederationTransport(FederationTransport):
    """Simulated transport mapping endpoint strings to CommitmentNetwork instances.

    Validates authentication before serving — matching production behavior
    where the remote network verifies credentials before responding.
    """

    def __init__(self) -> None:
        self._networks: dict[str, object] = {}  # endpoint → CommitmentNetwork
        self._network_ids: dict[str, str] = {}  # endpoint → network_id

    def register_network(self, endpoint: str, network, network_id: str = "") -> None:
        """Register a CommitmentNetwork for an endpoint (testing only)."""
        self._networks[endpoint] = network
        if network_id:
            self._network_ids[endpoint] = network_id

    def fetch_shards(
        self,
        endpoint: str,
        entity_id: str,
        shard_indices: list[int],
        auth: FederationAuth,
    ) -> dict[int, bytes]:
        """Fetch shards from a registered network after auth verification.

        Verifies that the auth agreement covers this specific network.
        """
        target_nid = self._network_ids.get(endpoint, "")
        if target_nid and not auth.verify_for_network(target_nid):
            return {}
        elif not auth.verify():
            return {}

        network = self._networks.get(endpoint)
        if network is None:
            return {}

        result: dict[int, bytes] = {}
        for idx in shard_indices:
            for node in network.nodes:
                if node.evicted:
                    continue
                data = node.fetch_shard(entity_id, idx)
                if data is not None:
                    result[idx] = data
                    break
        return result

    def query_entity(
        self,
        endpoint: str,
        entity_id: str,
        auth: FederationAuth,
    ) -> Optional[dict]:
        """Query if entity exists in a registered network.

        Verifies that the auth agreement covers this specific network.
        """
        target_nid = self._network_ids.get(endpoint, "")
        if target_nid and not auth.verify_for_network(target_nid):
            return None
        elif not auth.verify():
            return None

        network = self._networks.get(endpoint)
        if network is None:
            return None

        record = network.log.fetch(entity_id)
        if record is None:
            return None

        return {
            "entity_id": entity_id,
            "found": True,
            "shard_count": record.encoding_params.get("n", 8),
        }


# The real HTTP federation transport lives in `src/ltp/federation_http.py`
# as `HTTPFederationTransport` — imported separately so `federation.py` stays
# network-agnostic. See that module for the production client with retries,
# connection pooling, and auth header wiring.


# ---------------------------------------------------------------------------
# Cross-Network Shard Fetcher
# ---------------------------------------------------------------------------


class CrossNetworkFetcher:
    """High-level cross-network shard fetcher.

    Combines FederationRegistry (entity resolution) + FederationTransport
    (shard fetching) + FederationAuth (authentication).

    Usage:
        fetcher = CrossNetworkFetcher(registry, transport, my_nir, agreements)
        shards = fetcher.fetch_entity_shards("entity-id", [0, 1, 2, 3])
    """

    def __init__(
        self,
        registry: FederationRegistry,
        transport: FederationTransport,
        local_nir: NetworkIdentityRecord,
        agreements: dict[str, FederationAgreement],
        rate_limiter: Optional["FederationRateLimiter"] = None,
    ) -> None:
        self._registry = registry
        self._transport = transport
        self._local_nir = local_nir
        self._agreements = agreements  # network_id → FederationAgreement
        self._rate_limiter = rate_limiter

    def fetch_entity_shards(
        self,
        entity_id: str,
        shard_indices: list[int],
    ) -> Optional[dict[int, bytes]]:
        """Resolve entity → authenticate → fetch shards from remote network.

        Returns {shard_index: encrypted_bytes} or None if entity not found
        or authentication fails.
        """
        # Build auth for resolution (use first available agreement)
        resolution_auth = self._get_any_auth()
        if resolution_auth is None:
            return None

        # Resolve entity location
        resolution = self._registry.resolve_entity(
            entity_id,
            transport=self._transport,
            auth=resolution_auth,
        )
        if not resolution.found or resolution.home_network_id is None:
            return None

        # Local entity — no cross-network fetch needed
        if resolution.home_network_id == self._registry.local_network_id:
            return None

        # Rate limit check
        if self._rate_limiter is not None:
            if not self._rate_limiter.allow(resolution.home_network_id):
                return None

        # Get auth for the specific remote network
        auth = self._get_auth_for_network(resolution.home_network_id)
        if auth is None:
            return None

        # Fetch shards via transport
        endpoint = resolution.shard_endpoints[0] if resolution.shard_endpoints else None
        if endpoint is None:
            return None

        shards = self._transport.fetch_shards(
            endpoint,
            entity_id,
            shard_indices,
            auth,
        )
        return shards if shards else None

    def _get_auth_for_network(self, network_id: str) -> Optional[FederationAuth]:
        """Build FederationAuth for a specific remote network."""
        agreement = self._agreements.get(network_id)
        if agreement is None:
            return None
        return FederationAuth(requester_nir=self._local_nir, agreement=agreement)

    def _get_any_auth(self) -> Optional[FederationAuth]:
        """Build FederationAuth using any available agreement (for resolution)."""
        for agreement in self._agreements.values():
            return FederationAuth(requester_nir=self._local_nir, agreement=agreement)
        return None


# ---------------------------------------------------------------------------
# Federation Rate Limiter
# ---------------------------------------------------------------------------


class FederationRateLimiter:
    """Per-network rate limiter for federation requests.

    Tracks requests per network within a sliding time window.
    Rejects requests that exceed the configured quota.

    Thread-safe via threading.Lock. Injectable clock for deterministic testing.
    """

    def __init__(
        self,
        max_requests_per_window: int = 100,
        window_seconds: float = 60.0,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        if max_requests_per_window < 0:
            raise ValueError("max_requests_per_window must be >= 0")
        self._max_requests = max_requests_per_window
        self._window = window_seconds
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()
        # network_id → (window_start, request_count)
        self._counters: dict[str, tuple[float, int]] = {}

    def allow(self, network_id: str) -> bool:
        """Check if a request to network_id is allowed.

        Returns True and consumes one request from the quota.
        Returns False if quota exhausted for the current window.
        """
        now = self._clock()
        with self._lock:
            window_start, count = self._counters.get(network_id, (now, 0))

            # Reset window if expired
            if now - window_start >= self._window:
                window_start = now
                count = 0

            if count >= self._max_requests:
                return False

            self._counters[network_id] = (window_start, count + 1)
            return True

    def remaining(self, network_id: str) -> int:
        """Return remaining quota for a network in the current window."""
        now = self._clock()
        with self._lock:
            window_start, count = self._counters.get(network_id, (now, 0))
            if now - window_start >= self._window:
                return self._max_requests
            return max(0, self._max_requests - count)

    def reset(self, network_id: str) -> None:
        """Manually reset quota for a network."""
        with self._lock:
            if network_id in self._counters:
                del self._counters[network_id]

    @property
    def max_requests_per_window(self) -> int:
        return self._max_requests

    @property
    def window_seconds(self) -> float:
        return self._window
