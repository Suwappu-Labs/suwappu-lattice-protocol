"""
Node configuration for ETP nodes.

Supports loading from TOML files (tomllib/tomli), environment variables,
or a combination (TOML base with env overlays).
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field

__all__ = ["NodeConfig"]


@dataclass
class NodeConfig:
    """Configuration for an ETP node."""

    node_id: str = "etp-node-1"
    region: str = "default"
    listen_host: str = "0.0.0.0"
    listen_port: int = 50051
    rest_port: int = 8080
    seed_peers: list[str] = field(default_factory=list)
    keypair_path: str = ""  # empty = generate ephemeral
    storage_backend: str = "memory"  # "memory" | "sqlite" | "filesystem"
    storage_path: str = ""
    max_workers: int = 10
    require_real_crypto: bool = True
    log_level: str = "INFO"
    audit_interval_seconds: float = 60.0
    strike_threshold: int = 3  # audit failures before auto-eviction

    # Anchor configuration — opt-in chain anchoring
    anchor_enabled: bool = False
    anchor_rpc_url: str = ""
    anchor_registry_address: str = ""
    anchor_operator_key: str = ""
    anchor_chain_id: int = 103115120  # SUWAPPU Testnet default
    anchor_batch_size: int = 50
    anchor_interval_seconds: float = 15.0
    anchor_max_wait_seconds: float = 60.0
    anchor_confirmation_depth: int = 3
    anchor_finality_depth: int = 1
    anchor_max_rpc_retries: int = 5
    anchor_rest_port: int = 8082
    diagnostics_port: int = 8081
    diagnostics_public_mode: bool = False

    # Multi-chain anchor configuration — list of per-chain dicts.
    # When populated, these take precedence over flat anchor_* fields.
    anchor_chains: list[dict] = field(default_factory=list)

    # Gateway configuration — unified FastAPI REST server (replaces legacy HTTP servers)
    gateway_enabled: bool = False
    gateway_port: int = 8080
    gateway_jwt_enabled: bool = False
    gateway_jwt_ttl_seconds: int = 3600
    gateway_rate_limit_per_minute: int = 60

    # Gossip peer discovery
    gossip_enabled: bool = False
    gossip_interval_seconds: float = 30.0
    gossip_max_peers: int = 20
    gossip_liveness_timeout_seconds: float = 90.0

    # Governance — on-chain phase transition voting
    governance_contract_address: str = ""
    governance_chain_rpc: str = ""
    governance_chain_id: int = 0

    # KMS — cloud key management
    kms_backend: str = "memory"  # "memory" | "aws"
    kms_region: str = ""  # AWS region (e.g., "us-east-1")
    kms_key_arn: str = ""  # KMS master key ARN for envelope encryption
    kms_endpoint: str = ""  # Custom endpoint (localstack/moto testing)

    # Observability
    observability_enabled: bool = True  # Lightweight — default on

    # TLS / mTLS — secure gRPC channels
    tls_enabled: bool = False
    tls_cert_path: str = ""
    tls_key_path: str = ""
    tls_ca_path: str = ""
    tls_require_client_cert: bool = True

    # Bridge operator — persistent cross-chain bridging daemon
    bridge_operator_enabled: bool = False
    bridge_operator_interval_seconds: float = 30.0
    bridge_operator_direction: str = "suwappu_to_base"
    bridge_operator_max_retries: int = 3
    bridge_operator_challenge_period: float = 3600.0
    bridge_operator_zk_mode: str = "simulated"

    def __repr__(self) -> str:
        """Custom repr that redacts secret fields."""
        fields = []
        for f in self.__dataclass_fields__:
            val = getattr(self, f)
            if f == "anchor_operator_key" and val:
                fields.append(f"{f}='***REDACTED***'")
            elif f == "anchor_chains" and val:
                redacted = []
                for chain in val:
                    c = dict(chain)
                    if "operator_key" in c:
                        c["operator_key"] = "***REDACTED***"
                    redacted.append(c)
                fields.append(f"{f}={redacted!r}")
            else:
                fields.append(f"{f}={val!r}")
        return f"NodeConfig({', '.join(fields)})"

    def get_chain_configs(self) -> list:
        """Build ChainConfig instances from configuration.

        Resolution order:
        1. If anchor_chains is populated → [ChainConfig.from_dict(c) for c in anchor_chains]
        2. Else if anchor_rpc_url is non-empty → single ChainConfig from flat fields
        3. Otherwise → []

        Per-chain confirmation_depth/finality_depth override the flat
        NodeConfig fields when anchor_chains is populated.
        """
        from ..anchor.chain_config import ChainConfig

        if self.anchor_chains:
            return [ChainConfig.from_dict(c) for c in self.anchor_chains]

        if self.anchor_rpc_url:
            return [
                ChainConfig(
                    chain_id=self.anchor_chain_id,
                    label="default",
                    rpc_url=self.anchor_rpc_url,
                    registry_address=self.anchor_registry_address,
                    operator_key=self.anchor_operator_key,
                    confirmation_depth=self.anchor_confirmation_depth,
                    finality_depth=self.anchor_finality_depth,
                    max_rpc_retries=self.anchor_max_rpc_retries,
                )
            ]

        return []

    @classmethod
    def from_toml(cls, path: str) -> "NodeConfig":
        """Load configuration from a TOML file."""
        if sys.version_info >= (3, 11):
            import tomllib
        else:
            try:
                import tomli as tomllib  # type: ignore[no-redef]
            except ImportError:
                raise ImportError("tomli is required for Python < 3.11: pip install tomli")

        with open(path, "rb") as f:
            data = tomllib.load(f)

        return cls._from_dict(data)

    @classmethod
    def from_env(cls) -> "NodeConfig":
        """Load configuration from environment variables.

        Env vars:
            ETP_NODE_ID, ETP_REGION, ETP_LISTEN_HOST, ETP_LISTEN_PORT,
            ETP_REST_PORT, ETP_SEED_PEERS (comma-separated),
            ETP_KEYPAIR_PATH, ETP_STORAGE_BACKEND, ETP_STORAGE_PATH,
            ETP_MAX_WORKERS, ETP_REQUIRE_REAL_CRYPTO, ETP_LOG_LEVEL
        """
        kwargs: dict = {}
        _env_str(kwargs, "node_id", "ETP_NODE_ID")
        _env_str(kwargs, "region", "ETP_REGION")
        _env_str(kwargs, "listen_host", "ETP_LISTEN_HOST")
        _env_int(kwargs, "listen_port", "ETP_LISTEN_PORT")
        _env_int(kwargs, "rest_port", "ETP_REST_PORT")
        _env_str(kwargs, "keypair_path", "ETP_KEYPAIR_PATH")
        _env_str(kwargs, "storage_backend", "ETP_STORAGE_BACKEND")
        _env_str(kwargs, "storage_path", "ETP_STORAGE_PATH")
        _env_int(kwargs, "max_workers", "ETP_MAX_WORKERS")
        _env_bool(kwargs, "require_real_crypto", "ETP_REQUIRE_REAL_CRYPTO")
        _env_str(kwargs, "log_level", "ETP_LOG_LEVEL")
        _env_float(kwargs, "audit_interval_seconds", "ETP_AUDIT_INTERVAL")
        _env_int(kwargs, "strike_threshold", "ETP_STRIKE_THRESHOLD")

        # Anchor
        _env_bool(kwargs, "anchor_enabled", "ETP_ANCHOR_ENABLED")
        _env_str(kwargs, "anchor_rpc_url", "ETP_ANCHOR_RPC_URL")
        _env_str(kwargs, "anchor_registry_address", "ETP_ANCHOR_REGISTRY")
        _env_str(kwargs, "anchor_operator_key", "ETP_ANCHOR_OPERATOR_KEY")
        _env_int(kwargs, "anchor_chain_id", "ETP_ANCHOR_CHAIN_ID")
        _env_int(kwargs, "anchor_batch_size", "ETP_ANCHOR_BATCH_SIZE")
        _env_float(kwargs, "anchor_interval_seconds", "ETP_ANCHOR_INTERVAL")
        _env_float(kwargs, "anchor_max_wait_seconds", "ETP_ANCHOR_MAX_WAIT")
        _env_int(kwargs, "anchor_confirmation_depth", "ETP_ANCHOR_CONFIRMATION_DEPTH")
        _env_int(kwargs, "anchor_finality_depth", "ETP_ANCHOR_FINALITY_DEPTH")
        _env_int(kwargs, "anchor_max_rpc_retries", "ETP_ANCHOR_MAX_RPC_RETRIES")
        _env_int(kwargs, "anchor_rest_port", "ETP_ANCHOR_REST_PORT")
        _env_int(kwargs, "diagnostics_port", "ETP_DIAGNOSTICS_PORT")
        _env_bool(kwargs, "diagnostics_public_mode", "ETP_DIAGNOSTICS_PUBLIC_MODE")

        peers_str = os.environ.get("ETP_SEED_PEERS", "")
        if peers_str:
            kwargs["seed_peers"] = [p.strip() for p in peers_str.split(",") if p.strip()]

        # Multi-chain: JSON array of chain config dicts
        chains_json = os.environ.get("ETP_ANCHOR_CHAINS_JSON", "")
        if chains_json:
            import json

            try:
                parsed = json.loads(chains_json)
            except json.JSONDecodeError as e:
                raise ValueError(f"ETP_ANCHOR_CHAINS_JSON is not valid JSON: {e}") from e
            if not isinstance(parsed, list):
                raise ValueError(
                    f"ETP_ANCHOR_CHAINS_JSON must be a JSON array, got {type(parsed).__name__}"
                )
            kwargs["anchor_chains"] = parsed

        # Gateway
        _env_bool(kwargs, "gateway_enabled", "ETP_GATEWAY_ENABLED")
        _env_int(kwargs, "gateway_port", "ETP_GATEWAY_PORT")
        _env_bool(kwargs, "gateway_jwt_enabled", "ETP_GATEWAY_JWT_ENABLED")
        _env_int(kwargs, "gateway_jwt_ttl_seconds", "ETP_GATEWAY_JWT_TTL")
        _env_int(kwargs, "gateway_rate_limit_per_minute", "ETP_GATEWAY_RATE_LIMIT")

        # Gossip
        _env_bool(kwargs, "gossip_enabled", "ETP_GOSSIP_ENABLED")
        _env_float(kwargs, "gossip_interval_seconds", "ETP_GOSSIP_INTERVAL")
        _env_int(kwargs, "gossip_max_peers", "ETP_GOSSIP_MAX_PEERS")
        _env_float(kwargs, "gossip_liveness_timeout_seconds", "ETP_GOSSIP_LIVENESS_TIMEOUT")

        # TLS
        # Governance
        _env_str(kwargs, "governance_contract_address", "ETP_GOVERNANCE_CONTRACT")
        _env_str(kwargs, "governance_chain_rpc", "ETP_GOVERNANCE_RPC")
        _env_int(kwargs, "governance_chain_id", "ETP_GOVERNANCE_CHAIN_ID")

        # KMS
        _env_str(kwargs, "kms_backend", "ETP_KMS_BACKEND")
        _env_str(kwargs, "kms_region", "ETP_KMS_REGION")
        _env_str(kwargs, "kms_key_arn", "ETP_KMS_KEY_ARN")
        _env_str(kwargs, "kms_endpoint", "ETP_KMS_ENDPOINT")

        # Observability
        _env_bool(kwargs, "observability_enabled", "ETP_OBSERVABILITY_ENABLED")

        _env_bool(kwargs, "tls_enabled", "ETP_TLS_ENABLED")
        _env_str(kwargs, "tls_cert_path", "ETP_TLS_CERT_PATH")
        _env_str(kwargs, "tls_key_path", "ETP_TLS_KEY_PATH")
        _env_str(kwargs, "tls_ca_path", "ETP_TLS_CA_PATH")
        _env_bool(kwargs, "tls_require_client_cert", "ETP_TLS_REQUIRE_CLIENT_CERT")

        # Bridge operator
        _env_bool(kwargs, "bridge_operator_enabled", "ETP_BRIDGE_OPERATOR_ENABLED")
        _env_float(kwargs, "bridge_operator_interval_seconds", "ETP_BRIDGE_OPERATOR_INTERVAL")
        _env_str(kwargs, "bridge_operator_direction", "ETP_BRIDGE_OPERATOR_DIRECTION")
        _env_int(kwargs, "bridge_operator_max_retries", "ETP_BRIDGE_OPERATOR_MAX_RETRIES")
        _env_float(
            kwargs, "bridge_operator_challenge_period", "ETP_BRIDGE_OPERATOR_CHALLENGE_PERIOD"
        )
        _env_str(kwargs, "bridge_operator_zk_mode", "ETP_BRIDGE_OPERATOR_ZK_MODE")

        return cls(**kwargs)

    @classmethod
    def from_toml_with_env_overlay(cls, path: str) -> "NodeConfig":
        """Load from TOML, then override with any set environment variables."""
        config = cls.from_toml(path)

        # Apply env overrides on top
        _env_str_override(config, "node_id", "ETP_NODE_ID")
        _env_str_override(config, "region", "ETP_REGION")
        _env_str_override(config, "listen_host", "ETP_LISTEN_HOST")
        _env_int_override(config, "listen_port", "ETP_LISTEN_PORT")
        _env_int_override(config, "rest_port", "ETP_REST_PORT")
        _env_str_override(config, "keypair_path", "ETP_KEYPAIR_PATH")
        _env_str_override(config, "storage_backend", "ETP_STORAGE_BACKEND")
        _env_str_override(config, "storage_path", "ETP_STORAGE_PATH")
        _env_int_override(config, "max_workers", "ETP_MAX_WORKERS")
        _env_bool_override(config, "require_real_crypto", "ETP_REQUIRE_REAL_CRYPTO")
        _env_str_override(config, "log_level", "ETP_LOG_LEVEL")
        _env_float_override(config, "audit_interval_seconds", "ETP_AUDIT_INTERVAL")
        _env_int_override(config, "strike_threshold", "ETP_STRIKE_THRESHOLD")

        # Anchor overrides
        _env_bool_override(config, "anchor_enabled", "ETP_ANCHOR_ENABLED")
        _env_str_override(config, "anchor_rpc_url", "ETP_ANCHOR_RPC_URL")
        _env_str_override(config, "anchor_registry_address", "ETP_ANCHOR_REGISTRY")
        _env_str_override(config, "anchor_operator_key", "ETP_ANCHOR_OPERATOR_KEY")
        _env_int_override(config, "anchor_chain_id", "ETP_ANCHOR_CHAIN_ID")
        _env_int_override(config, "anchor_batch_size", "ETP_ANCHOR_BATCH_SIZE")
        _env_float_override(config, "anchor_interval_seconds", "ETP_ANCHOR_INTERVAL")
        _env_float_override(config, "anchor_max_wait_seconds", "ETP_ANCHOR_MAX_WAIT")
        _env_int_override(config, "anchor_confirmation_depth", "ETP_ANCHOR_CONFIRMATION_DEPTH")
        _env_int_override(config, "anchor_finality_depth", "ETP_ANCHOR_FINALITY_DEPTH")
        _env_int_override(config, "anchor_max_rpc_retries", "ETP_ANCHOR_MAX_RPC_RETRIES")
        _env_int_override(config, "anchor_rest_port", "ETP_ANCHOR_REST_PORT")
        _env_int_override(config, "diagnostics_port", "ETP_DIAGNOSTICS_PORT")
        _env_bool_override(config, "diagnostics_public_mode", "ETP_DIAGNOSTICS_PUBLIC_MODE")

        # Gateway overrides
        _env_bool_override(config, "gateway_enabled", "ETP_GATEWAY_ENABLED")
        _env_int_override(config, "gateway_port", "ETP_GATEWAY_PORT")
        _env_bool_override(config, "gateway_jwt_enabled", "ETP_GATEWAY_JWT_ENABLED")
        _env_int_override(config, "gateway_jwt_ttl_seconds", "ETP_GATEWAY_JWT_TTL")
        _env_int_override(config, "gateway_rate_limit_per_minute", "ETP_GATEWAY_RATE_LIMIT")

        # Gossip overrides
        _env_bool_override(config, "gossip_enabled", "ETP_GOSSIP_ENABLED")
        _env_float_override(config, "gossip_interval_seconds", "ETP_GOSSIP_INTERVAL")
        _env_int_override(config, "gossip_max_peers", "ETP_GOSSIP_MAX_PEERS")
        _env_float_override(
            config, "gossip_liveness_timeout_seconds", "ETP_GOSSIP_LIVENESS_TIMEOUT"
        )

        # TLS overrides
        # Governance overrides
        _env_str_override(config, "governance_contract_address", "ETP_GOVERNANCE_CONTRACT")
        _env_str_override(config, "governance_chain_rpc", "ETP_GOVERNANCE_RPC")
        _env_int_override(config, "governance_chain_id", "ETP_GOVERNANCE_CHAIN_ID")

        # KMS overrides
        _env_str_override(config, "kms_backend", "ETP_KMS_BACKEND")
        _env_str_override(config, "kms_region", "ETP_KMS_REGION")
        _env_str_override(config, "kms_key_arn", "ETP_KMS_KEY_ARN")
        _env_str_override(config, "kms_endpoint", "ETP_KMS_ENDPOINT")

        # Observability override
        _env_bool_override(config, "observability_enabled", "ETP_OBSERVABILITY_ENABLED")

        _env_bool_override(config, "tls_enabled", "ETP_TLS_ENABLED")
        _env_str_override(config, "tls_cert_path", "ETP_TLS_CERT_PATH")
        _env_str_override(config, "tls_key_path", "ETP_TLS_KEY_PATH")
        _env_str_override(config, "tls_ca_path", "ETP_TLS_CA_PATH")
        _env_bool_override(config, "tls_require_client_cert", "ETP_TLS_REQUIRE_CLIENT_CERT")

        # Bridge operator overrides
        _env_bool_override(config, "bridge_operator_enabled", "ETP_BRIDGE_OPERATOR_ENABLED")
        _env_float_override(
            config, "bridge_operator_interval_seconds", "ETP_BRIDGE_OPERATOR_INTERVAL"
        )
        _env_str_override(config, "bridge_operator_direction", "ETP_BRIDGE_OPERATOR_DIRECTION")
        _env_int_override(config, "bridge_operator_max_retries", "ETP_BRIDGE_OPERATOR_MAX_RETRIES")
        _env_float_override(
            config, "bridge_operator_challenge_period", "ETP_BRIDGE_OPERATOR_CHALLENGE_PERIOD"
        )
        _env_str_override(config, "bridge_operator_zk_mode", "ETP_BRIDGE_OPERATOR_ZK_MODE")

        peers_str = os.environ.get("ETP_SEED_PEERS")
        if peers_str is not None:
            config.seed_peers = [p.strip() for p in peers_str.split(",") if p.strip()]

        # Multi-chain env overlay
        chains_json = os.environ.get("ETP_ANCHOR_CHAINS_JSON")
        if chains_json is not None:
            import json

            try:
                parsed = json.loads(chains_json)
            except json.JSONDecodeError as e:
                raise ValueError(f"ETP_ANCHOR_CHAINS_JSON is not valid JSON: {e}") from e
            if not isinstance(parsed, list):
                raise ValueError(
                    f"ETP_ANCHOR_CHAINS_JSON must be a JSON array, got {type(parsed).__name__}"
                )
            config.anchor_chains = parsed

        return config

    @classmethod
    def _from_dict(cls, data: dict) -> "NodeConfig":
        """Build NodeConfig from a nested TOML dict."""
        node = data.get("node", {})
        network = data.get("network", {})
        crypto = data.get("crypto", {})
        storage = data.get("storage", {})
        server = data.get("server", {})

        anchor = data.get("anchor", {})
        gateway = data.get("gateway", {})
        gossip = data.get("gossip", {})
        governance_cfg = data.get("governance", {})
        kms = data.get("kms", {})
        observability = data.get("observability", {})
        tls = data.get("tls", {})
        bridge_op = data.get("bridge_operator", {})

        return cls(
            node_id=node.get("node_id", cls.node_id),
            region=node.get("region", cls.region),
            listen_host=network.get("listen_host", cls.listen_host),
            listen_port=network.get("listen_port", cls.listen_port),
            rest_port=network.get("rest_port", cls.rest_port),
            seed_peers=network.get("seed_peers", []),
            keypair_path=crypto.get("keypair_path", cls.keypair_path),
            require_real_crypto=crypto.get("require_real_crypto", cls.require_real_crypto),
            storage_backend=storage.get("backend", cls.storage_backend),
            storage_path=storage.get("path", cls.storage_path),
            max_workers=server.get("max_workers", cls.max_workers),
            log_level=server.get("log_level", cls.log_level),
            audit_interval_seconds=server.get("audit_interval", cls.audit_interval_seconds),
            strike_threshold=server.get("strike_threshold", cls.strike_threshold),
            # Anchor
            anchor_enabled=anchor.get("enabled", cls.anchor_enabled),
            anchor_rpc_url=anchor.get("rpc_url", cls.anchor_rpc_url),
            anchor_registry_address=anchor.get("registry_address", cls.anchor_registry_address),
            anchor_operator_key=anchor.get("operator_key", cls.anchor_operator_key),
            anchor_chain_id=anchor.get("chain_id", cls.anchor_chain_id),
            anchor_batch_size=anchor.get("batch_size", cls.anchor_batch_size),
            anchor_interval_seconds=anchor.get("interval", cls.anchor_interval_seconds),
            anchor_max_wait_seconds=anchor.get("max_wait", cls.anchor_max_wait_seconds),
            anchor_confirmation_depth=anchor.get(
                "confirmation_depth", cls.anchor_confirmation_depth
            ),
            anchor_finality_depth=anchor.get("finality_depth", cls.anchor_finality_depth),
            anchor_max_rpc_retries=anchor.get("max_rpc_retries", cls.anchor_max_rpc_retries),
            anchor_rest_port=anchor.get("rest_port", cls.anchor_rest_port),
            diagnostics_port=server.get("diagnostics_port", cls.diagnostics_port),
            diagnostics_public_mode=server.get(
                "diagnostics_public_mode", cls.diagnostics_public_mode
            ),
            # Multi-chain: [[anchor.chains]] in TOML
            anchor_chains=anchor.get("chains", []),
            # Gateway
            gateway_enabled=gateway.get("enabled", cls.gateway_enabled),
            gateway_port=gateway.get("port", cls.gateway_port),
            gateway_jwt_enabled=gateway.get("jwt_enabled", cls.gateway_jwt_enabled),
            gateway_jwt_ttl_seconds=gateway.get("jwt_ttl_seconds", cls.gateway_jwt_ttl_seconds),
            gateway_rate_limit_per_minute=gateway.get(
                "rate_limit_per_minute", cls.gateway_rate_limit_per_minute
            ),
            # Gossip
            gossip_enabled=gossip.get("enabled", cls.gossip_enabled),
            gossip_interval_seconds=gossip.get("interval_seconds", cls.gossip_interval_seconds),
            gossip_max_peers=gossip.get("max_peers", cls.gossip_max_peers),
            gossip_liveness_timeout_seconds=gossip.get(
                "liveness_timeout_seconds", cls.gossip_liveness_timeout_seconds
            ),
            # TLS
            governance_contract_address=governance_cfg.get(
                "contract_address", cls.governance_contract_address
            ),
            governance_chain_rpc=governance_cfg.get("chain_rpc", cls.governance_chain_rpc),
            governance_chain_id=governance_cfg.get("chain_id", cls.governance_chain_id),
            kms_backend=kms.get("backend", cls.kms_backend),
            kms_region=kms.get("region", cls.kms_region),
            kms_key_arn=kms.get("key_arn", cls.kms_key_arn),
            kms_endpoint=kms.get("endpoint", cls.kms_endpoint),
            observability_enabled=observability.get("enabled", cls.observability_enabled),
            tls_enabled=tls.get("enabled", cls.tls_enabled),
            tls_cert_path=tls.get("cert_path", cls.tls_cert_path),
            tls_key_path=tls.get("key_path", cls.tls_key_path),
            tls_ca_path=tls.get("ca_path", cls.tls_ca_path),
            tls_require_client_cert=tls.get("require_client_cert", cls.tls_require_client_cert),
            # Bridge operator
            bridge_operator_enabled=bridge_op.get("enabled", cls.bridge_operator_enabled),
            bridge_operator_interval_seconds=bridge_op.get(
                "interval", cls.bridge_operator_interval_seconds
            ),
            bridge_operator_direction=bridge_op.get("direction", cls.bridge_operator_direction),
            bridge_operator_max_retries=bridge_op.get(
                "max_retries", cls.bridge_operator_max_retries
            ),
            bridge_operator_challenge_period=bridge_op.get(
                "challenge_period", cls.bridge_operator_challenge_period
            ),
            bridge_operator_zk_mode=bridge_op.get("zk_mode", cls.bridge_operator_zk_mode),
        )


# ---------------------------------------------------------------------------
# Env-var helpers
# ---------------------------------------------------------------------------


def _env_str(d: dict, key: str, env: str) -> None:
    val = os.environ.get(env)
    if val is not None:
        d[key] = val


def _env_int(d: dict, key: str, env: str) -> None:
    val = os.environ.get(env)
    if val is not None:
        d[key] = int(val)


def _env_float(d: dict, key: str, env: str) -> None:
    val = os.environ.get(env)
    if val is not None:
        d[key] = float(val)


def _env_bool(d: dict, key: str, env: str) -> None:
    val = os.environ.get(env)
    if val is not None:
        d[key] = val.lower() in ("true", "1", "yes")


def _env_str_override(config: NodeConfig, attr: str, env: str) -> None:
    val = os.environ.get(env)
    if val is not None:
        setattr(config, attr, val)


def _env_int_override(config: NodeConfig, attr: str, env: str) -> None:
    val = os.environ.get(env)
    if val is not None:
        setattr(config, attr, int(val))


def _env_float_override(config: NodeConfig, attr: str, env: str) -> None:
    val = os.environ.get(env)
    if val is not None:
        setattr(config, attr, float(val))


def _env_bool_override(config: NodeConfig, attr: str, env: str) -> None:
    val = os.environ.get(env)
    if val is not None:
        setattr(config, attr, val.lower() in ("true", "1", "yes"))
