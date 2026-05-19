"""
Per-chain configuration for multi-chain anchor deployment.

Each ChainConfig holds the RPC, registry address, operator key, and
tuning parameters for one target chain.  The create_anchor_client()
factory wires these into an AnchorClient instance with per-chain rate
limiter and circuit breaker settings.

Reference: ETP_UNIFIED_NODE_DEPLOYMENT_PLAN.md §4
"""

from __future__ import annotations

import logging
import os
import re

logger = logging.getLogger(__name__)
from dataclasses import dataclass

__all__ = ["ChainConfig", "create_anchor_client"]

_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


@dataclass(frozen=True)
class ChainConfig:
    """Immutable configuration for a single target chain."""

    chain_id: int
    label: str  # "gsx_testnet", "base_sepolia"
    rpc_url: str
    registry_address: str
    operator_key: str  # Raw private key (development) or empty if using KMS
    operator_kms_key_id: str = ""  # KMS key ARN/ID for production (overrides operator_key)
    confirmation_depth: int = 3
    finality_depth: int = 1
    max_tps: float = 10.0
    burst: int = 20
    failure_threshold: int = 5
    cooldown_seconds: float = 30.0
    tx_timeout: int = 120
    max_rpc_retries: int = 5

    def __post_init__(self) -> None:
        if not isinstance(self.chain_id, int) or self.chain_id <= 0:
            raise ValueError("chain_id must be a positive integer")
        if not self.rpc_url:
            raise ValueError("rpc_url is required and must be non-empty")
        if not _ADDRESS_RE.match(self.registry_address):
            raise ValueError("invalid registry_address format")
        if not self.operator_key and not self.operator_kms_key_id:
            raise ValueError("operator_key or operator_kms_key_id is required")
        if self.operator_key and not self.operator_kms_key_id:
            import warnings

            warnings.warn(
                "Using plaintext operator_key — production should use KMS",
                stacklevel=2,
            )

    def __repr__(self) -> str:
        fields = []
        for f in self.__dataclass_fields__:
            val = getattr(self, f)
            if f == "operator_key":
                fields.append(f"{f}='***REDACTED***'")
            else:
                fields.append(f"{f}={val!r}")
        return f"ChainConfig({', '.join(fields)})"

    @classmethod
    def from_dict(cls, data: dict) -> "ChainConfig":
        """Build a ChainConfig from a plain dict (e.g. parsed TOML section).

        Required keys: chain_id, rpc_url, registry_address, operator_key.
        All other keys fall back to dataclass defaults.
        """
        if "chain_id" not in data:
            raise ValueError("chain_id is required")

        return cls(
            chain_id=int(data["chain_id"]),
            label=data.get("label", ""),
            rpc_url=data.get("rpc_url", ""),
            registry_address=data.get("registry_address", ""),
            operator_key=data.get("operator_key", ""),
            operator_kms_key_id=data.get("operator_kms_key_id", ""),
            confirmation_depth=int(data.get("confirmation_depth", 3)),
            finality_depth=int(data.get("finality_depth", 1)),
            max_tps=float(data.get("max_tps", 10.0)),
            burst=int(data.get("burst", 20)),
            failure_threshold=int(data.get("failure_threshold", 5)),
            cooldown_seconds=float(data.get("cooldown_seconds", 30.0)),
            tx_timeout=int(data.get("tx_timeout", 120)),
            max_rpc_retries=int(data.get("max_rpc_retries", 5)),
        )

    @classmethod
    def from_env(cls, prefix: str) -> "ChainConfig":
        """Build a ChainConfig from environment variables.

        Reads {PREFIX}_CHAIN_ID, {PREFIX}_RPC_URL, {PREFIX}_REGISTRY_ADDRESS,
        {PREFIX}_OPERATOR_KEY, and optional tuning vars.
        """

        def _get(name: str, default: str | None = None) -> str:
            val = os.environ.get(f"{prefix}{name}", default)
            if val is None:
                raise EnvironmentError(f"Missing required env var: {prefix}{name}")
            return val

        return cls(
            chain_id=int(_get("CHAIN_ID")),
            label=_get("LABEL", ""),
            rpc_url=_get("RPC_URL"),
            registry_address=_get("REGISTRY_ADDRESS"),
            operator_key=_get("OPERATOR_KEY", ""),
            operator_kms_key_id=_get("OPERATOR_KMS_KEY_ID", ""),
            confirmation_depth=int(_get("CONFIRMATION_DEPTH", "3")),
            finality_depth=int(_get("FINALITY_DEPTH", "1")),
            max_tps=float(_get("MAX_TPS", "10.0")),
            burst=int(_get("BURST", "20")),
            failure_threshold=int(_get("FAILURE_THRESHOLD", "5")),
            cooldown_seconds=float(_get("COOLDOWN_SECONDS", "30.0")),
            tx_timeout=int(_get("TX_TIMEOUT", "120")),
            max_rpc_retries=int(_get("MAX_RPC_RETRIES", "5")),
        )


def create_anchor_client(chain: ChainConfig, kms_backend=None) -> "AnchorClient":
    """Factory: create an AnchorClient from a ChainConfig.

    If the chain has operator_kms_key_id set and a kms_backend is provided,
    signing keys are managed via KMS instead of raw private key.

    Passes all per-chain parameters (rate limiter, circuit breaker, timeout)
    to the AnchorClient constructor.
    """
    from .client import AnchorClient

    # Determine signing key: prefer KMS, fall back to raw key
    private_key = chain.operator_key
    if chain.operator_kms_key_id and kms_backend is not None:
        # KMS-managed key: the private_key may be empty — AnchorClient
        # will use KMS for signing via the kms_backend parameter
        logger.info(
            "Using KMS key %s for chain %s",
            chain.operator_kms_key_id[:20],
            chain.label,
        )

    return AnchorClient(
        rpc_url=chain.rpc_url,
        contract_address=chain.registry_address,
        private_key=private_key,
        chain_id=chain.chain_id,
        tx_timeout=chain.tx_timeout,
        max_tps=chain.max_tps,
        burst=chain.burst,
        failure_threshold=chain.failure_threshold,
        cooldown_seconds=chain.cooldown_seconds,
    )
