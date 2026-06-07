"""Gateway VM configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class GatewayVMConfig:
    """Configuration for the Gateway VM service.

    All fields have safe defaults. Use from_env() to overlay
    with ETP_GATEWAY_VM_* environment variables.
    """

    # General
    enabled: bool = False
    mode: str = "poa-attestation"
    gateway_id: str = "gateway-vm-0"

    # Source chain (external testnet to watch)
    source_chain_id: int = 84532  # Base Sepolia
    source_rpc_url: str = ""
    source_bridge_contract: str = ""
    finality_depth: int = 12
    poll_interval_seconds: float = 5.0

    # Destination chain (SUWAPPU devnet to anchor into)
    dest_chain_id: int = 103115120  # SUWAPPU Testnet
    dest_rpc_url: str = ""
    dest_registry_address: str = ""

    # Validation
    replay_db_path: str = ":memory:"
    max_retries: int = 5
    retry_interval_seconds: float = 30.0
    challenge_mode: str = "optimistic"  # "optimistic" | "zk" | "disabled"
    challenge_period_seconds: float = 3600.0

    # Observability
    metrics_port: int = 9090
    log_level: str = "info"

    @classmethod
    def from_env(cls) -> GatewayVMConfig:
        """Create config from ETP_GATEWAY_VM_* environment variables."""

        def _bool(key: str, default: bool) -> bool:
            val = os.environ.get(key, "")
            if not val:
                return default
            return val.lower() in ("true", "1", "yes")

        def _int(key: str, default: int) -> int:
            val = os.environ.get(key, "")
            return int(val) if val else default

        def _float(key: str, default: float) -> float:
            val = os.environ.get(key, "")
            return float(val) if val else default

        def _str(key: str, default: str) -> str:
            return os.environ.get(key, default)

        return cls(
            enabled=_bool("ETP_GATEWAY_VM_ENABLED", False),
            mode=_str("ETP_GATEWAY_VM_MODE", "poa-attestation"),
            gateway_id=_str("ETP_GATEWAY_VM_GATEWAY_ID", "gateway-vm-0"),
            source_chain_id=_int("ETP_GATEWAY_VM_SOURCE_CHAIN_ID", 84532),
            source_rpc_url=_str("ETP_GATEWAY_VM_SOURCE_RPC_URL", ""),
            source_bridge_contract=_str("ETP_GATEWAY_VM_SOURCE_BRIDGE_CONTRACT", ""),
            finality_depth=_int("ETP_GATEWAY_VM_FINALITY_DEPTH", 12),
            poll_interval_seconds=_float("ETP_GATEWAY_VM_POLL_INTERVAL", 5.0),
            dest_chain_id=_int("ETP_GATEWAY_VM_DEST_CHAIN_ID", 103115120),
            dest_rpc_url=_str("ETP_GATEWAY_VM_DEST_RPC_URL", ""),
            dest_registry_address=_str("ETP_GATEWAY_VM_DEST_REGISTRY", ""),
            replay_db_path=_str("ETP_GATEWAY_VM_REPLAY_DB_PATH", ":memory:"),
            max_retries=_int("ETP_GATEWAY_VM_MAX_RETRIES", 5),
            retry_interval_seconds=_float("ETP_GATEWAY_VM_RETRY_INTERVAL", 30.0),
            challenge_mode=_str("ETP_GATEWAY_VM_CHALLENGE_MODE", "optimistic"),
            challenge_period_seconds=_float("ETP_GATEWAY_VM_CHALLENGE_PERIOD", 3600.0),
            metrics_port=_int("ETP_GATEWAY_VM_METRICS_PORT", 9090),
            log_level=_str("ETP_GATEWAY_VM_LOG_LEVEL", "info"),
        )
