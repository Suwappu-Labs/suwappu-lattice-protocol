"""
Backend factory — instantiate the appropriate backend from configuration.

Usage:
    from ltp.backends import BackendConfig, create_backend

    backend = create_backend(BackendConfig(backend_type="base-l1"))
    backend = create_backend(BackendConfig(backend_type="ethereum", eth_use_l2=True))
    backend = create_backend(BackendConfig(backend_type="local"))
"""

from __future__ import annotations

from .base import BackendConfig, CommitmentBackend
from .base_l1 import BaseL1Backend
from .ethereum import EthereumBackend
from .local import LocalBackend

_REGISTRY: dict[str, type[CommitmentBackend]] = {
    "local": LocalBackend,
    "base-l1": BaseL1Backend,
    "ethereum": EthereumBackend,
}


def create_backend(config: BackendConfig) -> CommitmentBackend:
    """
    Create a commitment backend from the given configuration.

    Supported backend_type values:
      - "local"     — in-memory, instant finality, no economics
      - "base-l1"   — custom L1, single-slot finality, native proofs
      - "ethereum"  — Ethereum L1/L2 smart contracts, probabilistic finality

    Raises ValueError for unknown backend types.
    """
    cls = _REGISTRY.get(config.backend_type)
    if cls is None:
        raise ValueError(
            f"Unknown backend type '{config.backend_type}'. Available: {sorted(_REGISTRY.keys())}"
        )
    return cls(config)
