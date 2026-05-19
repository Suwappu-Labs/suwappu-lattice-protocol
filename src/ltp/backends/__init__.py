"""
Commitment network backends for the Lattice Transfer Protocol.

Provides pluggable backend implementations for the commitment log and
network economics layer:

  - CommitmentBackend   — abstract interface every backend must implement
  - LocalBackend        — in-memory backend (default, used by tests)
  - BaseL1Backend       — custom L1 with parallel EVM execution
  - EthereumBackend     — Ethereum L1/L2 using smart contracts for commitment log

Usage:
  from ltp.backends import BackendConfig, create_backend

  # Option 1: Custom L1
  backend = create_backend(BackendConfig(backend_type="base-l1", ...))

  # Option 2: Ethereum
  backend = create_backend(BackendConfig(backend_type="ethereum", ...))

  # Default: local in-memory
  backend = create_backend(BackendConfig(backend_type="local"))
"""

from .base import BackendCapabilities, BackendConfig, CommitmentBackend
from .base_l1 import BaseL1Backend
from .ethereum import EthereumBackend
from .factory import create_backend
from .local import LocalBackend

__all__ = [
    "CommitmentBackend",
    "BackendConfig",
    "BackendCapabilities",
    "LocalBackend",
    "BaseL1Backend",
    "EthereumBackend",
    "create_backend",
]
