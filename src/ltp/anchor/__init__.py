"""
On-chain anchor state machine for the Lattice Transfer Protocol.

Manages entity lifecycle on-chain: UNKNOWN → COMMITTED → ANCHORED →
MATERIALIZED, with DISPUTED and DELETED terminal states.

Not to be confused with bridge/anchor.py (L1 bridge anchor), which handles
cross-chain message commitment. This package manages the on-chain entity
state machine that smart contracts use to track trust artifacts.

Reference: GSX_PRE_BLOCKCHAIN_ROADMAP.md §2.9-2.10
"""

from .chain_config import ChainConfig, create_anchor_client
from .state import VALID_TRANSITIONS, EntityState, validate_transition
from .submission import AnchorSubmission

__all__ = [
    "EntityState",
    "VALID_TRANSITIONS",
    "validate_transition",
    "AnchorSubmission",
    "ChainConfig",
    "create_anchor_client",
]


def get_anchor_client(
    rpc_url: str,
    contract_address: str,
    private_key: str,
    chain_id: int,
    verify_live_config: bool = False,
) -> "AnchorClient":
    """Factory for AnchorClient. Requires ltp[chain] extra.

    Args:
        verify_live_config: If True, calls verify_live_configuration()
            after construction. Raises RuntimeError on bad RPC, chain ID
            mismatch, or missing contract code.
    """
    from .client import AnchorClient

    client = AnchorClient(rpc_url, contract_address, private_key, chain_id)
    if verify_live_config:
        client.verify_live_configuration()
    return client
