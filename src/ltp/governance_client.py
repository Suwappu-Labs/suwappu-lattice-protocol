"""
On-chain governance client — submits votes and transitions to ETPGovernance.sol.

Follows AnchorClient pattern: web3.py client with rate limiter and retry.

ML-DSA-65 signature verification happens off-chain (Python side).
The contract validates: operator authorization, duplicate rejection,
sequence monotonicity, temporal expiry, and supermajority threshold.
"""

from __future__ import annotations

import logging
import time as _time
from typing import Optional

logger = logging.getLogger(__name__)

__all__ = ["OnChainGovernanceClient"]


def _keccak256(data: bytes) -> bytes:
    """Compute Keccak-256 hash (Ethereum's hash, NOT FIPS SHA3-256)."""
    try:
        from web3 import Web3

        return Web3.keccak(data)
    except ImportError:
        # Fallback: use pysha3 or pycryptodome
        try:
            import sha3

            return sha3.keccak_256(data).digest()
        except ImportError:
            raise ImportError("web3 or pysha3 required for keccak256: pip install web3")


# Minimal ABI for ETPGovernance contract
_GOVERNANCE_ABI = [
    {
        "name": "castVote",
        "type": "function",
        "inputs": [
            {"name": "transitionKey", "type": "bytes32"},
            {"name": "voterVkHash", "type": "bytes32"},
            {"name": "sequence", "type": "uint64"},
            {"name": "validUntil", "type": "uint64"},
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "name": "executeTransition",
        "type": "function",
        "inputs": [
            {"name": "fromPhase", "type": "bytes32"},
            {"name": "toPhase", "type": "bytes32"},
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "name": "getVoteCount",
        "type": "function",
        "inputs": [{"name": "transitionKey", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
    },
    {
        "name": "isSupermajority",
        "type": "function",
        "inputs": [{"name": "transitionKey", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "view",
    },
    {
        "name": "currentPhase",
        "type": "function",
        "inputs": [],
        "outputs": [{"name": "", "type": "bytes32"}],
        "stateMutability": "view",
    },
    {
        "name": "operatorCount",
        "type": "function",
        "inputs": [],
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
    },
    {
        "name": "getRequiredVotes",
        "type": "function",
        "inputs": [],
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
    },
]

# Phase constants (must match Solidity keccak256 values — NOT sha3_256!)
PHASE_BOOTSTRAP = _keccak256(b"bootstrap")
PHASE_GROWTH = _keccak256(b"growth")
PHASE_MATURITY = _keccak256(b"maturity")

_PHASE_NAMES = {
    PHASE_BOOTSTRAP: "bootstrap",
    PHASE_GROWTH: "growth",
    PHASE_MATURITY: "maturity",
}


def _make_transition_key(from_phase: str, to_phase: str) -> bytes:
    """Compute the on-chain transition key: keccak256(abi.encodePacked(fromPhaseHash, "->", toPhaseHash)).

    Must match Solidity: keccak256(abi.encodePacked(fromPhase, "->", toPhase))
    where fromPhase and toPhase are bytes32 keccak256 hashes.
    """
    phase_map = {"bootstrap": PHASE_BOOTSTRAP, "growth": PHASE_GROWTH, "maturity": PHASE_MATURITY}
    from_hash = phase_map.get(from_phase, _keccak256(from_phase.encode()))
    to_hash = phase_map.get(to_phase, _keccak256(to_phase.encode()))
    return _keccak256(from_hash + b"->" + to_hash)


class OnChainGovernanceClient:
    """Web3.py client for ETPGovernance contract.

    Submits votes and transitions on-chain. Read operations are free (view calls).
    Write operations require an operator key for signing transactions.
    """

    def __init__(
        self,
        rpc_url: str,
        contract_address: str,
        operator_key: str = "",
        chain_id: int = 0,
    ) -> None:
        try:
            from web3 import Web3
        except ImportError:
            raise ImportError("web3 is required: pip install web3")

        self._w3 = Web3(Web3.HTTPProvider(rpc_url))
        self._contract = self._w3.eth.contract(
            address=Web3.to_checksum_address(contract_address),
            abi=_GOVERNANCE_ABI,
        )
        self._account = None
        if operator_key:
            self._account = self._w3.eth.account.from_key(operator_key)
        self._chain_id = chain_id

    def cast_vote_on_chain(
        self,
        transition_key: bytes,
        voter_vk_hash: bytes,
        sequence: int,
        valid_until: int,
    ) -> str:
        """Submit a vote to the on-chain governance contract.

        Returns: transaction hash.
        """
        if self._account is None:
            raise ValueError("No operator key configured for write operations")

        fn = self._contract.functions.castVote(
            transition_key,
            voter_vk_hash,
            sequence,
            valid_until,
        )
        return self._send_tx(fn)

    def execute_transition_on_chain(self, from_phase: str, to_phase: str) -> str:
        """Execute a phase transition on-chain after supermajority.

        Returns: transaction hash.
        """
        if self._account is None:
            raise ValueError("No operator key configured for write operations")

        phase_map = {
            "bootstrap": PHASE_BOOTSTRAP,
            "growth": PHASE_GROWTH,
            "maturity": PHASE_MATURITY,
        }
        from_hash = phase_map.get(from_phase)
        to_hash = phase_map.get(to_phase)
        if from_hash is None or to_hash is None:
            raise ValueError(f"Unknown phase: {from_phase} or {to_phase}")

        fn = self._contract.functions.executeTransition(from_hash, to_hash)
        return self._send_tx(fn)

    def get_vote_count(self, transition_key: bytes) -> int:
        """Get current vote count for a transition (view call)."""
        return self._contract.functions.getVoteCount(transition_key).call()

    def is_supermajority(self, transition_key: bytes) -> bool:
        """Check if supermajority reached (view call)."""
        return self._contract.functions.isSupermajority(transition_key).call()

    def current_phase(self) -> str:
        """Get current network phase name (view call)."""
        phase_bytes = self._contract.functions.currentPhase().call()
        return _PHASE_NAMES.get(phase_bytes, f"unknown({phase_bytes.hex()[:16]})")

    def operator_count(self) -> int:
        """Get registered operator count (view call)."""
        return self._contract.functions.operatorCount().call()

    def required_votes(self) -> int:
        """Get required vote count for supermajority (view call)."""
        return self._contract.functions.getRequiredVotes().call()

    def _send_tx(self, fn) -> str:
        """Build, sign, and send a transaction with nonce retry."""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                nonce = self._w3.eth.get_transaction_count(self._account.address)
                try:
                    gas_estimate = fn.estimate_gas({"from": self._account.address})
                    gas_limit = int(gas_estimate * 1.2)
                except Exception:
                    gas_limit = 300_000
                tx = fn.build_transaction(
                    {
                        "from": self._account.address,
                        "nonce": nonce,
                        "gas": gas_limit,
                        "chainId": self._chain_id or self._w3.eth.chain_id,
                    }
                )
                signed = self._account.sign_transaction(tx)
                tx_hash = self._w3.eth.send_raw_transaction(signed.raw_transaction)
                receipt = self._w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
                if receipt["status"] != 1:
                    raise RuntimeError(f"Transaction reverted: {tx_hash.hex()}")
                return tx_hash.hex()
            except Exception as e:
                if "nonce" in str(e).lower() and attempt < max_retries - 1:
                    logger.warning("Nonce conflict (attempt %d), retrying...", attempt + 1)
                    _time.sleep(0.5 * (2**attempt))
                    continue
                raise
