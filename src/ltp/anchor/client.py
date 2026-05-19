"""
Anchor client — submits AnchorSubmission instances to the on-chain LTPAnchorRegistry.

Bridges the Python trust layer to the Solidity contract via web3.py.
The client reads from AnchorSubmission dataclass fields directly (not
to_calldata() packed bytes), passing individual parameters through
web3.py's contract function interface for standard ABI encoding.

Requires: pip install web3>=6.0.0  (or install ltp[chain])

Reference: GSX_PRE_BLOCKCHAIN_ROADMAP.md §2.10
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..anchor.state import EntityState

logger = logging.getLogger(__name__)

__all__ = ["AnchorClient"]

# Default timeout for waiting on transaction receipts (seconds).
_TX_RECEIPT_TIMEOUT = 120

# Maximum number of retries on nonce-conflict errors.
_NONCE_RETRIES = 3

# Rate limiter defaults
_DEFAULT_MAX_TPS = 10  # max transactions per second
_DEFAULT_BURST = 20  # burst allowance (token bucket capacity)

# Circuit breaker defaults
_DEFAULT_FAILURE_THRESHOLD = 5  # consecutive failures to trip breaker
_DEFAULT_COOLDOWN_SECONDS = 30  # seconds to wait before retrying after trip


class CircuitBreaker:
    """Simple circuit breaker: trips after N consecutive failures, resets after cooldown."""

    def __init__(
        self,
        failure_threshold: int = _DEFAULT_FAILURE_THRESHOLD,
        cooldown_seconds: float = _DEFAULT_COOLDOWN_SECONDS,
    ) -> None:
        self._failure_threshold = failure_threshold
        self._cooldown_seconds = cooldown_seconds
        self._consecutive_failures = 0
        self._tripped_at: float | None = None
        self._lock = threading.Lock()

    @property
    def is_open(self) -> bool:
        """True if the circuit breaker is tripped (blocking requests)."""
        with self._lock:
            if self._tripped_at is None:
                return False
            elapsed = time.monotonic() - self._tripped_at
            if elapsed >= self._cooldown_seconds:
                # Cooldown expired — half-open state, allow one attempt
                return False
            return True

    def record_success(self) -> None:
        """Record a successful call — resets failure count."""
        with self._lock:
            self._consecutive_failures = 0
            self._tripped_at = None

    def record_failure(self) -> None:
        """Record a failed call — may trip the breaker."""
        with self._lock:
            self._consecutive_failures += 1
            if self._consecutive_failures >= self._failure_threshold:
                self._tripped_at = time.monotonic()
                logger.warning(
                    "[CircuitBreaker] TRIPPED after %d consecutive failures. Cooldown: %ds",
                    self._consecutive_failures,
                    self._cooldown_seconds,
                )

    @property
    def failure_count(self) -> int:
        return self._consecutive_failures


class TokenBucketRateLimiter:
    """Token bucket rate limiter: allows burst up to capacity, refills at max_tps."""

    def __init__(
        self,
        max_tps: float = _DEFAULT_MAX_TPS,
        burst: int = _DEFAULT_BURST,
    ) -> None:
        self._max_tps = max_tps
        self._burst = burst
        self._tokens = float(burst)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, timeout: float = 10.0) -> bool:
        """Block until a token is available or timeout expires. Returns True if acquired."""
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True
            if time.monotonic() >= deadline:
                return False
            # Wait for one token to refill
            time.sleep(1.0 / self._max_tps)

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._burst, self._tokens + elapsed * self._max_tps)
        self._last_refill = now


# Minimal ABI for LTPAnchorRegistry — only the functions we call.
_REGISTRY_ABI = [
    {
        "type": "function",
        "name": "anchor",
        "inputs": [
            {"name": "anchorDigest", "type": "bytes32"},
            {"name": "entityIdHash", "type": "bytes32"},
            {"name": "merkleRoot", "type": "bytes32"},
            {"name": "policyHash", "type": "bytes32"},
            {"name": "signerVkHash", "type": "bytes32"},
            {"name": "sequence", "type": "uint64"},
            {"name": "validUntil", "type": "uint64"},
            {"name": "receiptType", "type": "uint8"},
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "type": "function",
        "name": "batchAnchor",
        "inputs": [
            {"name": "anchorDigests", "type": "bytes32[]"},
            {"name": "entityIdHashes", "type": "bytes32[]"},
            {"name": "merkleRoots", "type": "bytes32[]"},
            {"name": "policyHashes", "type": "bytes32[]"},
            {"name": "signerVkHashes", "type": "bytes32[]"},
            {"name": "sequences", "type": "uint64[]"},
            {"name": "validUntils", "type": "uint64[]"},
            {"name": "receiptTypes", "type": "uint8[]"},
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "type": "function",
        "name": "transitionState",
        "inputs": [
            {"name": "entityIdHash", "type": "bytes32"},
            {"name": "newState", "type": "uint8"},
            {"name": "signerVkHash", "type": "bytes32"},
            {"name": "sequence", "type": "uint64"},
            {"name": "validUntil", "type": "uint64"},
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "type": "function",
        "name": "registerSigner",
        "inputs": [{"name": "vkHash", "type": "bytes32"}],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "type": "function",
        "name": "revokeSigner",
        "inputs": [{"name": "vkHash", "type": "bytes32"}],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "type": "function",
        "name": "isAnchored",
        "inputs": [{"name": "anchorDigest", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "view",
    },
    {
        "type": "function",
        "name": "getEntityState",
        "inputs": [{"name": "entityIdHash", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "uint8"}],
        "stateMutability": "view",
    },
    {
        "type": "function",
        "name": "getSignerSequence",
        "inputs": [{"name": "vkHash", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "uint64"}],
        "stateMutability": "view",
    },
    {
        "type": "function",
        "name": "areAnchored",
        "inputs": [{"name": "anchorDigests", "type": "bytes32[]"}],
        "outputs": [{"name": "", "type": "bool[]"}],
        "stateMutability": "view",
    },
    {
        "type": "function",
        "name": "getEntityStates",
        "inputs": [{"name": "entityIdHashes", "type": "bytes32[]"}],
        "outputs": [{"name": "", "type": "uint8[]"}],
        "stateMutability": "view",
    },
    # v6 — atomic signer rotation
    {
        "type": "function",
        "name": "rotateSigner",
        "inputs": [
            {"name": "oldVkHash", "type": "bytes32"},
            {"name": "newVkHash", "type": "bytes32"},
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    # v6 — entity-signer reassignment
    {
        "type": "function",
        "name": "reassignEntitySigner",
        "inputs": [
            {"name": "entityIdHash", "type": "bytes32"},
            {"name": "newSignerVkHash", "type": "bytes32"},
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    # v6 — entity-signer binding query
    {
        "type": "function",
        "name": "entitySigners",
        "inputs": [{"name": "entityIdHash", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "bytes32"}],
        "stateMutability": "view",
    },
]

# ReceiptType string → uint8 ordinal mapping (mirrors receipt.py ReceiptType enum)
_RECEIPT_TYPE_ORDINALS: dict[str, int] = {
    "COMMIT": 0,
    "MATERIALIZE": 1,
    "SHARD_AUDIT_PASS": 2,
    "KEY_ROTATION": 3,
    "DELETION": 4,
    "GOVERNANCE": 5,
}


class AnchorClient:
    """Submits AnchorSubmission instances to the on-chain LTPAnchorRegistry."""

    def __init__(
        self,
        rpc_url: str,
        contract_address: str,
        private_key: str,
        chain_id: int,
        tx_timeout: int = _TX_RECEIPT_TIMEOUT,
        max_tps: float = _DEFAULT_MAX_TPS,
        burst: int = _DEFAULT_BURST,
        failure_threshold: int = _DEFAULT_FAILURE_THRESHOLD,
        cooldown_seconds: float = _DEFAULT_COOLDOWN_SECONDS,
    ) -> None:
        try:
            from web3 import Web3
        except ImportError as e:
            raise ImportError(
                "web3 is required for on-chain anchoring. Install with: pip install 'ltp[chain]'"
            ) from e

        self._w3 = Web3(Web3.HTTPProvider(rpc_url))
        self._account = self._w3.eth.account.from_key(private_key)
        self._chain_id = chain_id
        self._contract = self._w3.eth.contract(
            address=Web3.to_checksum_address(contract_address),
            abi=_REGISTRY_ABI,
        )
        self._tx_timeout = tx_timeout
        self._nonce_lock = threading.Lock()
        self._chain_id = chain_id

        # Rate limiter: prevents self-DoS under sustained load
        self._rate_limiter = TokenBucketRateLimiter(max_tps=max_tps, burst=burst)

        # Circuit breaker: stops sending after consecutive failures
        self._circuit_breaker = CircuitBreaker(
            failure_threshold=failure_threshold,
            cooldown_seconds=cooldown_seconds,
        )

    @classmethod
    def from_env(cls, prefix: str = "") -> "AnchorClient":
        """Create an AnchorClient from environment variables.

        Reads configuration from env vars, optionally prefixed (e.g. prefix="GSX_"
        reads GSX_RPC_URL, GSX_CHAIN_ID, etc.).

        Required env vars: {prefix}RPC_URL, {prefix}ANCHOR_REGISTRY,
                          {prefix}OPERATOR_KEY, {prefix}CHAIN_ID
        Optional: {prefix}ANCHOR_MAX_TPS, {prefix}ANCHOR_BURST,
                  {prefix}ANCHOR_FAILURE_THRESHOLD, {prefix}ANCHOR_COOLDOWN_SECONDS,
                  {prefix}ANCHOR_TX_TIMEOUT
        """

        def _get(name: str, default: str | None = None) -> str:
            val = os.environ.get(f"{prefix}{name}", default)
            if val is None:
                raise EnvironmentError(f"Missing required env var: {prefix}{name}")
            return val

        client = cls(
            rpc_url=_get("RPC_URL"),
            contract_address=_get("ANCHOR_REGISTRY"),
            private_key=_get("OPERATOR_KEY"),
            chain_id=int(_get("CHAIN_ID")),
            tx_timeout=int(_get("ANCHOR_TX_TIMEOUT", str(_TX_RECEIPT_TIMEOUT))),
            max_tps=float(_get("ANCHOR_MAX_TPS", str(_DEFAULT_MAX_TPS))),
            burst=int(_get("ANCHOR_BURST", str(_DEFAULT_BURST))),
            failure_threshold=int(
                _get("ANCHOR_FAILURE_THRESHOLD", str(_DEFAULT_FAILURE_THRESHOLD))
            ),
            cooldown_seconds=float(_get("ANCHOR_COOLDOWN_SECONDS", str(_DEFAULT_COOLDOWN_SECONDS))),
        )

        if os.environ.get(f"{prefix}VERIFY_LIVE_CONFIG", "").strip() == "1":
            client.verify_live_configuration()

        return client

    def verify_live_configuration(self) -> None:
        """Fail-fast check: verifies RPC connectivity and chain ID match.

        Raises RuntimeError if:
          - RPC endpoint is unreachable
          - Connected chain ID doesn't match configured chain ID
          - Contract address has no deployed code

        Call this before sending any transactions to catch misconfigurations
        early instead of failing on the first anchor() call.
        """
        # 1. RPC connectivity
        if not self._w3.is_connected():
            raise RuntimeError(f"RPC endpoint unreachable: {self._w3.provider.endpoint_uri}")

        # 2. Chain ID match
        remote_chain_id = self._w3.eth.chain_id
        if remote_chain_id != self._chain_id:
            raise RuntimeError(
                f"Chain ID mismatch: configured={self._chain_id}, remote={remote_chain_id}"
            )

        # 3. Contract has deployed code
        code = self._w3.eth.get_code(self._contract.address)
        if code == b"" or code == b"\x00":
            raise RuntimeError(
                f"No contract deployed at {self._contract.address} on chain {self._chain_id}"
            )

        logger.info(
            "[AnchorClient] Live configuration verified: chain=%d, contract=%s",
            self._chain_id,
            self._contract.address,
        )

    def _send_tx(self, fn) -> dict:
        """Build, sign, send, and wait for a contract function call.

        Applies rate limiting and circuit breaker before sending. Uses gas
        estimation, nonce locking for thread safety, and receipt waiting
        with revert detection.

        Returns:
            Transaction receipt dict with 'status', 'transactionHash', etc.

        Raises:
            RuntimeError: If circuit breaker is open, rate limit exceeded,
                          or transaction reverts on-chain (status == 0).
            Exception: On RPC or signing errors after retries exhausted.
        """
        # Circuit breaker check
        if self._circuit_breaker.is_open:
            raise RuntimeError(
                f"Circuit breaker OPEN: {self._circuit_breaker.failure_count} "
                f"consecutive failures. Retry after cooldown."
            )

        # Rate limiting
        if not self._rate_limiter.acquire(timeout=self._tx_timeout):
            raise RuntimeError("Rate limit exceeded: could not acquire token")

        last_err = None
        for attempt in range(_NONCE_RETRIES):
            try:
                with self._nonce_lock:
                    nonce = self._w3.eth.get_transaction_count(self._account.address, "pending")
                    estimated_gas = fn.estimate_gas({"from": self._account.address})
                    # 20% headroom on gas estimate
                    gas_limit = int(estimated_gas * 1.2)

                    tx = fn.build_transaction(
                        {
                            "from": self._account.address,
                            "nonce": nonce,
                            "chainId": self._chain_id,
                            "gas": gas_limit,
                            "gasPrice": self._w3.eth.gas_price,
                        }
                    )
                    signed = self._account.sign_transaction(tx)
                    tx_hash = self._w3.eth.send_raw_transaction(signed.raw_transaction)

                receipt = self._w3.eth.wait_for_transaction_receipt(
                    tx_hash, timeout=self._tx_timeout
                )
                if receipt["status"] == 0:
                    self._circuit_breaker.record_failure()
                    raise RuntimeError(f"Transaction reverted: {tx_hash.hex()}")

                self._circuit_breaker.record_success()
                return receipt

            except Exception as e:
                err_msg = str(e).lower()
                if "nonce" in err_msg and attempt < _NONCE_RETRIES - 1:
                    last_err = e
                    continue
                self._circuit_breaker.record_failure()
                raise

        self._circuit_breaker.record_failure()
        raise RuntimeError(f"Transaction failed after {_NONCE_RETRIES} retries") from last_err

    def anchor(self, submission: "AnchorSubmission") -> str:
        """Anchor a single submission on-chain. Returns tx hash hex."""
        receipt_ordinal = _RECEIPT_TYPE_ORDINALS.get(submission.receipt_type, 0)
        entity_id_hash = getattr(submission, "entity_id_hash", submission.anchor_digest)
        fn = self._contract.functions.anchor(
            submission.anchor_digest,
            entity_id_hash,
            submission.merkle_root,
            submission.policy_hash,
            submission.signer_vk_hash,
            submission.sequence,
            submission.valid_until,
            receipt_ordinal,
        )
        receipt = self._send_tx(fn)
        return receipt["transactionHash"].hex()

    def batch_anchor(self, submissions: list["AnchorSubmission"]) -> str:
        """Anchor multiple submissions in a single transaction. Returns tx hash hex."""
        digests = [s.anchor_digest for s in submissions]
        entity_ids = [getattr(s, "entity_id_hash", s.anchor_digest) for s in submissions]
        roots = [s.merkle_root for s in submissions]
        policies = [s.policy_hash for s in submissions]
        signers = [s.signer_vk_hash for s in submissions]
        sequences = [s.sequence for s in submissions]
        valid_untils = [s.valid_until for s in submissions]
        receipt_types = [_RECEIPT_TYPE_ORDINALS.get(s.receipt_type, 0) for s in submissions]

        fn = self._contract.functions.batchAnchor(
            digests,
            entity_ids,
            roots,
            policies,
            signers,
            sequences,
            valid_untils,
            receipt_types,
        )
        receipt = self._send_tx(fn)
        return receipt["transactionHash"].hex()

    def transition_state(
        self,
        entity_id_hash: bytes,
        new_state: int,
        signer_vk_hash: bytes,
        sequence: int,
        valid_until: int,
    ) -> str:
        """Transition an entity's state on-chain. Returns tx hash hex."""
        fn = self._contract.functions.transitionState(
            entity_id_hash,
            new_state,
            signer_vk_hash,
            sequence,
            valid_until,
        )
        receipt = self._send_tx(fn)
        return receipt["transactionHash"].hex()

    def register_signer(self, vk_hash: bytes) -> str:
        """Register an authorized signer. Returns tx hash hex."""
        fn = self._contract.functions.registerSigner(vk_hash)
        receipt = self._send_tx(fn)
        return receipt["transactionHash"].hex()

    def revoke_signer(self, vk_hash: bytes) -> str:
        """Revoke an authorized signer. Returns tx hash hex."""
        fn = self._contract.functions.revokeSigner(vk_hash)
        receipt = self._send_tx(fn)
        return receipt["transactionHash"].hex()

    def is_anchored(self, anchor_digest: bytes) -> bool:
        """Check if an anchor digest has been recorded on-chain."""
        return self._contract.functions.isAnchored(anchor_digest).call()

    def entity_state(self, entity_id_hash: bytes) -> "EntityState":
        """Get the on-chain entity state for an entity ID hash."""
        from ..anchor.state import EntityState

        raw = self._contract.functions.getEntityState(entity_id_hash).call()
        return EntityState(raw)

    def signer_sequence(self, vk_hash: bytes) -> int:
        """Get the current on-chain sequence for a signer VK hash."""
        return self._contract.functions.getSignerSequence(vk_hash).call()

    def get_tx_receipt(self, tx_hash: str) -> dict | None:
        """Fetch a transaction receipt by hex hash, or None if still pending.

        Returns a dict with at minimum 'status', 'blockNumber', 'gasUsed'
        keys when the receipt exists.  Returns None for unmined transactions.

        Raises on RPC/network errors so the caller (AnchorVerifier) can
        distinguish "pending" (None) from "RPC down" (exception).
        """
        receipt = self._w3.eth.get_transaction_receipt(tx_hash)
        return dict(receipt) if receipt is not None else None

    def get_block_number(self) -> int:
        """Return the latest block number from the connected chain."""
        return self._w3.eth.block_number

    def are_anchored(self, anchor_digests: list[bytes]) -> list[bool]:
        """Batch check if anchor digests have been recorded on-chain."""
        return self._contract.functions.areAnchored(anchor_digests).call()

    def rotate_signer(self, old_vk_hash: bytes, new_vk_hash: bytes) -> str:
        """Atomically rotate a signer key. Returns tx hash hex."""
        fn = self._contract.functions.rotateSigner(old_vk_hash, new_vk_hash)
        receipt = self._send_tx(fn)
        return receipt["transactionHash"].hex()

    def reassign_entity_signer(self, entity_id_hash: bytes, new_signer_vk_hash: bytes) -> str:
        """Reassign an entity's bound signer. Returns tx hash hex."""
        fn = self._contract.functions.reassignEntitySigner(entity_id_hash, new_signer_vk_hash)
        receipt = self._send_tx(fn)
        return receipt["transactionHash"].hex()

    def get_entity_signer(self, entity_id_hash: bytes) -> bytes:
        """Get the bound signer VK hash for an entity."""
        return self._contract.functions.entitySigners(entity_id_hash).call()

    def get_entity_states(self, entity_id_hashes: list[bytes]) -> list["EntityState"]:
        """Batch get entity states for multiple entity ID hashes."""
        from ..anchor.state import EntityState

        raw_states = self._contract.functions.getEntityStates(entity_id_hashes).call()
        return [EntityState(s) for s in raw_states]
