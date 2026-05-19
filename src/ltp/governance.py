"""
Signer governance for the Lattice Transfer Protocol.

Defines the policy framework for multi-signer authorization:
  - SignerEntry:    A signer's identity, roles, and validity window
  - ApprovalRule:   Required roles/signers for a given action type
  - SignerPolicy:   The complete policy governing receipt authorization

Integrates with existing ComplianceRole and Permission enums from
compliance.py (read-only imports).

Reference: GSX_PRE_BLOCKCHAIN_ROADMAP.md §2.7
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

import math
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from .domain import (
    DOMAIN_GOVERNANCE_VOTE,
    DOMAIN_SIGNER_POLICY,
    domain_hash_bytes,
    domain_sign,
    domain_verify,
    signer_fingerprint,
)
from .encoding import CanonicalEncoder
from .primitives import MLDSA, canonical_hash

__all__ = [
    "SignerEntry",
    "ApprovalRule",
    "SignerPolicy",
    "TransitionVote",
    "TransitionVoteManager",
    "create_transition_vote",
    "verify_transition_vote",
]


@dataclass
class SignerEntry:
    """A signer's identity, roles, and validity window.

    Fields:
        signer_id:       Human-readable identifier (maps to KeyPair.label)
        vk:              ML-DSA-65 verification key
        roles:           Set of authorized roles (e.g. {"operator", "auditor"})
        valid_from:      Epoch from which this entry is active
        valid_until:     Epoch after which this entry is inactive
        predecessor_vk:  Previous VK if this is a key rotation (None otherwise)
    """

    signer_id: str
    vk: bytes
    roles: set[str]
    valid_from: int
    valid_until: int
    predecessor_vk: bytes | None = None


@dataclass
class ApprovalRule:
    """Required authorization for a given action type.

    Fields:
        action_type:     The action this rule governs ("COMMIT", "MATERIALIZE", etc.)
        required_roles:  At least one signer must hold each of these roles
        min_signers:     Minimum number of distinct signers required
        max_age_seconds: Maximum age of a receipt for this action type
    """

    action_type: str
    required_roles: set[str]
    min_signers: int = 1
    max_age_seconds: int = 3600


@dataclass
class SignerPolicy:
    """The complete policy governing receipt authorization.

    A SignerPolicy defines who can sign what, with what thresholds,
    and over what time windows. It is itself signed by a policy authority.

    Fields:
        policy_id:        Content-addressed identifier
        policy_version:   Monotonically increasing version
        signers:          Authorized signer entries
        approval_rules:   Per-action authorization rules
        policy_signature: ML-DSA-65 signature over policy content
    """

    policy_id: str
    policy_version: int
    signers: list[SignerEntry]
    approval_rules: list[ApprovalRule]
    policy_signature: bytes = b""

    def canonical_bytes(self) -> bytes:
        """Deterministic encoding for hashing/signing."""
        enc = (
            CanonicalEncoder(DOMAIN_SIGNER_POLICY)
            .uint32(self.policy_version)
            .uint32(len(self.signers))
        )
        for s in self.signers:
            enc.string(s.signer_id)
            enc.length_prefixed_bytes(s.vk)
            # Encode roles sorted
            sorted_roles = sorted(s.roles)
            enc.uint32(len(sorted_roles))
            for r in sorted_roles:
                enc.string(r)
            enc.uint64(s.valid_from)
            enc.uint64(s.valid_until)
            enc.optional_bytes(s.predecessor_vk)

        enc.uint32(len(self.approval_rules))
        for rule in self.approval_rules:
            enc.string(rule.action_type)
            sorted_roles = sorted(rule.required_roles)
            enc.uint32(len(sorted_roles))
            for r in sorted_roles:
                enc.string(r)
            enc.uint32(rule.min_signers)
            enc.uint32(rule.max_age_seconds)

        return enc.finalize()

    def policy_hash(self) -> str:
        """Content-addressed hash of the policy."""
        return canonical_hash(self.canonical_bytes())

    def sign_policy(self, authority_sk: bytes) -> None:
        """Sign this policy with the policy authority's key."""
        self.policy_id = self.policy_hash()
        self.policy_signature = domain_sign(
            DOMAIN_SIGNER_POLICY,
            authority_sk,
            self.canonical_bytes(),
        )

    def verify_policy(self, authority_vk: bytes) -> bool:
        """Verify the policy signature."""
        if not self.policy_signature:
            return False
        return domain_verify(
            DOMAIN_SIGNER_POLICY,
            authority_vk,
            self.canonical_bytes(),
            self.policy_signature,
        )

    def is_signer_authorized(self, vk: bytes, action: str, epoch: int) -> bool:
        """Check if a signer (by VK) is authorized for an action at an epoch.

        Returns True if the signer:
          1. Has an active SignerEntry (valid_from <= epoch < valid_until)
          2. Holds at least one role required by the action's ApprovalRule
        """
        # Find the signer entry
        entry = None
        for s in self.signers:
            if s.vk == vk:
                entry = s
                break
        if entry is None:
            return False

        # Check epoch validity
        if not (entry.valid_from <= epoch < entry.valid_until):
            return False

        # Find applicable rule
        rule = None
        for r in self.approval_rules:
            if r.action_type == action:
                rule = r
                break
        if rule is None:
            return False

        # Check role overlap
        return bool(entry.roles & rule.required_roles)

    def verify_receipt(self, receipt: "ApprovalReceipt") -> tuple[bool, str]:
        """Verify a receipt against this policy.

        Checks:
          1. Signer is authorized for the receipt's action type
          2. Receipt is not too old per the action's max_age_seconds
          3. Receipt signature is valid

        Returns: (True, "") or (False, reason)
        """
        # Check signer authorization
        action = receipt.receipt_type.value
        if not self.is_signer_authorized(receipt.signer_vk, action, receipt.epoch):
            return False, f"signer not authorized for {action} at epoch {receipt.epoch}"

        # Check receipt age
        rule = None
        for r in self.approval_rules:
            if r.action_type == action:
                rule = r
                break
        if rule is not None:
            age = time.time() - receipt.timestamp
            if age > rule.max_age_seconds:
                return False, f"receipt too old: {age:.0f}s > {rule.max_age_seconds}s"

        # Check signature
        if not receipt.verify(receipt.signer_vk):
            return False, "invalid signature"

        return True, ""


# ---------------------------------------------------------------------------
# Operator Supermajority Voting for Phase Transitions
# ---------------------------------------------------------------------------


@dataclass
class TransitionVote:
    """A single operator's signed vote for a phase transition."""

    voter_vk_hash: str
    from_phase: str
    to_phase: str
    signature: bytes
    timestamp: float
    voter_label: str = ""


def create_transition_vote(keypair, from_phase: str, to_phase: str) -> TransitionVote:
    """Create a signed transition vote using ML-DSA-65."""
    payload = DOMAIN_GOVERNANCE_VOTE + from_phase.encode() + to_phase.encode() + keypair.vk
    sig = keypair.sign(payload)
    return TransitionVote(
        voter_vk_hash=canonical_hash(keypair.vk),
        from_phase=from_phase,
        to_phase=to_phase,
        signature=sig,
        timestamp=time.time(),
        voter_label=keypair.label,
    )


def verify_transition_vote(vote: TransitionVote, voter_vk: bytes) -> bool:
    """Verify a transition vote signature."""
    payload = DOMAIN_GOVERNANCE_VOTE + vote.from_phase.encode() + vote.to_phase.encode() + voter_vk
    return MLDSA.verify(voter_vk, payload, vote.signature)


class OnChainGovernanceClient:
    """Bridges Python governance votes to the ETPGovernance Solidity contract.

    Requires web3 library (included in [chain] extras).
    Connects to the deployed ETPGovernance contract to:
      - Cast votes on-chain (castVote)
      - Check supermajority status (isSupermajority)
      - Execute phase transitions (executeTransition)
    """

    # Minimal ABI for the functions we call
    _ABI = [
        {
            "inputs": [
                {"name": "transitionKey", "type": "bytes32"},
                {"name": "voterVkHash", "type": "bytes32"},
                {"name": "sequence", "type": "uint64"},
                {"name": "validUntil", "type": "uint64"},
            ],
            "name": "castVote",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function",
        },
        {
            "inputs": [{"name": "transitionKey", "type": "bytes32"}],
            "name": "isSupermajority",
            "outputs": [{"type": "bool"}],
            "stateMutability": "view",
            "type": "function",
        },
        {
            "inputs": [
                {"name": "fromPhase", "type": "bytes32"},
                {"name": "toPhase", "type": "bytes32"},
            ],
            "name": "executeTransition",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function",
        },
        {
            "inputs": [{"name": "transitionKey", "type": "bytes32"}],
            "name": "getVoteCount",
            "outputs": [{"type": "uint256"}],
            "stateMutability": "view",
            "type": "function",
        },
    ]

    def __init__(self, rpc_url: str, contract_address: str, private_key: str) -> None:
        from web3 import Web3

        self._w3 = Web3(Web3.HTTPProvider(rpc_url))
        self._contract = self._w3.eth.contract(
            address=Web3.to_checksum_address(contract_address),
            abi=self._ABI,
        )
        self._account = self._w3.eth.account.from_key(private_key)

    def cast_vote_on_chain(
        self,
        transition_key: bytes,
        voter_vk_hash: bytes,
        sequence: int,
        valid_until: int,
    ) -> str:
        """Submit a vote to the on-chain ETPGovernance contract."""
        from web3 import Web3

        tx_key = Web3.keccak(transition_key) if len(transition_key) != 32 else transition_key
        vk_key = Web3.keccak(voter_vk_hash) if len(voter_vk_hash) != 32 else voter_vk_hash

        tx = self._contract.functions.castVote(
            tx_key,
            vk_key,
            sequence,
            valid_until,
        ).build_transaction(
            {
                "from": self._account.address,
                "nonce": self._w3.eth.get_transaction_count(self._account.address),
                "gas": 200_000,
            }
        )

        signed = self._account.sign_transaction(tx)
        tx_hash = self._w3.eth.send_raw_transaction(signed.raw_transaction)
        self._w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
        return tx_hash.hex()

    def check_supermajority(self, transition_key: bytes) -> bool:
        """Check if a transition has reached supermajority on-chain."""
        from web3 import Web3

        tx_key = Web3.keccak(transition_key) if len(transition_key) != 32 else transition_key
        return self._contract.functions.isSupermajority(tx_key).call()

    def execute_transition(self, from_phase: str, to_phase: str) -> str:
        """Execute a phase transition on-chain after supermajority."""
        from web3 import Web3

        from_key = Web3.keccak(text=from_phase)
        to_key = Web3.keccak(text=to_phase)

        tx = self._contract.functions.executeTransition(
            from_key,
            to_key,
        ).build_transaction(
            {
                "from": self._account.address,
                "nonce": self._w3.eth.get_transaction_count(self._account.address),
                "gas": 200_000,
            }
        )

        signed = self._account.sign_transaction(tx)
        tx_hash = self._w3.eth.send_raw_transaction(signed.raw_transaction)
        self._w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
        return tx_hash.hex()


class TransitionVoteManager:
    """Collects operator votes for phase transitions.

    Requires >=2/3 supermajority of registered operators.
    Thread-safe via threading.Lock.
    """

    def __init__(
        self,
        required_ratio: float = 2 / 3,
        clock: Optional[Callable[[], float]] = None,
        on_chain_client=None,
    ) -> None:
        if not (0.0 < required_ratio <= 1.0):
            raise ValueError("required_ratio must be in (0, 1]")
        self._required_ratio = required_ratio
        self._clock = clock or time.time
        self._on_chain_client = on_chain_client
        self._lock = threading.Lock()
        self._operators: dict[str, str] = {}  # operator_id → vk_hash
        self._votes: dict[str, list[TransitionVote]] = {}  # transition_key → votes

    def register_operator(self, operator_id: str, vk_hash: str) -> None:
        """Register an operator eligible to vote."""
        with self._lock:
            self._operators[operator_id] = vk_hash

    def cast_vote(
        self,
        transition_key: str,
        vote: TransitionVote,
        voter_vk: Optional[bytes] = None,
    ) -> dict:
        """Cast a signed vote. Returns current tally.

        If voter_vk is provided, verifies the vote signature.
        Rejects duplicate votes from the same operator.
        """
        if voter_vk is not None:
            if not verify_transition_vote(vote, voter_vk):
                raise ValueError("Vote signature verification failed")

        with self._lock:
            # Verify voter is a registered operator
            if vote.voter_vk_hash not in self._operators.values():
                raise ValueError(f"Voter {vote.voter_vk_hash[:16]} is not a registered operator")

            votes = self._votes.setdefault(transition_key, [])

            # Reject duplicate
            existing = {v.voter_vk_hash for v in votes}
            if vote.voter_vk_hash in existing:
                raise ValueError(
                    f"Operator {vote.voter_vk_hash[:16]} already voted on {transition_key!r}"
                )

            votes.append(vote)
            tally = self._tally_unlocked(transition_key)

        # Sync to on-chain governance contract (non-fatal)
        if self._on_chain_client is not None:
            try:
                self._on_chain_client.cast_vote_on_chain(
                    transition_key=transition_key.encode()
                    if isinstance(transition_key, str)
                    else transition_key,
                    voter_vk_hash=vote.voter_vk_hash.encode()
                    if isinstance(vote.voter_vk_hash, str)
                    else vote.voter_vk_hash,
                    sequence=int(vote.timestamp),
                    valid_until=int(vote.timestamp) + 3600,
                )
            except Exception:
                logger.warning("On-chain vote sync failed (non-fatal)", exc_info=True)

        return tally

    def has_supermajority(self, transition_key: str) -> bool:
        """Check if >=required_ratio of operators have voted."""
        with self._lock:
            tally = self._tally_unlocked(transition_key)
            return tally["has_supermajority"]

    def execute_if_ready(
        self,
        transition_key: str,
        governance_transition,
        metrics,
    ) -> Optional[bool]:
        """If supermajority reached AND metrics pass, execute the transition.

        Returns True if transition executed, False if metrics fail after
        supermajority reached, or None if supermajority not yet reached.
        """
        if not self.has_supermajority(transition_key):
            return None

        # Parse from/to from transition_key (format: "bootstrap->growth")
        parts = transition_key.split("->")
        if len(parts) != 2:
            raise ValueError(f"Invalid transition_key format: {transition_key!r}")
        from_phase, to_phase = parts

        can, unmet = governance_transition.can_transition(from_phase, to_phase, metrics)
        if not can:
            return False

        return governance_transition.execute_transition(from_phase, to_phase, metrics)

    def get_tally(self, transition_key: str) -> dict:
        """Return current vote count and threshold."""
        with self._lock:
            return self._tally_unlocked(transition_key)

    def _tally_unlocked(self, transition_key: str) -> dict:
        """Compute tally (caller must hold lock)."""
        votes = self._votes.get(transition_key, [])
        total_operators = len(self._operators)
        vote_count = len(votes)
        required = math.ceil(total_operators * self._required_ratio)
        return {
            "transition_key": transition_key,
            "votes": vote_count,
            "total_operators": total_operators,
            "required": required,
            "has_supermajority": vote_count >= required and total_operators > 0,
        }

    @property
    def operator_count(self) -> int:
        with self._lock:
            return len(self._operators)
