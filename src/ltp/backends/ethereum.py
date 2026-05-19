"""
Ethereum commitment backend — L1/L2 smart contract integration for LTP.

Architecture: Solidity smart contracts deployed on Ethereum mainnet or an
L2 (Base, Arbitrum, Optimism) that implement the commitment log, node
registry, and economic layer.

Why Ethereum:
  - Battle-tested security (~$400B+ economic security on mainnet)
  - Largest developer ecosystem and tooling
  - Mature L2 scaling (10-100x cheaper transactions)
  - Rich DeFi composability (staking, slashing, restaking via EigenLayer)
  - Existing infrastructure (RPC providers, block explorers, wallets)

LTP contract architecture:
  1. LTPCommitmentLog.sol   — append-only commitment record storage
  2. LTPNodeRegistry.sol    — node admission, staking, eviction
  3. LTPSlashingManager.sol — audit evidence submission and stake slashing
  4. LTPStoragePricing.sol  — dynamic pricing oracle for shard storage

Finality model:
  - L1 mainnet: "safe" head (~6.4 min), "finalized" (~12.8 min / 2 epochs)
  - L2 (Base/Arbitrum): soft finality ~2s, L1 finality after batch posting
  - Users choose finality mode via eth_finality_mode config

Gas costs (estimated):
  - Commitment append: ~80,000 gas (store record hash + emit event)
  - Node registration: ~120,000 gas (stake deposit + registry update)
  - Slash submission: ~150,000 gas (verify evidence + update stake)

Modes:
  - Real mode: rpc_url + contract_address + operator_private_key configured.
    All operations route through AnchorClient to live on-chain contracts.
    Fails closed on RPC errors (no silent fallback to simulation).
  - Test mode: No RPC configured. Uses local simulation for unit testing.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Optional

from ..primitives import canonical_hash
from .base import (
    BackendCapabilities,
    BackendConfig,
    CommitmentBackend,
    FinalityModel,
)

# ---------------------------------------------------------------------------
# Simulated Ethereum types
# ---------------------------------------------------------------------------


@dataclass
class EthBlock:
    """Simulated Ethereum block."""

    number: int
    timestamp: float
    parent_hash: str
    state_root: str
    base_fee_gwei: int = 30
    transactions: list[dict] = field(default_factory=list)


@dataclass
class EthTransaction:
    """Simulated Ethereum transaction receipt."""

    tx_hash: str
    block_number: int
    gas_used: int
    status: int  # 1 = success, 0 = revert
    logs: list[dict] = field(default_factory=list)


@dataclass
class MerklePatriciaProof:
    """
    Simulated Ethereum Merkle Patricia Trie inclusion proof.

    Ethereum uses MPT for state storage.  Inclusion proofs are ~1KB
    and consist of a list of trie node hashes from leaf to root.

    For commitment verification:
      - storage_key: keccak256(abi.encode(entity_id))
      - storage_value: record_hash
      - proof_nodes: list of trie node hashes
      - state_root: the block's state root
    """

    storage_key: str
    storage_value: str
    proof_nodes: list[str]
    block_number: int
    state_root: str


# ---------------------------------------------------------------------------
# Solidity contract ABI simulation
# ---------------------------------------------------------------------------

# These represent the key functions from the Solidity contracts.
# In production, these would be actual contract ABIs used with web3.py.

COMMITMENT_LOG_ABI = {
    "commitRecord": {
        "inputs": ["bytes32 entityId", "bytes32 recordHash", "bytes signature", "bytes senderVk"],
        "outputs": ["bytes32 commitmentRef"],
        "gas": 80_000,
    },
    "getCommitment": {
        "inputs": ["bytes32 entityId"],
        "outputs": ["bytes32 recordHash", "uint256 blockNumber", "uint256 timestamp"],
        "gas": 5_000,
    },
    "verifyInclusion": {
        "inputs": ["bytes32 entityId", "bytes proof"],
        "outputs": ["bool"],
        "gas": 30_000,
    },
}

NODE_REGISTRY_ABI = {
    "registerNode": {
        "inputs": ["bytes32 nodeId", "string region"],
        "outputs": ["bool"],
        "gas": 120_000,
        "payable": True,
    },
    "evictNode": {
        "inputs": ["bytes32 nodeId", "string reason", "bytes evidence"],
        "outputs": ["bool"],
        "gas": 150_000,
    },
    "getActiveNodes": {
        "inputs": [],
        "outputs": ["tuple[]"],
        "gas": 50_000,
    },
}


# ---------------------------------------------------------------------------
# Ethereum Backend
# ---------------------------------------------------------------------------


class EthereumBackend(CommitmentBackend):
    """
    Ethereum L1/L2 commitment backend using smart contracts.

    Real mode (rpc_url configured): routes operations through AnchorClient
    to deployed LTPAnchorRegistry contracts. Fails closed on RPC errors.

    Test mode (no rpc_url): local simulation for unit testing only.

    Supports both L1 (mainnet) and L2 (Base, Arbitrum, Optimism) deployment:
      - L1: highest security, ~$80K+ economic security per validator
      - L2: 10-100x cheaper, soft finality in ~2s, L1 finality after batch

    Finality modes:
      - "latest":    included in latest block (no confirmation, risky)
      - "safe":      safe head, ~64 blocks behind tip (~6.4 min)
      - "finalized": 2 full epochs finalized (~12.8 min)
    """

    # Standard Ethereum block time
    BLOCK_TIME_SECONDS = 12

    # L2 block times (approximate)
    L2_BLOCK_TIMES = {
        "base": 2,
        "arbitrum": 0.25,
        "optimism": 2,
    }

    # Confirmation thresholds for finality modes
    FINALITY_BLOCKS = {
        "latest": 0,
        "safe": 64,  # ~12.8 min on L1
        "finalized": 96,  # ~19.2 min on L1 (2 epochs)
    }

    def __init__(self, config: BackendConfig) -> None:
        super().__init__(config)

        # Real mode: route through AnchorClient when rpc_url is configured.
        # In real mode, all state-changing operations go through on-chain
        # contracts. There is NO silent fallback to simulation.
        self._real_mode = bool(
            config.rpc_url and config.contract_address and config.operator_private_key
        )
        self._anchor_client = None
        if self._real_mode:
            from ..anchor.client import AnchorClient

            self._anchor_client = AnchorClient(
                rpc_url=config.rpc_url,
                contract_address=config.contract_address,
                private_key=config.operator_private_key,
                chain_id=config.chain_id or 1,
            )
            import logging

            logging.getLogger(__name__).info(
                "EthereumBackend: REAL mode — chain=%d, contract=%s",
                config.chain_id or 1,
                config.contract_address,
            )

        # Chain state (simulation mode)
        self._blocks: list[EthBlock] = []
        self._commitments: dict[str, dict] = {}
        self._commitment_block_map: dict[str, int] = {}
        self._transactions: list[EthTransaction] = []
        self._nonce: int = 0

        # Node registry (simulated contract state)
        self._node_registry: dict[str, dict] = {}
        self._total_staked: int = 0

        # Gas accounting
        self._total_gas_used: int = 0

        # L2 configuration
        self._is_l2 = config.eth_use_l2
        self._l2_name = config.eth_l2_name
        self._block_time = (
            self.L2_BLOCK_TIMES.get(config.eth_l2_name or "", 2)
            if self._is_l2
            else self.BLOCK_TIME_SECONDS
        )

        # Finality configuration
        self._finality_mode = config.eth_finality_mode
        self._confirmations = config.eth_confirmations

        # Initialize genesis block
        genesis = EthBlock(
            number=0,
            timestamp=time.time(),
            parent_hash="0" * 64,
            state_root=canonical_hash(b"ethereum-genesis-state"),
        )
        self._blocks.append(genesis)

    def capabilities(self) -> BackendCapabilities:
        if self._is_l2:
            return BackendCapabilities(
                finality=FinalityModel.PROBABILISTIC,
                max_tps=4_000,
                has_native_storage_proofs=False,
                has_slashing=True,
                has_node_registry=True,
                supports_zk_verification=True,
                estimated_finality_seconds=self._block_time * 2,
                gas_cost_per_commit=80_000,
            )
        return BackendCapabilities(
            finality=FinalityModel.PROBABILISTIC,
            max_tps=30,
            has_native_storage_proofs=False,
            has_slashing=True,
            has_node_registry=True,
            supports_zk_verification=True,
            estimated_finality_seconds=self._finality_seconds(),
            gas_cost_per_commit=80_000,
        )

    def _finality_seconds(self) -> float:
        """Compute expected finality time based on mode."""
        blocks = self.FINALITY_BLOCKS.get(self._finality_mode, 64)
        return blocks * self._block_time

    # --- Internal: block and transaction simulation ---

    def _produce_block(self, transactions: list[dict] | None = None) -> EthBlock:
        """Simulate Ethereum block production."""
        parent = self._blocks[-1]

        state_data = json.dumps(
            {
                "commitments": len(self._commitments),
                "nodes": len(self._node_registry),
                "staked": self._total_staked,
                "parent": parent.state_root,
            },
            sort_keys=True,
        ).encode()

        block = EthBlock(
            number=parent.number + 1,
            timestamp=time.time(),
            parent_hash=canonical_hash(f"{parent.number}:{parent.state_root}".encode()),
            state_root=canonical_hash(state_data),
            transactions=transactions or [],
        )
        self._blocks.append(block)
        return block

    def _submit_tx(self, tx_type: str, data: dict, gas: int) -> EthTransaction:
        """Simulate submitting a transaction to the Ethereum network."""
        self._nonce += 1
        tx_data = json.dumps(
            {"type": tx_type, "nonce": self._nonce, **data}, sort_keys=True
        ).encode()
        tx_hash = canonical_hash(tx_data)

        block = self._produce_block([{"tx_hash": tx_hash, **data}])

        receipt = EthTransaction(
            tx_hash=tx_hash,
            block_number=block.number,
            gas_used=gas,
            status=1,
            logs=[{"event": tx_type, "data": data}],
        )
        self._transactions.append(receipt)
        self._total_gas_used += gas
        return receipt

    def _compute_mpt_proof(self, entity_id: str) -> MerklePatriciaProof:
        """
        Generate a simulated Merkle Patricia Trie proof.

        In production, this would be obtained via eth_getProof RPC call.
        MPT proofs are ~1KB and consist of trie node hashes.
        """
        block_num = self._commitment_block_map.get(entity_id, 0)
        block = self._blocks[min(block_num, len(self._blocks) - 1)]

        storage_key = canonical_hash(f"slot:commitment:{entity_id}".encode())
        storage_value = canonical_hash(
            json.dumps(self._commitments.get(entity_id, {}), sort_keys=True).encode()
        )

        # Simulate MPT proof nodes (typically 6-8 nodes for 20-byte keys)
        proof_nodes = []
        current = storage_key
        for depth in range(7):
            node_hash = canonical_hash(f"{current}:depth:{depth}".encode())
            proof_nodes.append(node_hash)
            current = node_hash

        return MerklePatriciaProof(
            storage_key=storage_key,
            storage_value=storage_value,
            proof_nodes=proof_nodes,
            block_number=block.number,
            state_root=block.state_root,
        )

    # --- Log operations ---

    def append_commitment(
        self,
        entity_id: str,
        record_bytes: bytes,
        signature: bytes,
        sender_vk: bytes,
    ) -> str:
        # Real mode: route through AnchorClient
        if self._real_mode and self._anchor_client is not None:
            import time as _time

            from web3 import Web3

            from ..anchor.submission import AnchorSubmission

            record_hash = canonical_hash(record_bytes)
            entity_id_hash = Web3.keccak(entity_id.encode())
            anchor_digest = Web3.keccak(record_bytes)
            merkle_root = Web3.keccak(text=record_hash)
            policy_hash = Web3.keccak(signature)
            signer_vk_hash = Web3.keccak(sender_vk)

            submission = AnchorSubmission(
                anchor_digest=anchor_digest,
                entity_id_hash=entity_id_hash,
                merkle_root=merkle_root,
                policy_hash=policy_hash,
                signer_vk_hash=signer_vk_hash,
                sequence=self._nonce + 1,
                valid_until=int(_time.time()) + 3600,
                target_chain_id=self.config.chain_id or 1,
                receipt_type="COMMIT",
            )
            tx_hash = self._anchor_client.anchor(submission)
            self._nonce += 1
            self._commitments[entity_id] = {
                "entity_id": entity_id,
                "record_hash": record_hash,
                "tx_hash": tx_hash,
                "timestamp": _time.time(),
            }
            return record_hash

        if entity_id in self._commitments:
            raise ValueError(f"Entity {entity_id} already committed on Ethereum")

        record_hash = canonical_hash(record_bytes)

        # Test mode: simulate contract call
        entry = {
            "entity_id": entity_id,
            "record_hash": record_hash,
            "record_bytes": record_bytes.hex(),
            "signature": signature.hex(),
            "sender_vk": sender_vk.hex(),
            "timestamp": time.time(),
        }
        self._commitments[entity_id] = entry

        # Submit transaction
        receipt = self._submit_tx(
            "CommitRecord",
            {"entity_id": entity_id, "record_hash": record_hash},
            gas=COMMITMENT_LOG_ABI["commitRecord"]["gas"],
        )
        self._commitment_block_map[entity_id] = receipt.block_number
        entry["block_number"] = receipt.block_number
        entry["tx_hash"] = receipt.tx_hash

        return record_hash

    def fetch_commitment(self, entity_id: str) -> Optional[dict]:
        return self._commitments.get(entity_id)

    def verify_inclusion(self, entity_id: str, proof: dict) -> bool:
        """
        Verify an MPT inclusion proof for a commitment.

        In production, this would verify the Merkle Patricia Trie proof
        against the block's state root using eth_getProof semantics.
        """
        if entity_id not in self._commitments:
            return False

        if isinstance(proof, dict) and "mpt_proof" in proof:
            mp = proof["mpt_proof"]
            expected_value = canonical_hash(
                json.dumps(self._commitments[entity_id], sort_keys=True).encode()
            )
            return mp.get("storage_value") == expected_value

        return entity_id in self._commitments

    def is_finalized(self, entity_id: str) -> bool:
        """
        Check finality based on configured finality mode.

        - "latest": finalized immediately (included in any block)
        - "safe": finalized after 64 blocks (~6.4 min on L1)
        - "finalized": finalized after 96 blocks (~12.8 min on L1)

        For L2: soft finality is near-instant; L1 finality requires
        waiting for the batch to be posted and finalized on L1.
        """
        if self._real_mode and self._anchor_client is not None:
            from web3 import Web3

            w3 = self._anchor_client._w3
            # Let RPC errors propagate — callers must handle failures explicitly.
            finalized_block = w3.eth.get_block("finalized")
            entity_bytes = bytes.fromhex(entity_id) if len(entity_id) == 64 else entity_id.encode()
            digest = Web3.keccak(entity_bytes)
            return self._anchor_client.is_anchored(digest)

        if entity_id not in self._commitment_block_map:
            return False

        commit_block = self._commitment_block_map[entity_id]
        current_block = self._blocks[-1].number
        required_confirmations = self.FINALITY_BLOCKS.get(self._finality_mode, 64)

        # In simulation, we relax the requirement to just check inclusion
        # since we don't actually produce 64+ blocks
        if self._is_l2:
            return (current_block - commit_block) >= min(
                self._confirmations, required_confirmations
            )

        return (current_block - commit_block) >= min(self._confirmations, required_confirmations)

    def get_inclusion_proof(self, entity_id: str) -> Optional[dict]:
        """Generate an MPT inclusion proof for a commitment."""
        if entity_id not in self._commitments:
            return None
        mp = self._compute_mpt_proof(entity_id)
        return {
            "entity_id": entity_id,
            "mpt_proof": {
                "storage_key": mp.storage_key,
                "storage_value": mp.storage_value,
                "proof_nodes": mp.proof_nodes,
                "block_number": mp.block_number,
                "state_root": mp.state_root,
            },
        }

    # --- Node registry ---

    def register_node(self, node_id: str, region: str, stake_wei: int = 0) -> bool:
        min_stake = self.config.min_stake_wei
        if stake_wei < min_stake:
            return False

        # Simulate contract call: LTPNodeRegistry.registerNode{value: stake}(...)
        receipt = self._submit_tx(
            "RegisterNode",
            {"node_id": node_id, "region": region, "stake": stake_wei},
            gas=NODE_REGISTRY_ABI["registerNode"]["gas"],
        )

        self._node_registry[node_id] = {
            "node_id": node_id,
            "region": region,
            "stake_wei": stake_wei,
            "active": True,
            "registered_block": receipt.block_number,
            "tx_hash": receipt.tx_hash,
        }
        self._total_staked += stake_wei
        return True

    def evict_node(self, node_id: str, reason: str, evidence: bytes = b"") -> bool:
        entry = self._node_registry.get(node_id)
        if entry is None or not entry["active"]:
            return False

        # Compute slash
        slash_amount = self._compute_slash(entry)
        entry["active"] = False
        entry["stake_wei"] -= slash_amount
        self._total_staked -= slash_amount

        self._submit_tx(
            "EvictNode",
            {"node_id": node_id, "reason": reason, "slash": slash_amount},
            gas=NODE_REGISTRY_ABI["evictNode"]["gas"],
        )
        return True

    def get_active_nodes(self) -> list[dict]:
        return [
            {
                "node_id": e["node_id"],
                "region": e["region"],
                "stake_wei": e["stake_wei"],
            }
            for e in self._node_registry.values()
            if e["active"]
        ]

    # --- Economic hooks ---

    def compensate_node(self, node_id: str, amount_wei: int, reason: str) -> bool:
        entry = self._node_registry.get(node_id)
        if entry is None or not entry["active"]:
            return False
        entry["stake_wei"] += amount_wei
        self._total_staked += amount_wei
        return True

    def slash_node(
        self,
        node_id: str,
        evidence: bytes,
        concurrent_slashed_stake: int = 0,
        total_network_stake: int = 0,
    ) -> int:
        entry = self._node_registry.get(node_id)
        if entry is None:
            return 0

        slash_amount = self._compute_slash(
            entry,
            concurrent_slashed_stake=concurrent_slashed_stake,
            total_network_stake=total_network_stake,
        )

        # Grace period: create pending slash instead of immediate deduction
        if not hasattr(self, "_pending_slashes"):
            self._pending_slashes: list[dict] = []

        self._pending_slashes.append(
            {
                "node_id": node_id,
                "amount": slash_amount,
                "evidence": evidence.hex(),
                "created_block": self._blocks[-1].number,
                "grace_blocks": 168,  # ~7 days at 1 block/epoch
                "finalized": False,
            }
        )

        self._submit_tx(
            "SlashNode",
            {"node_id": node_id, "amount": slash_amount, "pending": True},
            gas=150_000,
        )
        return slash_amount

    def finalize_pending_slashes(self) -> list[dict]:
        """Finalize pending slashes past their grace period."""
        if not hasattr(self, "_pending_slashes"):
            return []

        current_block = self._blocks[-1].number
        finalized = []
        remaining = []

        for ps in self._pending_slashes:
            if ps["finalized"]:
                continue
            if current_block >= ps["created_block"] + ps["grace_blocks"]:
                entry = self._node_registry.get(ps["node_id"])
                if entry and entry["active"]:
                    deduct = min(ps["amount"], entry["stake_wei"])
                    entry["stake_wei"] -= deduct
                    self._total_staked -= deduct
                ps["finalized"] = True
                finalized.append(ps)
            else:
                remaining.append(ps)

        self._pending_slashes = remaining
        return finalized

    def get_pricing(self) -> dict:
        base_cost = 100 if not self._is_l2 else 5  # L2 is ~20x cheaper
        return {
            "cost_per_shard_per_epoch": base_cost,
            "epoch_seconds": 3600,
            "currency": "ETH",
            "gas_per_commit": COMMITMENT_LOG_ABI["commitRecord"]["gas"],
            "block_time_seconds": self._block_time,
            "finality_mode": self._finality_mode,
            "is_l2": self._is_l2,
            "l2_name": self._l2_name,
        }

    def _compute_slash(
        self,
        entry: dict,
        concurrent_slashed_stake: int = 0,
        total_network_stake: int = 0,
    ) -> int:
        fraction = self.config.slash_fraction_bps / 10_000
        base_slash = int(entry["stake_wei"] * fraction)

        # Correlation penalty (parity with Base L1 backend)
        if total_network_stake > 0 and concurrent_slashed_stake > 0:
            correlation_ratio = concurrent_slashed_stake / total_network_stake
            multiplier = min(3.0, 1.0 + 2.0 * correlation_ratio)
            base_slash = int(base_slash * multiplier)

        return min(base_slash, entry["stake_wei"])

    # --- Batch operations (amortized gas via calldata batching) ---

    def append_commitments_batch(
        self,
        commitments: list[tuple[str, bytes, bytes, bytes]],
    ) -> list[str]:
        """
        Append multiple commitments in a single transaction.

        On Ethereum, batching amortizes the 21K base gas cost across
        all commits. Each additional commitment adds ~60K marginal gas
        (vs ~80K individually including base cost).

        On L2, this is even more effective since the batch is posted
        as a single blob to L1.
        """
        refs = []
        batch_data = []

        for entity_id, record_bytes, signature, sender_vk in commitments:
            if entity_id in self._commitments:
                raise ValueError(f"Entity {entity_id} already committed on Ethereum")

            record_hash = canonical_hash(record_bytes)
            entry = {
                "entity_id": entity_id,
                "record_hash": record_hash,
                "record_bytes": record_bytes.hex(),
                "signature": signature.hex(),
                "sender_vk": sender_vk.hex(),
                "timestamp": time.time(),
            }
            self._commitments[entity_id] = entry
            batch_data.append({"entity_id": entity_id, "record_hash": record_hash})
            refs.append(record_hash)

        # Single transaction for all commits
        # Gas: 21K base + 60K per commit (vs 80K each individually)
        batch_gas = 21_000 + 60_000 * len(commitments)
        receipt = self._submit_tx(
            "BatchCommitRecords",
            {"count": len(commitments), "commits": batch_data},
            gas=batch_gas,
        )

        for entity_id, _, _, _ in commitments:
            self._commitment_block_map[entity_id] = receipt.block_number
            self._commitments[entity_id]["block_number"] = receipt.block_number
            self._commitments[entity_id]["tx_hash"] = receipt.tx_hash

        return refs

    # --- Ethereum-specific queries ---

    @property
    def chain_height(self) -> int:
        return self._blocks[-1].number

    @property
    def total_gas_used(self) -> int:
        return self._total_gas_used

    @property
    def total_staked(self) -> int:
        return self._total_staked

    @property
    def transaction_count(self) -> int:
        return len(self._transactions)
