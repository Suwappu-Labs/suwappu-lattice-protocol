"""
SHA3-256 Merkle tree for STARK proof commitments.

Domain-separated hashing following the project's canonical lane convention:
  - Leaf:  SHA3-256(DOMAIN + "stark-leaf" + leaf_data)
  - Node:  SHA3-256(DOMAIN + "stark-node" + left_hash + right_hash)

Power-of-2 leaf count (padded with empty leaves if needed).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

_DOMAIN = b"GSX-LTP:zk-stark:v1\x00"
_LEAF_TAG = _DOMAIN + b"stark-leaf"
_NODE_TAG = _DOMAIN + b"stark-node"
_EMPTY_LEAF = b"\x00" * 32


def _hash_leaf(data: bytes) -> bytes:
    return hashlib.sha3_256(_LEAF_TAG + data).digest()


def _hash_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha3_256(_NODE_TAG + left + right).digest()


@dataclass(frozen=True)
class MerkleProof:
    """Merkle authentication path for a single leaf."""

    index: int
    leaf_data: bytes
    siblings: tuple[bytes, ...]  # from leaf level to root

    def path_length(self) -> int:
        return len(self.siblings)


class StarkMerkleTree:
    """
    Complete binary Merkle tree built from a list of leaves.

    Pads to next power of 2 with empty leaves.
    """

    def __init__(self, leaves: list[bytes]) -> None:
        if not leaves:
            raise ValueError("Cannot build Merkle tree from empty leaf list")

        # Pad to power of 2
        n = 1
        while n < len(leaves):
            n *= 2
        self._n = n
        self._leaf_count = len(leaves)

        # Hash leaves
        hashed = [_hash_leaf(leaf) for leaf in leaves]
        hashed.extend([_hash_leaf(_EMPTY_LEAF)] * (n - len(leaves)))

        # Store raw leaf data for proof opening
        self._raw_leaves = list(leaves) + [_EMPTY_LEAF] * (n - len(leaves))

        # Build tree bottom-up (nodes[1] = root, nodes[n..2n-1] = leaves)
        self._nodes: list[bytes] = [b""] * (2 * n)
        for i in range(n):
            self._nodes[n + i] = hashed[i]
        for i in range(n - 1, 0, -1):
            self._nodes[i] = _hash_node(self._nodes[2 * i], self._nodes[2 * i + 1])

    def root(self) -> bytes:
        """Return the 32-byte Merkle root."""
        return self._nodes[1]

    def open(self, index: int) -> MerkleProof:
        """Generate a Merkle proof for the leaf at the given index."""
        if index < 0 or index >= self._n:
            raise IndexError(f"Index {index} out of range [0, {self._n})")

        siblings = []
        pos = self._n + index
        while pos > 1:
            # Sibling is the other child of parent
            sibling = pos ^ 1
            siblings.append(self._nodes[sibling])
            pos >>= 1

        return MerkleProof(
            index=index,
            leaf_data=self._raw_leaves[index],
            siblings=tuple(siblings),
        )

    @staticmethod
    def verify(root: bytes, proof: MerkleProof, n: int) -> bool:
        """
        Verify a Merkle proof against a root.

        Args:
            root: Expected Merkle root.
            proof: The proof to verify.
            n: Total leaf count (power of 2).

        Returns:
            True if the proof is valid.
        """
        current = _hash_leaf(proof.leaf_data)
        idx = proof.index

        for sibling in proof.siblings:
            if idx & 1 == 0:
                current = _hash_node(current, sibling)
            else:
                current = _hash_node(sibling, current)
            idx >>= 1

        return current == root
