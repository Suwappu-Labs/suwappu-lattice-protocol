"""
Portable Merkle proofs for the Lattice Transfer Protocol.

Self-contained proofs that can be verified without access to the full tree.
Designed for cross-chain verification and external auditor consumption.

A PortableMerkleProof contains everything needed for standalone verification:
  - The leaf hash and its position in the tree
  - The root hash and tree size
  - The audit path (sibling hashes) with direction flags
  - Tree type discriminator

Reference: SUWAPPU_PRE_BLOCKCHAIN_ROADMAP.md §2.6
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ..domain import DOMAIN_COMMIT_RECORD
from ..encoding import CanonicalEncoder
from .tree import _leaf_hash, _verify_inclusion

__all__ = ["TreeType", "PortableMerkleProof"]


class TreeType(Enum):
    """Discriminator for the type of Merkle tree this proof belongs to."""

    COMMITMENT_LOG = "commitment_log"
    SHARD_TREE = "shard_tree"


@dataclass
class PortableMerkleProof:
    """A self-contained, portable Merkle inclusion proof.

    Contains all information needed to verify that a leaf exists at a
    specific position in a Merkle tree, without holding any other data.

    Fields:
        version:         Protocol version (uint8, currently 1)
        tree_type:       Which tree this proof is for
        leaf_index:      Position of the leaf (0-based)
        tree_size:       Number of leaves when proof was generated
        leaf_hash:       32B hash of the leaf data
        root_hash:       32B Merkle root
        path:            Sibling hashes from leaf to root
        path_directions: True = left sibling, False = right sibling
    """

    version: int
    tree_type: TreeType
    leaf_index: int
    tree_size: int
    leaf_hash: bytes
    root_hash: bytes
    path: list[bytes] = field(default_factory=list)
    path_directions: list[bool] = field(default_factory=list)

    def verify(self) -> bool:
        """Verify this proof: reconstruct root from leaf_hash + path.

        Returns True if the reconstructed root matches root_hash.
        """
        if len(self.path) != len(self.path_directions):
            return False
        if not self.path and self.tree_size == 1:
            return self.leaf_hash == self.root_hash

        reconstructed = _verify_inclusion(
            self.leaf_index,
            self.tree_size,
            self.leaf_hash,
            self.path,
        )
        return reconstructed == self.root_hash

    def canonical_bytes(self) -> bytes:
        """Deterministic binary encoding for hashing/signing."""
        enc = (
            CanonicalEncoder(DOMAIN_COMMIT_RECORD)
            .uint8(self.version)
            .string(self.tree_type.value)
            .uint64(self.leaf_index)
            .uint64(self.tree_size)
            .raw_bytes(self.leaf_hash)
            .raw_bytes(self.root_hash)
        )
        # Encode path as count + raw hashes
        enc.uint32(len(self.path))
        for sibling in self.path:
            enc.raw_bytes(sibling)
        # Encode directions as packed bits
        enc.uint32(len(self.path_directions))
        for d in self.path_directions:
            enc.uint8(1 if d else 0)
        return enc.finalize()

    def to_compact_bytes(self) -> bytes:
        """Minimal encoding for on-chain verification.

        Omits version/tree_type (known from context) for gas efficiency.
        Format: leaf_index(8) || tree_size(8) || leaf_hash(32) || root_hash(32)
                || path_count(4) || [sibling_hash(32)]... || directions_packed
        """
        import struct

        parts = [
            struct.pack(">Q", self.leaf_index),
            struct.pack(">Q", self.tree_size),
            self.leaf_hash,
            self.root_hash,
            struct.pack(">I", len(self.path)),
        ]
        for sibling in self.path:
            parts.append(sibling)
        # Pack directions as bits (1 byte per 8 directions)
        direction_bytes = bytearray()
        for i in range(0, len(self.path_directions), 8):
            byte_val = 0
            for j in range(8):
                if i + j < len(self.path_directions) and self.path_directions[i + j]:
                    byte_val |= 1 << (7 - j)
            direction_bytes.append(byte_val)
        parts.append(bytes(direction_bytes))
        return b"".join(parts)

    @classmethod
    def from_inclusion_proof(
        cls,
        proof: "InclusionProof",
        tree_type: TreeType,
        data: bytes,
    ) -> "PortableMerkleProof":
        """Convert an InclusionProof to a PortableMerkleProof.

        Args:
            proof:     The InclusionProof from the Merkle log
            tree_type: Which tree this belongs to
            data:      The raw leaf data (needed to compute leaf_hash)
        """
        leaf_h = _leaf_hash(data)

        # Compute path directions by replaying the tree decomposition
        directions = _compute_directions(proof.leaf_index, proof.tree_size)

        return cls(
            version=1,
            tree_type=tree_type,
            leaf_index=proof.leaf_index,
            tree_size=proof.tree_size,
            leaf_hash=leaf_h,
            root_hash=proof.root_hash,
            path=list(proof.audit_path),
            path_directions=directions,
        )


def _compute_directions(index: int, tree_size: int) -> list[bool]:
    """Compute path directions (True=went left) for a given position.

    Mirrors the decomposition in tree._verify_inclusion.
    """
    directions: list[bool] = []
    i = index
    n = tree_size
    while n > 1:
        from .tree import _largest_pow2_below

        k = _largest_pow2_below(n)
        went_left = i < k
        directions.append(went_left)
        if went_left:
            n = k
        else:
            i -= k
            n -= k
    # Directions are root-to-leaf; audit_path is leaf-to-root, so reverse
    return list(reversed(directions))
