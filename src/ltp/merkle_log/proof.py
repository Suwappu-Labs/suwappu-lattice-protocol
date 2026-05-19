"""
Inclusion proof for the Merkle log.

An InclusionProof lets a verifier confirm that a specific record exists at a
given position in the log, without holding any other records.  It contains
only the audit path (O(log N) sibling hashes) needed to reconstruct the root.

Verification algorithm:
  1. Compute leaf_hash = H(0x00 || data)  — RFC 6962 domain-separated leaf
  2. Walk the audit_path from leaf level to root, applying _verify_inclusion()
  3. Compare the reconstructed root against the claimed_root (from a verified STH)
  4. If they match, the record is proven to be in the log

The verifier must independently obtain a trusted root (e.g., from a verified STH
published by a log operator).  The proof itself is not self-authenticating —
it proves membership relative to a root, not that the root is honest.
"""

from __future__ import annotations

import hmac as _hmac
from dataclasses import dataclass, field

from .tree import _leaf_hash, _verify_inclusion

__all__ = ["InclusionProof"]


@dataclass
class InclusionProof:
    """
    A O(log N) proof that a record is included in the Merkle log.

    Attributes:
        leaf_index:  Position of the record in the log (0-based).
        tree_size:   Number of leaves in the tree when the proof was generated.
        audit_path:  Sibling hashes from leaf level to root (len ≤ ⌈log₂(tree_size)⌉).
        root_hash:   The Merkle root this proof is relative to.
    """

    leaf_index: int
    tree_size: int
    audit_path: list[bytes] = field(default_factory=list)
    root_hash: bytes = b""

    def verify(self, data: bytes, claimed_root: bytes) -> bool:
        """
        Verify that `data` is the record at `leaf_index` in a log whose root
        is `claimed_root`.

        Returns True only if:
          - claimed_root matches this proof's root_hash (proof is for this root)
          - reconstructing the root from data + audit_path yields claimed_root

        A False return means either the data is wrong, the proof is for a
        different root, or the audit path has been tampered with.
        """
        # The proof must have been issued for the same root we're checking
        if not _hmac.compare_digest(self.root_hash, claimed_root):
            return False

        computed = _verify_inclusion(
            self.leaf_index,
            self.tree_size,
            _leaf_hash(data),
            self.audit_path,
        )
        return _hmac.compare_digest(computed, claimed_root)

    def to_portable(self, tree_type: "TreeType", data: bytes) -> "PortableMerkleProof":
        """Convert to a self-contained PortableMerkleProof.

        Args:
            tree_type: Which tree this belongs to (commitment_log, shard_tree)
            data:      The raw leaf data (needed to compute leaf_hash)
        """
        from .portable_proof import PortableMerkleProof

        return PortableMerkleProof.from_inclusion_proof(self, tree_type, data)

    @property
    def path_length(self) -> int:
        """Number of hashes in the audit path (≤ ⌈log₂(tree_size)⌉)."""
        return len(self.audit_path)
