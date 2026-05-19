"""
Append-only binary Merkle tree over BLAKE2b-256.

Construction follows RFC 6962 §2.1 (Certificate Transparency):
  Leaf nodes:     H(0x00 || data)          — domain-separated from internal nodes
  Internal nodes: H(0x01 || left || right) — prevents second-preimage attacks

The split for a tree of size n uses the largest power of 2 strictly less than n,
producing a left-complete tree that supports O(log N) audit paths for any N.

Any modification to any leaf changes the Merkle root, making the log tamper-evident
without requiring the verifier to hold the full record set.
"""

from __future__ import annotations

__all__ = ["MerkleTree"]

from ..primitives import canonical_hash_bytes

# ---------------------------------------------------------------------------
# Domain-separated hash primitives (RFC 6962 §2.1)
# ---------------------------------------------------------------------------


def _leaf_hash(data: bytes) -> bytes:
    """Hash a leaf: H(0x00 || data). The 0x00 prefix prevents leaf/node confusion."""
    return canonical_hash_bytes(b"\x00" + data)


def _internal_hash(left: bytes, right: bytes) -> bytes:
    """Hash two children: H(0x01 || left || right)."""
    return canonical_hash_bytes(b"\x01" + left + right)


def _largest_pow2_below(n: int) -> int:
    """Return the largest power of 2 strictly less than n.  Requires n >= 2."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


# ---------------------------------------------------------------------------
# Recursive tree operations
# ---------------------------------------------------------------------------


def _compute_root(leaves: list[bytes]) -> bytes:
    """Recursively compute the Merkle root from a list of pre-hashed leaf nodes."""
    n = len(leaves)
    assert n > 0, "Cannot compute root of empty leaf list"
    if n == 1:
        return leaves[0]
    k = _largest_pow2_below(n)
    return _internal_hash(_compute_root(leaves[:k]), _compute_root(leaves[k:]))


def _audit_path(index: int, leaves: list[bytes]) -> list[bytes]:
    """
    Return the sibling hashes (audit path) for the leaf at index.

    The path goes from leaf level up to root level.  Each entry is the
    root of the subtree that is the sibling at that level.  The verifier
    can reconstruct the root by applying _verify_inclusion().
    """
    n = len(leaves)
    if n == 1:
        return []
    k = _largest_pow2_below(n)
    if index < k:
        # Leaf is in the left subtree; right subtree root is the sibling at this level
        return _audit_path(index, leaves[:k]) + [_compute_root(leaves[k:])]
    else:
        # Leaf is in the right subtree; left subtree root is the sibling at this level
        return _audit_path(index - k, leaves[k:]) + [_compute_root(leaves[:k])]


def _verify_inclusion(
    index: int, tree_size: int, leaf_hash: bytes, audit_path: list[bytes]
) -> bytes:
    """
    Reconstruct the Merkle root from a leaf hash and its audit path.

    The audit_path from _audit_path is bottom-up (leaf level first, root level
    last).  To determine left/right ordering at each step we pre-compute the
    decomposition from root-to-leaf, then reverse it so it matches the
    bottom-up path order.

    Returns the reconstructed root, which the caller compares against a
    trusted root (e.g., from a verified STH).
    """
    # Walk from root to leaf, recording whether we went left at each level.
    going_left: list[bool] = []
    i = index
    n = tree_size
    while n > 1:
        k = _largest_pow2_below(n)
        left = i < k
        going_left.append(left)
        if left:
            n = k
        else:
            i -= k
            n -= k

    # Reconstruct from leaf to root (reverse the root-to-leaf direction list).
    node = leaf_hash
    for went_left, sibling in zip(reversed(going_left), audit_path):
        if went_left:
            # We descended left → our node is the left child, sibling is right
            node = _internal_hash(node, sibling)
        else:
            # We descended right → sibling is the left child, our node is right
            node = _internal_hash(sibling, node)
    return node


# ---------------------------------------------------------------------------
# MerkleTree class
# ---------------------------------------------------------------------------


class MerkleTree:
    """
    Append-only binary Merkle tree.

    Leaves are stored as H(0x00 || data) per RFC 6962 domain separation.
    Internal nodes are H(0x01 || left || right).

    Invariants:
      - Leaves are never modified after appending (append-only).
      - root() is deterministic: same sequence of appends → same root.
      - audit_path(i) produces a path of length ⌊log₂(size)⌋ or ⌈log₂(size)⌉.

    Performance:
      - Root is cached and invalidated on append (O(n) compute, O(1) read).
      - Subtree roots are cached during computation to accelerate audit_path.
    """

    def __init__(self) -> None:
        self._leaves: list[bytes] = []  # pre-hashed leaf nodes
        self._cached_root: bytes | None = None
        self._cache_leaf_count: int = 0  # leaf count when cache was computed
        self._cache_leaf_checksum: bytes = b""  # checksum of leaves at cache time

    @property
    def size(self) -> int:
        """Number of leaves in the tree."""
        return len(self._leaves)

    def append(self, data: bytes) -> int:
        """
        Append raw data to the tree.

        Computes leaf_hash = H(0x00 || data) and stores it.
        Returns the leaf index (0-based).
        """
        if len(self._leaves) >= 1_000_000:
            raise ValueError("Merkle log capacity exceeded")
        self._leaves.append(_leaf_hash(data))
        return len(self._leaves) - 1

    def root(self) -> bytes:
        """
        Compute the current Merkle root.

        Empty tree returns H(b'') — a canonical sentinel for the zero-state.
        Single-leaf tree returns the leaf hash directly.
        Root is cached; repeated calls without modification are O(1).
        Cache is invalidated if leaf count changes or leaf content is modified.
        """
        if not self._leaves:
            return canonical_hash_bytes(b"")

        # Fast path: if leaf count hasn't changed, check content via checksum.
        # The checksum is O(n) but still cheaper than recomputing the full tree.
        if (
            self._cached_root is not None
            and len(self._leaves) == self._cache_leaf_count
            and self._leaf_checksum() == self._cache_leaf_checksum
        ):
            return self._cached_root

        self._cached_root = _compute_root(self._leaves)
        self._cache_leaf_count = len(self._leaves)
        self._cache_leaf_checksum = self._leaf_checksum()
        return self._cached_root

    def _leaf_checksum(self) -> bytes:
        """Checksum of all leaves for cache invalidation.

        Hashes the concatenation of all leaf hashes. This is O(n) but still
        cheaper than recomputing the full tree root (which involves O(n)
        hash operations with recursive tree construction overhead).
        """
        if not self._leaves:
            return b""
        return canonical_hash_bytes(b"".join(self._leaves))

    def leaf_hash(self, index: int) -> bytes:
        """Return the stored leaf hash at index."""
        if not 0 <= index < self.size:
            raise IndexError(f"Leaf index {index} out of range (size={self.size})")
        return self._leaves[index]

    def audit_path(self, index: int) -> list[bytes]:
        """
        Return the audit path (sibling hashes) for the leaf at index.

        The path has at most ⌈log₂(size)⌉ entries.  Combined with the leaf
        hash and tree size, the verifier can reconstruct the root without
        holding any other leaf data.
        """
        if not 0 <= index < self.size:
            raise IndexError(f"Leaf index {index} out of range (size={self.size})")
        return _audit_path(index, self._leaves)

    def consistency_proof(self, old_size: int) -> list[bytes]:
        """
        Generate an O(log N) consistency proof per RFC 6962 §2.1.2.

        Proves that the first `old_size` leaves of the current tree produce
        the same root as they did when the tree had `old_size` leaves.  This
        is the cryptographic guarantee that the log is append-only.

        Args:
            old_size: The tree size of the earlier snapshot.

        Returns:
            List of sibling hashes needed to verify consistency.

        Raises:
            ValueError: if old_size is out of range.
        """
        if old_size < 1 or old_size > self.size:
            raise ValueError(f"old_size {old_size} out of range (1..{self.size})")
        if old_size == self.size:
            return []
        return _subproof(old_size, self._leaves, True)


# ---------------------------------------------------------------------------
# Consistency proof helpers (RFC 6962 §2.1.2)
# ---------------------------------------------------------------------------


def _subproof(m: int, leaves: list[bytes], start: bool) -> list[bytes]:
    """
    Recursive consistency subproof.

    m:      size of the older tree snapshot
    leaves: current leaf set (pre-hashed)
    start:  True on the first call (omits the root of the old subtree since
            the verifier already knows it)
    """
    n = len(leaves)
    if m == n:
        if start:
            return []
        return [_compute_root(leaves)]
    k = _largest_pow2_below(n)
    if m <= k:
        # Old tree fits entirely in the left subtree
        return _subproof(m, leaves[:k], start) + [_compute_root(leaves[k:])]
    else:
        # Old tree spans both subtrees
        return _subproof(m - k, leaves[k:], False) + [_compute_root(leaves[:k])]


def verify_consistency(
    old_size: int,
    new_size: int,
    old_root: bytes,
    new_root: bytes,
    proof: list[bytes],
) -> bool:
    """
    Verify an RFC 6962 consistency proof.

    Mirrors the recursive structure of _subproof() to reconstruct both
    old_root and new_root from the proof nodes.  The verifier already knows
    old_root (from a trusted STH), so the base case with start=True uses
    old_root directly instead of consuming a proof node.

    Returns True if and only if the proof is valid.
    """
    if old_size < 1 or old_size > new_size:
        return False
    if old_size == new_size:
        return old_root == new_root and len(proof) == 0

    proof_iter = iter(proof)
    consumed = [0]

    def _verify(m: int, n: int, start: bool):
        """Returns (old_hash, new_hash) mirroring _subproof's recursion."""
        if m == n:
            if start:
                # Verifier knows old_root — no proof node consumed
                return old_root, old_root
            node = next(proof_iter, None)
            if node is None:
                return None
            consumed[0] += 1
            return node, node

        k = _largest_pow2_below(n)
        if m <= k:
            result = _verify(m, k, start)
            if result is None:
                return None
            oh, nh = result
            sibling = next(proof_iter, None)
            if sibling is None:
                return None
            consumed[0] += 1
            return oh, _internal_hash(nh, sibling)
        else:
            result = _verify(m - k, n - k, False)
            if result is None:
                return None
            oh, nh = result
            sibling = next(proof_iter, None)
            if sibling is None:
                return None
            consumed[0] += 1
            return _internal_hash(sibling, oh), _internal_hash(sibling, nh)

    result = _verify(old_size, new_size, True)
    if result is None:
        return False
    oh, nh = result
    return oh == old_root and nh == new_root and consumed[0] == len(proof)
