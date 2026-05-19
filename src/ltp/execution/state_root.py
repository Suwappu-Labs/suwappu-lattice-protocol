"""MultiVMStateRoot — two-level Merkle over VM families."""

from __future__ import annotations

from dataclasses import dataclass

from ..domain import DOMAIN_MULTI_VM_STATE_ROOT
from ..primitives import canonical_hash_bytes
from .model import family_from_tag


def _merkle_root(leaves: list[bytes]) -> bytes:
    """Compute a simple binary Merkle root over a list of 32-byte leaves.

    If the list has odd length, the last leaf is paired with itself.
    Single-leaf trees return the leaf directly.
    """
    if not leaves:
        return b"\x00" * 32
    if len(leaves) == 1:
        return leaves[0]

    # Build tree bottom-up
    current = list(leaves)
    while len(current) > 1:
        next_level = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else current[i]
            next_level.append(canonical_hash_bytes(left + right))
        current = next_level
    return current[0]


@dataclass(frozen=True)
class MultiVMStateRoot:
    """Combined state root over all active VMs, grouped by family.

    Two-level Merkle:
      Level 1: per-VM leaf = SHA3(tag_byte + vm_state_root)
      Level 2: per-family subtree = merkle_root(sorted VM leaves)
      Level 3: root = SHA3(DOMAIN + merkle_root(sorted family subtrees) + round)
    """

    vm_roots: dict[int, bytes]
    batch_round: int

    @property
    def root(self) -> bytes:
        """Canonical multi-VM state root for anchoring."""
        family_subtrees = self._compute_family_subtrees()

        subtree_roots = []
        for family_id in sorted(family_subtrees.keys()):
            subtree_roots.append(family_subtrees[family_id])

        return canonical_hash_bytes(
            DOMAIN_MULTI_VM_STATE_ROOT
            + _merkle_root(subtree_roots)
            + self.batch_round.to_bytes(8, "big")
        )

    def active_families(self) -> list[int]:
        """Return sorted list of active family IDs."""
        families = set()
        for tag in self.vm_roots:
            families.add(family_from_tag(tag))
        return sorted(families)

    def family_subtree_root(self, family_id: int) -> bytes:
        """Return the Merkle root for a single family."""
        subtrees = self._compute_family_subtrees()
        if family_id not in subtrees:
            return b"\x00" * 32
        return subtrees[family_id]

    def _compute_family_subtrees(self) -> dict[int, bytes]:
        """Group VM leaves by family and compute per-family Merkle roots."""
        family_leaves: dict[int, list[bytes]] = {}
        for tag in sorted(self.vm_roots.keys()):
            family_id = family_from_tag(tag)
            leaf = canonical_hash_bytes(tag.to_bytes(1, "big") + self.vm_roots[tag])
            family_leaves.setdefault(family_id, []).append(leaf)

        return {fid: _merkle_root(leaves) for fid, leaves in family_leaves.items()}
