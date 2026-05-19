"""
Auditor Rotation — deterministic round-robin auditor selection from operator pool.

For each (epoch, target_node), selects which operator performs the audit.
Selection is deterministic from H(epoch || target_node_id || seed), ensuring
reproducibility and preventing gaming.

The rotation guarantees:
  1. Every node is audited every epoch (by exactly one operator)
  2. Auditor assignment rotates across epochs (no fixed pairings)
  3. An operator never audits itself
  4. Same seed + epoch + node → same auditor (reproducible)

Reference: ETP_UNIFIED_NODE_DEPLOYMENT_PLAN.md — Audit Protocol
"""

from __future__ import annotations

import struct
from collections import defaultdict

from ..dual_lane.hashing import internal_hash_bytes

__all__ = ["AuditorRotation"]


class AuditorRotation:
    """Deterministic round-robin auditor selection from operator pool.

    Uses hash-based selection: for each (epoch, target_node), computes
    H(seed || epoch || target_node_id) and maps to an operator index.
    This is the same approach used in VDF audit scheduling
    (commitment.py _vdf_audit_schedule).
    """

    def __init__(self, operators: list[str], seed: bytes = b"") -> None:
        if not operators:
            raise ValueError("operators list must not be empty")
        self._operators = sorted(operators)  # Sorted for determinism
        self._seed = seed

    def select_auditor(self, epoch: int, target_node_id: str) -> str:
        """Return the operator_id that should audit target_node in this epoch.

        If the selected operator IS the target node, advances to the next
        operator in the rotation to prevent self-audit.
        """
        h = internal_hash_bytes(self._seed + struct.pack(">Q", epoch) + target_node_id.encode())
        idx = int.from_bytes(h[:8], "big") % len(self._operators)
        selected = self._operators[idx]

        # Prevent self-audit: if selected == target, advance to next
        if selected == target_node_id:
            idx = (idx + 1) % len(self._operators)
            selected = self._operators[idx]

        return selected

    def audit_assignments(
        self,
        epoch: int,
        all_nodes: list[str],
    ) -> dict[str, list[str]]:
        """Return {auditor_id: [target_node_ids]} for an epoch.

        Every node in all_nodes is assigned exactly one auditor.
        """
        assignments: dict[str, list[str]] = defaultdict(list)
        for node_id in all_nodes:
            auditor = self.select_auditor(epoch, node_id)
            assignments[auditor].append(node_id)
        return dict(assignments)

    @property
    def operators(self) -> list[str]:
        return list(self._operators)
