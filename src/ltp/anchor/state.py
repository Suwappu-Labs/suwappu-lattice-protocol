"""
Entity state machine for on-chain anchoring.

Defines the lifecycle states an entity can be in on-chain, and the
valid transitions between them.

State diagram:
  UNKNOWN → COMMITTED → ANCHORED → MATERIALIZED
                ↓           ↓           ↓
             DISPUTED    DISPUTED    DISPUTED
                ↓           ↓           ↓
             DELETED     DELETED     DELETED

Reference: GSX_PRE_BLOCKCHAIN_ROADMAP.md §2.9
"""

from __future__ import annotations

from enum import IntEnum

__all__ = ["EntityState", "VALID_TRANSITIONS", "validate_transition"]


class EntityState(IntEnum):
    """On-chain entity lifecycle states.

    Integer values are used in Solidity mappings (uint8).
    """

    UNKNOWN = 0
    COMMITTED = 1
    ANCHORED = 2
    MATERIALIZED = 3
    DISPUTED = 4
    DELETED = 5


VALID_TRANSITIONS: frozenset[tuple[EntityState, EntityState]] = frozenset(
    {
        # Happy path
        (EntityState.UNKNOWN, EntityState.COMMITTED),
        (EntityState.COMMITTED, EntityState.ANCHORED),
        (EntityState.ANCHORED, EntityState.MATERIALIZED),
        # Dispute path (from any active state)
        (EntityState.COMMITTED, EntityState.DISPUTED),
        (EntityState.ANCHORED, EntityState.DISPUTED),
        (EntityState.MATERIALIZED, EntityState.DISPUTED),
        # Deletion path (from any state except UNKNOWN)
        (EntityState.COMMITTED, EntityState.DELETED),
        (EntityState.ANCHORED, EntityState.DELETED),
        (EntityState.MATERIALIZED, EntityState.DELETED),
        (EntityState.DISPUTED, EntityState.DELETED),
    }
)


def validate_transition(
    current: EntityState,
    target: EntityState,
) -> tuple[bool, str]:
    """Check if a state transition is valid.

    Returns: (True, "") if valid, (False, reason) if invalid.
    """
    if current == target:
        return False, f"no-op transition: {current.name} → {target.name}"
    if (current, target) in VALID_TRANSITIONS:
        return True, ""
    return False, f"invalid transition: {current.name} → {target.name}"
