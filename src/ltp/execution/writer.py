"""
Writer data model for the per-VM writer registry (Spec C2 §2–3).

Defines the identity tiers, lifecycle state machine, and record types
used throughout the writer registry subsystem.

State diagram:
  PENDING → PROBATION → ACTIVE
     ↓          ↓         ↓
   REVOKED   SUSPENDED  SUSPENDED
               ↓         ↓
             REVOKED   EXPIRED
                         ↓
                       REVOKED

  SUSPENDED → ACTIVE  (reinstatement)
  EXPIRED   → ACTIVE  (renewal)

Reference: ETP Spec C2 §2 (Writer Identity), §3 (Writer Lifecycle)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from ..primitives import canonical_hash_bytes
from ..bls_keys import BLSIdentity, bls_fingerprint, composite_fingerprint

__all__ = [
    "IdentityTier",
    "WriterState",
    "TRANSACTABLE_STATES",
    "VALID_WRITER_TRANSITIONS",
    "validate_writer_transition",
    "TransitionEntry",
    "WriterIdentity",
    "ApprovalPath",
    "WriterRecord",
]


# ---------------------------------------------------------------------------
# Identity Tier
# ---------------------------------------------------------------------------

class IdentityTier(str, Enum):
    """Cryptographic identity tier for a writer.

    Determines which verification key(s) are active and how the writer
    fingerprint is computed.
    """
    MLDSA     = "mldsa"      # ML-DSA-65 only (post-quantum standalone)
    BLS       = "bls"        # BLS12-381 only (aggregation-optimised)
    COMPOSITE = "composite"  # ML-DSA + BLS (dual-key, highest assurance)


# ---------------------------------------------------------------------------
# Writer Lifecycle State Machine
# ---------------------------------------------------------------------------

class WriterState(str, Enum):
    """Writer account lifecycle states.

    PENDING    — enrolled, awaiting approval
    PROBATION  — approved but under observation (limited tx rights)
    ACTIVE     — fully operational
    SUSPENDED  — temporarily blocked, reinstatement possible
    EXPIRED    — time-limited credential lapsed, renewal possible
    REVOKED    — permanently terminated (terminal state)
    """
    PENDING   = "pending"
    PROBATION = "probation"
    ACTIVE    = "active"
    SUSPENDED = "suspended"
    EXPIRED   = "expired"
    REVOKED   = "revoked"


TRANSACTABLE_STATES: frozenset[WriterState] = frozenset({
    WriterState.ACTIVE,
    WriterState.PROBATION,
})

VALID_WRITER_TRANSITIONS: frozenset[tuple[WriterState, WriterState]] = frozenset({
    # Enrollment path
    (WriterState.PENDING,   WriterState.PROBATION),
    (WriterState.PENDING,   WriterState.ACTIVE),
    (WriterState.PENDING,   WriterState.REVOKED),
    # Probation path
    (WriterState.PROBATION, WriterState.ACTIVE),
    (WriterState.PROBATION, WriterState.SUSPENDED),
    (WriterState.PROBATION, WriterState.REVOKED),
    # Active path
    (WriterState.ACTIVE,    WriterState.SUSPENDED),
    (WriterState.ACTIVE,    WriterState.EXPIRED),
    (WriterState.ACTIVE,    WriterState.REVOKED),
    # Recovery paths
    (WriterState.SUSPENDED, WriterState.ACTIVE),
    (WriterState.SUSPENDED, WriterState.REVOKED),
    (WriterState.EXPIRED,   WriterState.ACTIVE),
    (WriterState.EXPIRED,   WriterState.REVOKED),
})


def validate_writer_transition(
    current: WriterState,
    target: WriterState,
) -> tuple[bool, str]:
    """Check if a writer state transition is valid.

    Follows the same pattern as ``src/ltp/anchor/state.py:validate_transition``.

    Returns:
        (True, "")             if valid
        (False, reason_str)    if invalid (no-op or disallowed)
    """
    if current == target:
        return False, f"no-op transition: {current.name} → {target.name}"
    if (current, target) in VALID_WRITER_TRANSITIONS:
        return True, ""
    return False, f"invalid transition: {current.name} → {target.name}"


# ---------------------------------------------------------------------------
# Transition Audit Entry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TransitionEntry:
    """Immutable record of a single writer state transition.

    Stored in WriterRecord.transition_log for a complete audit trail.
    """
    timestamp:    int            # Timestamp in milliseconds
    from_state:   WriterState    # State before the transition
    to_state:     WriterState    # State after the transition
    actor_fp:     bytes          # 32-byte fingerprint of the authorising actor
    reason:       str            # Human-readable reason
    is_emergency: bool = False   # True when bypass rules were in effect


# ---------------------------------------------------------------------------
# Writer Identity
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class WriterIdentity:
    """Immutable cryptographic identity for a writer.

    Binds one or two public keys to a canonical fingerprint and a tier.
    """
    tier:        IdentityTier
    fingerprint: bytes           # 32-byte canonical identity hash
    mldsa_vk:    Optional[bytes] = None  # ML-DSA verification key (if tier != BLS)
    bls_pk:      Optional[bytes] = None  # BLS12-381 public key (if tier != MLDSA)

    # ------------------------------------------------------------------
    # Factory class methods
    # ------------------------------------------------------------------

    @classmethod
    def from_keypair(cls, kp) -> WriterIdentity:
        """Build a WriterIdentity from a KeyPair.

        Detects COMPOSITE tier when kp.bls_pk is present; falls back to
        MLDSA for pure post-quantum keypairs.

        Args:
            kp: A ``src.ltp.keypair.KeyPair`` instance.

        Returns:
            WriterIdentity with the appropriate tier and fingerprint.
        """
        if kp.bls_pk is not None:
            fp = composite_fingerprint(kp.vk, kp.bls_pk)
            return cls(
                tier=IdentityTier.COMPOSITE,
                fingerprint=fp,
                mldsa_vk=kp.vk,
                bls_pk=kp.bls_pk,
            )
        fp = canonical_hash_bytes(kp.vk)
        return cls(
            tier=IdentityTier.MLDSA,
            fingerprint=fp,
            mldsa_vk=kp.vk,
        )

    @classmethod
    def from_bls_identity(cls, bls_id: BLSIdentity) -> WriterIdentity:
        """Build a WriterIdentity from a standalone BLSIdentity.

        Args:
            bls_id: A ``BLSIdentity`` produced by BLSKeyPair.to_identity()
                    or KeyPair.to_bls_identity().

        Returns:
            WriterIdentity with BLS tier.
        """
        return cls(
            tier=IdentityTier.BLS,
            fingerprint=bls_id.fingerprint,
            bls_pk=bls_id.pk,
        )


# ---------------------------------------------------------------------------
# Approval Path
# ---------------------------------------------------------------------------

class ApprovalPath(str, Enum):
    """How a writer was approved (affects policy and audit).

    ADMIN   — directly approved by a registry admin
    SPONSOR — vouched for by an existing ACTIVE writer
    SELF    — self-service / open enrollment (policy-gated)
    """
    ADMIN   = "admin"
    SPONSOR = "sponsor"
    SELF    = "self"


# ---------------------------------------------------------------------------
# Writer Record
# ---------------------------------------------------------------------------

@dataclass
class WriterRecord:
    """Mutable state record for a registered writer.

    Owned by the WriterRegistry; mutated only through validated transitions.
    """
    identity:           WriterIdentity
    state:              WriterState
    approval_path:      ApprovalPath
    enrolled_at:        float                   # Unix timestamp of enrollment

    # Optional fields set on approval / progression
    approved_at:        Optional[float]         = None
    approved_by:        Optional[bytes]         = None  # 32-byte actor fingerprint
    sponsors:           list[bytes]             = field(default_factory=list)

    # Time-bounded fields
    probation_until:    Optional[int]           = None  # Unix epoch (int seconds)
    expires_at:         Optional[int]           = None  # Unix epoch (int seconds)

    # Suspension / revocation metadata
    suspension_reason:  Optional[str]           = None

    # Immutable audit trail
    transition_log:     list[TransitionEntry]   = field(default_factory=list)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def can_transact(self) -> bool:
        """True when the writer is allowed to submit transactions."""
        return self.state in TRANSACTABLE_STATES
