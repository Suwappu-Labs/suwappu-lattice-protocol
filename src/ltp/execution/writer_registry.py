"""
WriterRegistry — per-VM writer lifecycle state machine (Spec C2 §4).

Manages enrollment, approval, sponsorship, suspension, reinstatement,
revocation, renewal, and expiration of writer accounts.  Pure state
management — no policy logic belongs here.

Reference: ETP Spec C2 §4 (Writer Registry)
"""

from __future__ import annotations

from typing import Optional

from .writer import (
    ApprovalPath,
    TransitionEntry,
    WriterIdentity,
    WriterRecord,
    WriterState,
    TRANSACTABLE_STATES,
    validate_writer_transition,
)
from .writer_config import RegistryConfig

__all__ = ["WriterRegistry"]


class WriterRegistry:
    """Lifecycle registry for writer accounts on a single VM.

    All mutations go through :py:meth:`_transition` which validates the
    edge against ``VALID_WRITER_TRANSITIONS``, appends an immutable
    :class:`TransitionEntry` to the record's audit log, and updates the
    mutable state field.

    Args:
        config: Optional :class:`RegistryConfig`; defaults created if omitted.
    """

    def __init__(self, config: Optional[RegistryConfig] = None) -> None:
        self._config = config or RegistryConfig()
        self._records: dict[bytes, WriterRecord] = {}
        self._revoked: set[bytes] = set()

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def config(self) -> RegistryConfig:
        """Read-only access to the registry configuration."""
        return self._config

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enroll(self, identity: WriterIdentity, timestamp: int) -> WriterRecord:
        """Create a PENDING record for a new writer.

        Args:
            identity:  Cryptographic identity of the writer.
            timestamp: Enrollment time in milliseconds.

        Returns:
            The newly created :class:`WriterRecord`.

        Raises:
            ValueError: If the fingerprint is already registered or was
                        previously revoked.
        """
        fp = identity.fingerprint

        if fp in self._revoked:
            raise ValueError(
                f"Writer {fp.hex()[:16]}… was previously revoked and cannot re-enroll."
            )
        if fp in self._records:
            raise ValueError(
                f"Writer {fp.hex()[:16]}… is already registered (state="
                f"{self._records[fp].state.value})."
            )

        record = WriterRecord(
            identity=identity,
            state=WriterState.PENDING,
            approval_path=ApprovalPath.SPONSOR,  # default; overridden on approve
            enrolled_at=timestamp,
        )
        self._records[fp] = record
        return record

    def lookup(self, fingerprint: bytes) -> Optional[WriterRecord]:
        """Read-only lookup by fingerprint.

        Args:
            fingerprint: 32-byte identity hash.

        Returns:
            The :class:`WriterRecord` if found, else ``None``.
        """
        return self._records.get(fingerprint)

    def approve(
        self,
        fingerprint: bytes,
        admin_fp: bytes,
        timestamp: int,
    ) -> WriterRecord:
        """Admin approval path: PENDING → ACTIVE.

        Sets ``approved_at``, ``approved_by``, and ``approval_path=ADMIN``.

        Args:
            fingerprint: Target writer fingerprint.
            admin_fp:    32-byte fingerprint of the approving admin.
            timestamp:   Approval time in milliseconds.

        Returns:
            The mutated :class:`WriterRecord`.

        Raises:
            KeyError:   If ``fingerprint`` is not registered.
            ValueError: If the writer is not in PENDING state.
        """
        record = self._get_or_raise(fingerprint)
        if record.state != WriterState.PENDING:
            raise ValueError(
                f"approve requires PENDING state; writer is {record.state.value}."
            )

        self._transition(
            fingerprint=fingerprint,
            target=WriterState.ACTIVE,
            actor_fp=admin_fp,
            reason="admin approval",
            timestamp=timestamp,
        )
        record.approved_at = timestamp
        record.approved_by = admin_fp
        record.approval_path = ApprovalPath.ADMIN
        return record

    def sponsor(
        self,
        fingerprint: bytes,
        sponsor_fp: bytes,
        timestamp: int,
    ) -> WriterRecord:
        """Add a sponsor.  If threshold met, transition PENDING → PROBATION.

        Duplicate sponsors are silently ignored.  Only operates on writers in
        PENDING state.

        Args:
            fingerprint: Target writer fingerprint.
            sponsor_fp:  32-byte fingerprint of the sponsoring writer.
            timestamp:   Time of sponsorship in milliseconds.

        Returns:
            The mutated :class:`WriterRecord`.

        Raises:
            KeyError:   If ``fingerprint`` is not registered.
            ValueError: If the writer is not in PENDING state.
        """
        record = self._get_or_raise(fingerprint)
        if record.state != WriterState.PENDING:
            raise ValueError(
                f"sponsor only operates on PENDING writers; writer is {record.state.value}."
            )

        # Sponsor must be an ACTIVE writer (Spec C2 §4.4)
        sponsor_record = self._records.get(sponsor_fp)
        if sponsor_record is None or sponsor_record.state not in TRANSACTABLE_STATES:
            raise ValueError(
                f"Sponsor {sponsor_fp.hex()[:16]}… must be an ACTIVE or PROBATION writer."
            )

        # Duplicate sponsor — no-op
        if sponsor_fp in record.sponsors:
            return record

        record.sponsors.append(sponsor_fp)

        if len(record.sponsors) >= self._config.sponsor_threshold:
            self._transition(
                fingerprint=fingerprint,
                target=WriterState.PROBATION,
                actor_fp=sponsor_fp,
                reason=f"sponsor threshold met ({len(record.sponsors)}/{self._config.sponsor_threshold})",
                timestamp=timestamp,
            )
            record.probation_until = timestamp + self._config.probation_epochs
            record.approval_path = ApprovalPath.SPONSOR

        return record

    def promote(self, fingerprint: bytes, timestamp: int) -> WriterRecord:
        """Graduate from PROBATION → ACTIVE.

        Args:
            fingerprint: Target writer fingerprint.
            timestamp:   Promotion time in milliseconds.

        Returns:
            The mutated :class:`WriterRecord`.

        Raises:
            KeyError:   If ``fingerprint`` is not registered.
            ValueError: If ``validate_writer_transition`` rejects the edge.
        """
        record = self._get_or_raise(fingerprint)
        self._transition(
            fingerprint=fingerprint,
            target=WriterState.ACTIVE,
            actor_fp=record.identity.fingerprint,
            reason="probation completed; promoted to active",
            timestamp=timestamp,
        )
        return record

    def suspend(
        self,
        fingerprint: bytes,
        reason: str,
        actor_fp: bytes,
        timestamp: int,
    ) -> WriterRecord:
        """Temporarily block a writer: ACTIVE/PROBATION → SUSPENDED.

        Args:
            fingerprint: Target writer fingerprint.
            reason:      Human-readable suspension reason.
            actor_fp:    32-byte fingerprint of the actor.
            timestamp:   Suspension time in milliseconds.

        Returns:
            The mutated :class:`WriterRecord`.

        Raises:
            KeyError:   If ``fingerprint`` is not registered.
            ValueError: If the transition is invalid.
        """
        self._transition(
            fingerprint=fingerprint,
            target=WriterState.SUSPENDED,
            actor_fp=actor_fp,
            reason=reason,
            timestamp=timestamp,
        )
        record = self._records[fingerprint]
        record.suspension_reason = reason
        return record

    def reinstate(
        self,
        fingerprint: bytes,
        actor_fp: bytes,
        timestamp: int,
    ) -> WriterRecord:
        """Lift suspension: SUSPENDED → ACTIVE.

        Clears ``suspension_reason``.

        Args:
            fingerprint: Target writer fingerprint.
            actor_fp:    32-byte fingerprint of the actor.
            timestamp:   Reinstatement time in milliseconds.

        Returns:
            The mutated :class:`WriterRecord`.

        Raises:
            KeyError:   If ``fingerprint`` is not registered.
            ValueError: If the transition is invalid.
        """
        self._transition(
            fingerprint=fingerprint,
            target=WriterState.ACTIVE,
            actor_fp=actor_fp,
            reason="suspension lifted; reinstated",
            timestamp=timestamp,
        )
        record = self._records[fingerprint]
        record.suspension_reason = None
        return record

    def revoke(
        self,
        fingerprint: bytes,
        reason: str,
        actor_fp: bytes,
        timestamp: int,
    ) -> WriterRecord:
        """Permanently terminate: any state → REVOKED.

        Adds ``fingerprint`` to the internal ``_revoked`` set so that
        re-enrollment is permanently blocked.

        Args:
            fingerprint: Target writer fingerprint.
            reason:      Human-readable revocation reason.
            actor_fp:    32-byte fingerprint of the actor.
            timestamp:   Revocation time in milliseconds.

        Returns:
            The mutated :class:`WriterRecord`.

        Raises:
            KeyError:   If ``fingerprint`` is not registered.
            ValueError: If the transition is invalid.
        """
        self._transition(
            fingerprint=fingerprint,
            target=WriterState.REVOKED,
            actor_fp=actor_fp,
            reason=reason,
            timestamp=timestamp,
        )
        self._revoked.add(fingerprint)
        return self._records[fingerprint]

    def renew(
        self,
        fingerprint: bytes,
        actor_fp: bytes,
        timestamp: int,
    ) -> WriterRecord:
        """Renew an expired credential: EXPIRED → ACTIVE.

        Args:
            fingerprint: Target writer fingerprint.
            actor_fp:    32-byte fingerprint of the actor.
            timestamp:   Renewal time in milliseconds.

        Returns:
            The mutated :class:`WriterRecord`.

        Raises:
            KeyError:   If ``fingerprint`` is not registered.
            ValueError: If the transition is invalid.
        """
        self._transition(
            fingerprint=fingerprint,
            target=WriterState.ACTIVE,
            actor_fp=actor_fp,
            reason="credential renewed",
            timestamp=timestamp,
        )
        return self._records[fingerprint]

    def check_expirations(self, current_epoch: int) -> list[bytes]:
        """Batch scan and expire credentials whose time has come.

        Transitions every ACTIVE writer whose ``expires_at > 0`` and
        ``current_epoch >= expires_at`` to EXPIRED.

        Args:
            current_epoch: The current epoch counter to compare against.

        Returns:
            List of fingerprints that were newly transitioned to EXPIRED.
        """
        # Collect first, then mutate — safe against future dict-size changes
        to_expire = [
            fp for fp, record in self._records.items()
            if (
                record.state == WriterState.ACTIVE
                and record.expires_at is not None
                and record.expires_at > 0
                and current_epoch >= record.expires_at
            )
        ]
        for fp in to_expire:
            self._transition(
                fingerprint=fp,
                target=WriterState.EXPIRED,
                actor_fp=fp,  # self-actor (system-driven)
                reason=f"credential expired at epoch {self._records[fp].expires_at}",
                timestamp=current_epoch,
            )
        return to_expire

    def active_writers(self) -> list[WriterRecord]:
        """Return all writers in ACTIVE or PROBATION state.

        Returns:
            Unordered list of transactable :class:`WriterRecord` instances.
        """
        return [r for r in self._records.values() if r.state in TRANSACTABLE_STATES]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_or_raise(self, fingerprint: bytes) -> WriterRecord:
        """Retrieve a record by fingerprint or raise KeyError."""
        record = self._records.get(fingerprint)
        if record is None:
            raise KeyError(
                f"No writer registered with fingerprint {fingerprint.hex()[:16]}…"
            )
        return record

    def _transition(
        self,
        fingerprint: bytes,
        target: WriterState,
        actor_fp: bytes,
        reason: str,
        timestamp: int,
        is_emergency: bool = False,
    ) -> None:
        """Validate and apply a state transition, appending to the audit log.

        Args:
            fingerprint:  32-byte identity hash of the writer.
            target:       Desired target state.
            actor_fp:     32-byte fingerprint of the authorising actor.
            reason:       Human-readable description of the transition.
            timestamp:    Time of the transition in milliseconds.
            is_emergency: True when bypass rules are in effect.

        Raises:
            KeyError:   If no record exists for ``fingerprint``.
            ValueError: If ``validate_writer_transition`` rejects the edge.
        """
        record = self._get_or_raise(fingerprint)
        ok, msg = validate_writer_transition(record.state, target)
        if not ok:
            raise ValueError(
                f"Transition rejected for {fingerprint.hex()[:16]}…: {msg}"
            )

        entry = TransitionEntry(
            timestamp=timestamp,
            from_state=record.state,
            to_state=target,
            actor_fp=actor_fp,
            reason=reason,
            is_emergency=is_emergency,
        )
        record.transition_log.append(entry)
        record.state = target
