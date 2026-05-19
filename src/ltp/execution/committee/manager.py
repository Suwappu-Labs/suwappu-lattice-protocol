"""CommitteeManager — top-level coordinator (Spec C3a §9, C3b §8)."""

from __future__ import annotations

from typing import Optional

from ..writer import WriterRecord, WriterState
from ..writer_recovery import EmergencyState
from ..writer_registry import WriterRegistry
from .dkg.registry import DKGKeyRegistry
from .dkg.types import DKGSessionConfig, DKGState
from .epoch import EpochManager
from .eviction import EvictionHandler
from .formation import CommitteeFormation
from .policy import CommitteePolicy
from .standby import StandbySelector
from .types import CommitteeRoster, EpochRecord

__all__ = ["CommitteeManager"]


class CommitteeManager:
    """Top-level coordinator — one per VM."""

    def __init__(
        self,
        vm_tag: int,
        policy: CommitteePolicy,
        registry: WriterRegistry,
        emergency: EmergencyState,
    ) -> None:
        self._vm_tag = vm_tag
        self._policy = policy
        self._registry = registry
        self._formation = CommitteeFormation(registry)
        self._standby = StandbySelector(policy)
        self._eviction = EvictionHandler(policy, self._standby)
        self._epoch_mgr = EpochManager(vm_tag, policy, self._formation, emergency)
        self._dkg_registry = DKGKeyRegistry(vm_tag)
        self._signing_keys: dict[int, list] = {}

    def on_writer_state_change(
        self,
        writer: WriterRecord,
        old_state: WriterState,
        new_state: WriterState,
    ) -> None:
        """Hook called by WriterRegistry transitions."""
        roster = self._epoch_mgr.roster
        if roster is None:
            return
        self._eviction.handle_state_change(
            roster,
            writer.identity.fingerprint,
            old_state,
            new_state,
            timestamp=0,
        )

    def tick(self, current_round: int, timestamp_ms: int) -> bool:
        """Called every round. Returns True if epoch advanced."""
        advanced = self._epoch_mgr.check_advance(current_round, timestamp_ms)
        if advanced and self._policy.dkg_threshold > 0:
            self._run_dkg_ceremony()
        return advanced

    def _run_dkg_ceremony(self) -> None:
        """Run a synchronous DKG ceremony for the current roster."""
        roster = self._epoch_mgr.roster
        if roster is None:
            return

        participants = [m.writer_fp for m in roster.active_members]
        if len(participants) < self._policy.dkg_threshold:
            return

        from .dkg.session import DKGSession

        cfg = DKGSessionConfig(
            vm_tag=self._vm_tag,
            epoch=self._epoch_mgr.current_epoch,
            threshold=self._policy.dkg_threshold,
            participants=participants,
            timeout_rounds=self._policy.dkg_timeout_rounds,
            start_round=0,
        )

        sessions = [DKGSession(cfg, fp, idx + 1) for idx, fp in enumerate(participants)]

        # Phase 1: begin
        commitments = []
        all_shares: list[dict] = []
        for s in sessions:
            c, shares = s.begin()
            commitments.append(c)
            all_shares.append(shares)

        # Phase 2: distribute commitments
        for s in sessions:
            for c in commitments:
                if c.dealer_fp != s.my_fp:
                    s.receive_commitment(c)
            s.end_commitment_phase()

        # Phase 3: distribute shares
        for i, s in enumerate(sessions):
            fp = participants[i]
            for shares in all_shares:
                if fp in shares:
                    s.receive_share(shares[fp])
            s.end_sharing_phase()

        # Phase 4: finalize — collect results and signing keys
        epoch = self._epoch_mgr.current_epoch
        try:
            signing_keys = []
            for s in sessions:
                result, key = s.finalize()
                signing_keys.append(key)
            # Store the first result (group key is the same for all)
            self._dkg_registry.store(result)
            self._signing_keys[epoch] = signing_keys
        except (ValueError, KeyError):
            pass  # DKG failed — epoch runs without threshold signing

    def sign_as_committee(
        self,
        message: bytes,
        domain: bytes,
    ) -> Optional[bytes]:
        """Produce a threshold BLS signature over a message.

        Returns 96-byte combined signature, or None if no DKG keys exist.
        """
        epoch = self._epoch_mgr.current_epoch
        keys = self._signing_keys.get(epoch)
        if not keys:
            return None

        from .dkg.threshold_signing import combine_partial_signatures, partial_sign

        threshold = self._policy.dkg_threshold
        partials = [partial_sign(k, message, domain) for k in keys[:threshold]]
        return combine_partial_signatures(partials, threshold)

    def verify_committee_signature(
        self,
        message: bytes,
        signature: bytes,
        domain: bytes,
        epoch: Optional[int] = None,
    ) -> bool:
        """Verify a threshold BLS signature against the committee's group key."""
        if epoch is None:
            epoch = self._epoch_mgr.current_epoch
        if not self._dkg_registry.has_epoch(epoch):
            return False

        from .dkg.threshold_signing import threshold_verify

        group_pk = self._dkg_registry.group_pk(epoch)
        return threshold_verify(group_pk, message, signature, domain)

    @property
    def dkg_registry(self) -> DKGKeyRegistry:
        return self._dkg_registry

    def has_dkg_result(self, epoch: int) -> bool:
        return self._dkg_registry.has_epoch(epoch)

    @property
    def roster(self) -> Optional[CommitteeRoster]:
        return self._epoch_mgr.roster

    @property
    def epoch(self) -> int:
        return self._epoch_mgr.current_epoch

    @property
    def is_halted(self) -> bool:
        return self._eviction.is_halted

    def is_member(self, writer_fp: bytes) -> bool:
        roster = self._epoch_mgr.roster
        if roster is None:
            return False
        return any(m.writer_fp == writer_fp for m in roster.active_members)

    def history(self) -> list[EpochRecord]:
        return self._epoch_mgr.history
