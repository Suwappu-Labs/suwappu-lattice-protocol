"""MysticetiAdapter — real ConsensusAdapter implementation (Spec D1b §6)."""

from __future__ import annotations

import hashlib
from typing import Iterator, TYPE_CHECKING

from .events import ConsensusEvent, ConsensusEventType
from .validator_set import ValidatorSet
from .bls_certificates import BLSCertificateManager, SignedCertificate, DOMAIN_CONSENSUS_ACK
from .backend import LocalConsensusBackend
from .committee_sync import CommitteeSync
from .types import CommitDecision
from .engine import to_ordered_batch
from .faults import FaultConfig, FaultType

if TYPE_CHECKING:
    from ..execution.committee.manager import CommitteeManager
    from ..execution.committee.dkg.threshold_signing import ThresholdSigningKey

from ..execution.types import OrderedBatch
from ..execution.committee.dkg.threshold_signing import (
    DOMAIN_ATTESTATION,
    combine_partial_signatures,
)

__all__ = ["MysticetiAdapter"]


class MysticetiAdapter:
    """Implements ConsensusAdapter — connects Mysticeti engine to execution pipeline.

    Orchestrates ValidatorSet, BLSCertificateManager, LocalConsensusBackend,
    and CommitteeSync.
    """

    def __init__(
        self,
        committee_manager: CommitteeManager,
        round_timeout_ms: int = 1000,
    ) -> None:
        self._committee_manager = committee_manager
        self._round_timeout_ms = round_timeout_ms
        self._committee_sync = CommitteeSync(committee_manager)
        self._bls_manager = BLSCertificateManager()
        self._backend: LocalConsensusBackend | None = None
        self._validator_set: ValidatorSet | None = None
        self._signing_keys: list[ThresholdSigningKey] | None = None
        self._events: list[ConsensusEvent] = []
        self._running = False
        self._current_epoch = committee_manager.epoch

    def start(self) -> None:
        """Build validator set from roster, create backend, init BLS manager."""
        roster = self._committee_manager.roster
        if roster is None:
            raise RuntimeError("No roster available — cannot start adapter")

        self._validator_set = ValidatorSet.from_roster(roster)
        self._committee_sync.set_validator_set(self._validator_set)
        n = self._validator_set.size

        self._backend = LocalConsensusBackend(
            n, round_timeout_ms=self._round_timeout_ms,
        )

        epoch = self._committee_manager.epoch
        self._current_epoch = epoch
        if self._committee_manager.has_dkg_result(epoch):
            keys = self._committee_sync.get_signing_keys(epoch)
            if keys:
                self._signing_keys = keys
                self._bls_manager.update_keys(keys[0].group_pk)

        self._running = True

    def stop(self) -> None:
        """Stop the backend and clear running state."""
        if self._backend is not None:
            self._backend.stop()
        self._running = False

    def stream_batches(self) -> Iterator[OrderedBatch]:
        """Pull commits from backend, add BLS signatures, yield OrderedBatch."""
        if self._backend is None:
            return
        for decision in self._backend.stream_commits():
            yield self._process_decision(decision)

    def submit_transaction(self, tx_bytes: bytes) -> bytes:
        """Forward transaction to backend, return SHA3-256 hash."""
        if not self._running or self._backend is None:
            raise RuntimeError("Adapter not started")
        self._backend.submit_transactions([tx_bytes])
        return hashlib.sha3_256(tx_bytes).digest()

    def current_round(self) -> int:
        """Return the current consensus round."""
        if self._backend is None:
            return -1
        return self._backend.current_round()

    def consensus_type(self) -> str:
        return "mysticeti-dag"

    def drive_rounds(self, n: int) -> list[OrderedBatch]:
        """Run n rounds synchronously. Returns ordered batches."""
        if self._backend is None:
            raise RuntimeError("Adapter not started")
        decisions = self._backend.run_rounds(n)
        return [self._process_decision(d) for d in decisions]

    def tick(
        self,
        round: int,
        timestamp_ms: int,
    ) -> list[ConsensusEvent]:
        """Drive CommitteeSync, handle epoch/eviction events."""
        events = self._committee_sync.on_tick(round, timestamp_ms)

        for event in events:
            self._events.append(event)

            if event.event_type == ConsensusEventType.EPOCH_TRANSITION:
                self._handle_epoch_transition(event)

            elif event.event_type == ConsensusEventType.VALIDATOR_EVICTED:
                self._handle_eviction(event)

        return events

    def events(self) -> list[ConsensusEvent]:
        """Return event history."""
        return list(self._events)

    def _handle_epoch_transition(self, event: ConsensusEvent) -> None:
        """Rebuild backend for new epoch."""
        new_epoch = event.payload["new_epoch"]
        self._current_epoch = new_epoch

        self._validator_set = self._committee_sync.current_validator_set
        if self._validator_set is None:
            return

        n = self._validator_set.size
        if self._backend is not None:
            self._backend.rebuild(n)

        # Update BLS keys
        if self._committee_sync.has_signing_keys(new_epoch):
            keys = self._committee_sync.get_signing_keys(new_epoch)
            if keys:
                self._signing_keys = keys
                self._bls_manager.update_keys(keys[0].group_pk)
        else:
            self._signing_keys = None

        # Emit ENGINE_REBUILT event
        rebuilt_event = ConsensusEvent(
            event_type=ConsensusEventType.ENGINE_REBUILT,
            epoch=new_epoch,
            round=event.round,
            timestamp_ms=event.timestamp_ms,
            payload={
                "epoch": new_epoch,
                "validator_count": n,
                "quorum_threshold": self._validator_set.quorum_threshold,
            },
        )
        self._events.append(rebuilt_event)

    def _handle_eviction(self, event: ConsensusEvent) -> None:
        """Inject CRASH fault for evicted validator."""
        if self._backend is None:
            return
        idx = event.payload["validator_index"]
        fault = FaultConfig(
            validator=idx,
            fault_type=FaultType.CRASH,
            start_round=0,
        )
        self._backend.inject_fault(fault)

    def _process_decision(self, decision: CommitDecision) -> OrderedBatch:
        """Convert CommitDecision to OrderedBatch with optional BLS signing."""
        batch = to_ordered_batch(decision, self._current_epoch)

        if self._signing_keys and self._validator_set:
            self._sign_decision(decision, batch)

        return batch

    def _sign_decision(
        self,
        decision: CommitDecision,
        batch: OrderedBatch,
    ) -> None:
        """Add BLS signatures to the decision's certificate and attest the batch."""
        cert = decision.leader_certificate
        keys = self._signing_keys
        vs = self._validator_set
        if not keys or not vs:
            return

        # Produce partial ack sigs from each signer in the certificate
        partials = []
        for signer_idx in sorted(cert.signers):
            if signer_idx < len(keys):
                partial = self._bls_manager.sign_ack(keys[signer_idx], cert.digest)
                partials.append(partial)

        # Aggregate into signed certificate (if enough partials)
        if len(partials) >= vs.quorum_threshold:
            agg_sig = self._bls_manager.aggregate_ack_signatures(
                partials, cert.digest, vs,
            )
            SignedCertificate(
                certificate=cert,
                aggregated_signature=agg_sig,
                signer_keys=frozenset(
                    vs.bls_pk_for(i) for i in cert.signers if i < vs.size
                ),
            )

        # Attest the batch
        batch_bytes = self._serialize_batch(batch)
        threshold = vs.quorum_threshold
        batch_partials = []
        for k in keys[:threshold]:
            bp = self._bls_manager.sign_committed_batch(k, batch_bytes)
            batch_partials.append(bp)

        if len(batch_partials) >= threshold:
            combined_sig = combine_partial_signatures(batch_partials, threshold)
            batch_digest = hashlib.sha3_256(batch_bytes).digest()

            attest_event = ConsensusEvent(
                event_type=ConsensusEventType.COMMIT_ATTESTED,
                epoch=self._current_epoch,
                round=batch.round,
                timestamp_ms=batch.timestamp_ms,
                payload={
                    "round": batch.round,
                    "batch_digest": batch_digest,
                    "signature": combined_sig,
                },
            )
            self._events.append(attest_event)

    @staticmethod
    def _serialize_batch(batch: OrderedBatch) -> bytes:
        """Deterministic serialization of OrderedBatch for signing."""
        h = hashlib.sha3_256()
        h.update(batch.round.to_bytes(8, "big"))
        h.update(batch.epoch.to_bytes(8, "big"))
        h.update(len(batch.transactions).to_bytes(4, "big"))
        for tx in batch.transactions:
            h.update(len(tx).to_bytes(4, "big"))
            h.update(tx)
        return h.digest()
