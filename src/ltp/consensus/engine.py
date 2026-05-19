"""LocalMysticetiEngine — in-process multi-validator simulation (Spec D1a §3)."""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Iterator

from ..execution.types import OrderedBatch
from .faults import FaultConfig, FaultType, PartitionConfig
from .message_bus import MessageBus
from .protocol import MysticetiProtocol
from .types import Block, Certificate, CommitDecision


def to_ordered_batch(decision: CommitDecision, epoch: int) -> OrderedBatch:
    """Convert a CommitDecision to an OrderedBatch for the execution pipeline."""
    transactions: list[bytes] = []
    for block in decision.committed_blocks:
        transactions.extend(block.payload)
    return OrderedBatch(
        round=decision.round,
        epoch=epoch,
        transactions=transactions,
        leader_authority=decision.leader_certificate.block.author,
        timestamp_ms=decision.leader_certificate.block.timestamp_ms,
        consensus_type="dag",
    )


class LocalMysticetiEngine:
    """In-process Mysticeti simulation with n validators.

    Supports synchronous mode (advance_round/run_rounds) for deterministic
    testing, and async mode (start/stop/stream_commits) for production-like
    behavior.
    """

    def __init__(
        self,
        num_validators: int,
        fault_tolerance: int | None = None,
        round_timeout_ms: int = 1000,
    ) -> None:
        self._n = num_validators
        self._f = fault_tolerance if fault_tolerance is not None else (num_validators - 1) // 3
        self._quorum = 2 * self._f + 1
        self._round_timeout_ms = round_timeout_ms
        self._current_round = -1  # next advance_round will go to 0

        self._validators = [
            MysticetiProtocol(i, num_validators, self._f) for i in range(num_validators)
        ]
        self._bus = MessageBus(num_validators)
        self._mempool: deque[bytes] = deque()
        self._fault_configs: dict[int, FaultConfig] = {}

        # Async mode state
        self._running = False
        self._commit_queue: deque[CommitDecision] = deque()
        self._thread: threading.Thread | None = None

    @property
    def validators(self) -> list[MysticetiProtocol]:
        return self._validators

    def get_dag_store(self, validator: int):
        return self._validators[validator].dag_store

    def submit_transactions(self, txs: list[bytes]) -> None:
        """Add transactions to the mempool for the next round."""
        self._mempool.extend(txs)

    def inject_fault(self, fault: FaultConfig) -> None:
        """Register a fault configuration for a validator."""
        self._fault_configs[fault.validator] = fault

    def _is_faulty(self, validator: int, round: int, fault_type: FaultType) -> bool:
        """Check if a validator has a specific fault active at this round."""
        cfg = self._fault_configs.get(validator)
        if cfg is None:
            return False
        if cfg.fault_type != fault_type:
            return False
        if round < cfg.start_round:
            return False
        if cfg.end_round is not None and round > cfg.end_round:
            return False
        return True

    def advance_round(self) -> int:
        """Execute one full round synchronously. Returns the round number."""
        self._current_round += 1
        r = self._current_round
        decisions: list[CommitDecision] = []

        # Phase 1: Propose
        blocks: list[Block] = []
        for v_idx in range(self._n):
            if self._is_faulty(v_idx, r, FaultType.CRASH):
                continue

            if self._is_faulty(v_idx, r, FaultType.EQUIVOCATE):
                # Equivocating: propose two different blocks
                b1 = self._validators[v_idx].propose(r, payload=(b"equivocate_a",))
                b2 = Block(
                    author=v_idx,
                    round=r,
                    payload=(b"equivocate_b",),
                    parents=b1.parents,
                    timestamp_ms=b1.timestamp_ms,
                )
                blocks.append(b1)
                blocks.append(b2)
                continue

            # Determine payload — censors always empty, honest drain mempool
            payload: tuple[bytes, ...] = ()
            if self._is_faulty(v_idx, r, FaultType.CENSOR):
                payload = ()
            elif self._mempool:
                payload = tuple(self._mempool)
                self._mempool.clear()

            block = self._validators[v_idx].propose(r, payload)
            blocks.append(block)

        # Phase 2: Broadcast blocks, receive, ack
        acks: list[tuple[bytes, int]] = []
        for block in blocks:
            for v_idx in range(self._n):
                if self._is_faulty(v_idx, r, FaultType.CRASH):
                    continue
                if v_idx == block.author:
                    continue
                if self._is_faulty(block.author, r, FaultType.WITHHOLD):
                    targets = self._fault_configs[block.author].params.get("withhold_targets", [])
                    if v_idx in targets:
                        continue
                # Respect network partition: block author sends to v_idx
                if self._bus._is_partitioned(block.author, v_idx):
                    continue
                ack = self._validators[v_idx].receive_block(block)
                if ack is not None:
                    acks.append((block.digest, ack))

        # After block delivery, drop acks for known equivocators — their blocks
        # must not accumulate enough votes to form certificates.
        # Collect all equivocators detected by any validator so far.
        equivocators_known: set[int] = set()
        for v in self._validators:
            for author in range(self._n):
                if v.is_equivocator(author):
                    equivocators_known.add(author)
        # Build a digest→author mapping from all validators' DAG stores.
        digest_to_author: dict[bytes, int] = {}
        for digest, _signer in acks:
            if digest not in digest_to_author:
                for v in self._validators:
                    blk = v.dag_store.get_block(digest)
                    if blk is not None:
                        digest_to_author[digest] = blk.author
                        break
        acks = [
            (digest, signer)
            for digest, signer in acks
            if digest_to_author.get(digest) not in equivocators_known
        ]

        # Phase 3: Broadcast acks, form certificates
        certs: list[Certificate] = []
        for block_digest, signer in acks:
            for v_idx in range(self._n):
                if self._is_faulty(v_idx, r, FaultType.CRASH):
                    continue
                if self._is_faulty(signer, r, FaultType.DELAY):
                    continue  # delayed acks not delivered this round
                # Respect network partition: signer sends ack to v_idx
                if self._bus._is_partitioned(signer, v_idx):
                    continue
                cert = self._validators[v_idx].receive_ack(block_digest, signer)
                if cert is not None:
                    certs.append(cert)

        # Phase 4: Broadcast certificates, check commit
        seen_certs: set[bytes] = set()
        unique_certs: list[Certificate] = []
        for cert in certs:
            if cert.digest not in seen_certs:
                seen_certs.add(cert.digest)
                unique_certs.append(cert)

        for cert in unique_certs:
            cert_author = cert.block.author
            for v_idx in range(self._n):
                if self._is_faulty(v_idx, r, FaultType.CRASH):
                    continue
                # Respect network partition: cert originates from its block's author
                if self._bus._is_partitioned(cert_author, v_idx):
                    continue
                decision = self._validators[v_idx].receive_certificate(cert)
                if decision is not None and decision.round not in {d.round for d in decisions}:
                    decisions.append(decision)

        # Also explicitly check commit for all uncommitted rounds
        for v_idx in range(self._n):
            if self._is_faulty(v_idx, r, FaultType.CRASH):
                continue
            for check_round in range(r + 1):
                decision = self._validators[v_idx].check_commit(check_round)
                if decision is not None and decision.round not in {d.round for d in decisions}:
                    decisions.append(decision)
                    break  # one commit per check cycle

        decisions.sort(key=lambda d: d.round)
        self._commit_queue.extend(decisions)
        return r

    def run_rounds(self, n: int) -> list[CommitDecision]:
        """Run n rounds, return all commit decisions produced."""
        all_decisions: list[CommitDecision] = []
        for _ in range(n):
            self.advance_round()
        while self._commit_queue:
            all_decisions.append(self._commit_queue.popleft())
        all_decisions.sort(key=lambda d: d.round)
        return all_decisions

    def start(self) -> None:
        """Begin async protocol execution on a background thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._async_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop async execution."""
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

    def _async_loop(self) -> None:
        """Background loop that advances rounds on a timer."""
        interval = self._round_timeout_ms / 1000.0
        while self._running:
            self.advance_round()
            time.sleep(interval)

    def stream_commits(self) -> Iterator[CommitDecision]:
        """Yield committed decisions. Blocks briefly in async mode."""
        while self._running or self._commit_queue:
            if self._commit_queue:
                yield self._commit_queue.popleft()
            elif self._running:
                time.sleep(0.01)
            else:
                break
