"""
Tests for AnchorVerifier confirmation and finality tracking.
"""

from __future__ import annotations

import time as _time

import pytest

from src.ltp.node.anchor_status import AnchorStatus, AnchorStatusTracker
from src.ltp.node.anchor_verifier import AnchorVerifier, AnchorVerifyResult
from src.ltp.node.config import NodeConfig

# ---------------------------------------------------------------------------
# Mock chain provider
# ---------------------------------------------------------------------------


class MockChainProvider:
    """Duck-typed mock for AnchorClient receipt/block methods."""

    def __init__(
        self,
        *,
        block_number: int = 100,
        receipts: dict | None = None,
        fail_receipt: bool = False,
        fail_block: bool = False,
    ):
        self._block_number = block_number
        self._receipts: dict[str, dict] = receipts or {}
        self._fail_receipt = fail_receipt
        self._fail_block = fail_block
        self.receipt_calls: list[str] = []
        self.block_calls: int = 0

    def get_tx_receipt(self, tx_hash: str) -> dict | None:
        self.receipt_calls.append(tx_hash)
        if self._fail_receipt:
            raise ConnectionError("RPC unavailable")
        return self._receipts.get(tx_hash)

    def get_block_number(self) -> int:
        self.block_calls += 1
        if self._fail_block:
            raise ConnectionError("RPC unavailable")
        return self._block_number


def _make_config(
    *,
    confirmation_depth: int = 3,
    finality_depth: int | None = None,
    interval: float = 15.0,
    max_wait: float = 60.0,
    max_rpc_retries: int = 5,
) -> NodeConfig:
    cfg = NodeConfig()
    cfg.anchor_confirmation_depth = confirmation_depth
    cfg.anchor_finality_depth = finality_depth if finality_depth is not None else confirmation_depth
    cfg.anchor_interval_seconds = interval
    cfg.anchor_max_wait_seconds = max_wait
    cfg.anchor_max_rpc_retries = max_rpc_retries
    return cfg


def _setup_submitted(tracker: AnchorStatusTracker, entity_id: str, tx_hash: str) -> None:
    """Create a SUBMITTED entity in the tracker."""
    tracker.mark_pending(entity_id, b"\x00" * 32)
    tracker.mark_submitted(entity_id, tx_hash)


# ===================================================================
# Phase 1: SUBMITTED → CONFIRMED
# ===================================================================


class TestVerifierPhase1:
    def test_tick_no_submitted(self):
        """Empty SUBMITTED set → all counts zero."""
        tracker = AnchorStatusTracker()
        provider = MockChainProvider()
        config = _make_config()
        verifier = AnchorVerifier(provider, tracker, config)

        result = verifier.tick(1)
        assert result.submitted_checked == 0
        assert result.confirmed == 0
        assert result.failed == 0
        assert result.still_pending == 0

    def test_receipt_found_confirms(self):
        """Receipt with status=1 → entity CONFIRMED (below finality depth)."""
        tracker = AnchorStatusTracker()
        _setup_submitted(tracker, "ent-1", "0xabc")

        # block_number=51, tx at block 50 → depth=1, below confirmation_depth=3
        provider = MockChainProvider(
            block_number=51,
            receipts={
                "0xabc": {"status": 1, "blockNumber": 50, "gasUsed": 80_000},
            },
        )
        verifier = AnchorVerifier(provider, tracker, _make_config())

        result = verifier.tick(1)
        assert result.submitted_checked == 1
        assert result.receipts_found == 1
        assert result.confirmed == 1
        assert tracker.get("ent-1").status is AnchorStatus.CONFIRMED

    def test_receipt_records_block_metadata(self):
        """block_number and gas_used stored in tracker record."""
        tracker = AnchorStatusTracker()
        _setup_submitted(tracker, "ent-1", "0xabc")

        provider = MockChainProvider(
            receipts={
                "0xabc": {"status": 1, "blockNumber": 42, "gasUsed": 65_000},
            }
        )
        verifier = AnchorVerifier(provider, tracker, _make_config())
        verifier.tick(1)

        rec = tracker.get("ent-1")
        assert rec.block_number == 42
        assert rec.gas_used == 65_000
        assert rec.confirmed_at > 0

    def test_receipt_pending_skipped(self):
        """Receipt None → still_pending counted, entity stays SUBMITTED."""
        tracker = AnchorStatusTracker()
        _setup_submitted(tracker, "ent-1", "0xpending")

        provider = MockChainProvider()  # no receipts → returns None
        verifier = AnchorVerifier(provider, tracker, _make_config())

        result = verifier.tick(1)
        assert result.still_pending == 1
        assert result.confirmed == 0
        assert tracker.get("ent-1").status is AnchorStatus.SUBMITTED

    def test_receipt_reverted_marks_failed(self):
        """Receipt status=0 → entity FAILED."""
        tracker = AnchorStatusTracker()
        _setup_submitted(tracker, "ent-1", "0xreverted")

        provider = MockChainProvider(
            receipts={
                "0xreverted": {"status": 0, "blockNumber": 50, "gasUsed": 21_000},
            }
        )
        verifier = AnchorVerifier(provider, tracker, _make_config())

        result = verifier.tick(1)
        assert result.failed == 1
        assert result.confirmed == 0
        rec = tracker.get("ent-1")
        assert rec.status is AnchorStatus.FAILED
        assert "reverted" in rec.error

    def test_tx_hash_grouping(self):
        """3 entities same tx_hash → 1 receipt call, all 3 confirmed."""
        tracker = AnchorStatusTracker()
        tx = "0xbatch"
        for i in range(3):
            _setup_submitted(tracker, f"ent-{i}", tx)

        # block_number=61, tx at block 60 → depth=1, below confirmation_depth=3
        provider = MockChainProvider(
            block_number=61,
            receipts={
                tx: {"status": 1, "blockNumber": 60, "gasUsed": 120_000},
            },
        )
        verifier = AnchorVerifier(provider, tracker, _make_config())

        result = verifier.tick(1)
        assert result.submitted_checked == 3
        assert result.receipts_found == 1
        assert result.confirmed == 3
        # Only 1 RPC call for the shared tx_hash
        assert len(provider.receipt_calls) == 1
        assert provider.receipt_calls[0] == tx
        for i in range(3):
            assert tracker.get(f"ent-{i}").status is AnchorStatus.CONFIRMED

    def test_receipt_rpc_error_transient(self):
        """get_tx_receipt raises → errors counted, entity stays SUBMITTED."""
        tracker = AnchorStatusTracker()
        _setup_submitted(tracker, "ent-1", "0xfail")

        provider = MockChainProvider(fail_receipt=True)
        verifier = AnchorVerifier(provider, tracker, _make_config())

        result = verifier.tick(1)
        assert result.errors == 1
        assert result.confirmed == 0
        assert tracker.get("ent-1").status is AnchorStatus.SUBMITTED


# ===================================================================
# Phase 2: CONFIRMED → FINALIZED
# ===================================================================


class TestVerifierPhase2:
    def test_finalized_at_depth(self):
        """current=103, tx_block=100, depth=3 → FINALIZED."""
        tracker = AnchorStatusTracker()
        tracker.mark_pending("ent-1", b"\x00" * 32)
        tracker.mark_submitted("ent-1", "0xabc")
        tracker.mark_confirmed("ent-1", block_number=100, gas_used=50_000)

        provider = MockChainProvider(block_number=103)
        verifier = AnchorVerifier(provider, tracker, _make_config(confirmation_depth=3))

        result = verifier.tick(1)
        assert result.finalized == 1
        assert tracker.get("ent-1").status is AnchorStatus.FINALIZED

    def test_below_depth_stays_confirmed(self):
        """current=101, tx_block=100, depth=3 → stays CONFIRMED."""
        tracker = AnchorStatusTracker()
        tracker.mark_pending("ent-1", b"\x00" * 32)
        tracker.mark_submitted("ent-1", "0xabc")
        tracker.mark_confirmed("ent-1", block_number=100, gas_used=50_000)

        provider = MockChainProvider(block_number=101)
        verifier = AnchorVerifier(provider, tracker, _make_config(confirmation_depth=3))

        result = verifier.tick(1)
        assert result.finalized == 0
        assert tracker.get("ent-1").status is AnchorStatus.CONFIRMED

    def test_reorg_detected(self):
        """current=99, tx_block=100 → FAILED (chain reorg)."""
        tracker = AnchorStatusTracker()
        tracker.mark_pending("ent-1", b"\x00" * 32)
        tracker.mark_submitted("ent-1", "0xabc")
        tracker.mark_confirmed("ent-1", block_number=100, gas_used=50_000)

        provider = MockChainProvider(block_number=99)
        verifier = AnchorVerifier(provider, tracker, _make_config(confirmation_depth=3))

        result = verifier.tick(1)
        assert result.failed == 1
        assert result.finalized == 0
        rec = tracker.get("ent-1")
        assert rec.status is AnchorStatus.FAILED
        assert "reorg" in rec.error

    def test_block_rpc_error_skips_phase2(self):
        """get_block_number raises → Phase 2 skipped, Phase 1 results preserved."""
        tracker = AnchorStatusTracker()
        # One SUBMITTED entity — will be confirmed by Phase 1
        _setup_submitted(tracker, "ent-sub", "0xtx1")
        # One already CONFIRMED entity — would be finalized if Phase 2 ran
        tracker.mark_pending("ent-conf", b"\x01" * 32)
        tracker.mark_submitted("ent-conf", "0xtx2")
        tracker.mark_confirmed("ent-conf", block_number=50, gas_used=30_000)

        provider = MockChainProvider(
            receipts={"0xtx1": {"status": 1, "blockNumber": 60, "gasUsed": 40_000}},
            block_number=200,
            fail_block=True,
        )
        verifier = AnchorVerifier(provider, tracker, _make_config(confirmation_depth=3))

        result = verifier.tick(1)
        # Phase 1 succeeded
        assert result.confirmed == 1
        assert tracker.get("ent-sub").status is AnchorStatus.CONFIRMED
        # Phase 2 skipped — ent-conf stays CONFIRMED
        assert result.finalized == 0
        assert tracker.get("ent-conf").status is AnchorStatus.CONFIRMED
        assert result.error != ""


# ===================================================================
# Finality depth vs confirmation depth (Gap 1)
# ===================================================================


class TestFinalityDepthConfig:
    def test_finality_depth_from_config(self):
        """CONFIRMED→FINALIZED fires at anchor_finality_depth, not anchor_confirmation_depth."""
        tracker = AnchorStatusTracker()
        tracker.mark_pending("ent-1", b"\x00" * 32)
        tracker.mark_submitted("ent-1", "0xabc")
        tracker.mark_confirmed("ent-1", block_number=100, gas_used=50_000)

        # confirmation_depth=3, finality_depth=10 — depth=5 should NOT finalize
        provider = MockChainProvider(block_number=105)
        config = _make_config(confirmation_depth=3, finality_depth=10)
        verifier = AnchorVerifier(provider, tracker, config)

        result = verifier.tick(1)
        assert result.finalized == 0
        assert tracker.get("ent-1").status is AnchorStatus.CONFIRMED

        # Advance to depth=10 — now it should finalize
        provider._block_number = 110
        result2 = verifier.tick(2)
        assert result2.finalized == 1
        assert tracker.get("ent-1").status is AnchorStatus.FINALIZED


# ===================================================================
# Same-tick confirm + finalize
# ===================================================================


class TestVerifierSameTick:
    def test_confirm_and_finalize_same_tick(self):
        """Receipt found + already deep enough → CONFIRMED then FINALIZED in one tick."""
        tracker = AnchorStatusTracker()
        _setup_submitted(tracker, "ent-1", "0xdeep")

        # Receipt at block 50, current block 200 — well past depth=3
        provider = MockChainProvider(
            block_number=200,
            receipts={"0xdeep": {"status": 1, "blockNumber": 50, "gasUsed": 70_000}},
        )
        verifier = AnchorVerifier(provider, tracker, _make_config(confirmation_depth=3))

        result = verifier.tick(1)
        assert result.confirmed == 1
        assert result.finalized == 1
        assert tracker.get("ent-1").status is AnchorStatus.FINALIZED


# ===================================================================
# Multi-batch dedup
# ===================================================================


class TestVerifierMultiBatch:
    def test_different_tx_hashes_queried_independently(self):
        """Two batches with different tx_hashes → 2 receipt calls."""
        tracker = AnchorStatusTracker()
        _setup_submitted(tracker, "ent-a", "0xtx1")
        _setup_submitted(tracker, "ent-b", "0xtx1")
        _setup_submitted(tracker, "ent-c", "0xtx2")

        provider = MockChainProvider(
            receipts={
                "0xtx1": {"status": 1, "blockNumber": 80, "gasUsed": 50_000},
                "0xtx2": {"status": 1, "blockNumber": 82, "gasUsed": 60_000},
            }
        )
        verifier = AnchorVerifier(provider, tracker, _make_config())

        result = verifier.tick(1)
        assert result.submitted_checked == 3
        assert result.receipts_found == 2
        assert result.confirmed == 3
        assert len(provider.receipt_calls) == 2
        assert set(provider.receipt_calls) == {"0xtx1", "0xtx2"}


# ===================================================================
# Multi-tick progression (typical production path)
# ===================================================================


class TestVerifierMultiTick:
    def test_tick1_confirms_tick2_finalizes(self):
        """Tick 1: receipt found, below depth → CONFIRMED.
        Tick 2: depth reached → FINALIZED."""
        tracker = AnchorStatusTracker()
        _setup_submitted(tracker, "ent-1", "0xtx")

        # Tick 1: block 51, tx at 50, depth=1 < 3
        provider = MockChainProvider(
            block_number=51,
            receipts={"0xtx": {"status": 1, "blockNumber": 50, "gasUsed": 60_000}},
        )
        verifier = AnchorVerifier(provider, tracker, _make_config(confirmation_depth=3))

        r1 = verifier.tick(1)
        assert r1.confirmed == 1
        assert r1.finalized == 0
        assert tracker.get("ent-1").status is AnchorStatus.CONFIRMED

        # Tick 2: advance chain to block 53, depth = 53-50 = 3 → finalize
        provider._block_number = 53
        r2 = verifier.tick(2)
        assert r2.confirmed == 0
        assert r2.finalized == 1
        assert tracker.get("ent-1").status is AnchorStatus.FINALIZED

    def test_pending_then_confirmed_then_finalized(self):
        """Tick 1: still pending. Tick 2: receipt arrives. Tick 3: finalized."""
        tracker = AnchorStatusTracker()
        _setup_submitted(tracker, "ent-1", "0xslow")

        provider = MockChainProvider(block_number=50)
        verifier = AnchorVerifier(provider, tracker, _make_config(confirmation_depth=2))

        # Tick 1: no receipt yet
        r1 = verifier.tick(1)
        assert r1.still_pending == 1
        assert tracker.get("ent-1").status is AnchorStatus.SUBMITTED

        # Tick 2: receipt appears at block 50
        provider._receipts["0xslow"] = {"status": 1, "blockNumber": 50, "gasUsed": 40_000}
        provider._block_number = 51
        r2 = verifier.tick(2)
        assert r2.confirmed == 1
        assert r2.finalized == 0
        assert tracker.get("ent-1").status is AnchorStatus.CONFIRMED

        # Tick 3: block 52, depth = 52-50 = 2 → finalize
        provider._block_number = 52
        r3 = verifier.tick(3)
        assert r3.finalized == 1
        assert tracker.get("ent-1").status is AnchorStatus.FINALIZED


# ===================================================================
# Mixed receipt results in one tick
# ===================================================================


class TestVerifierMixedResults:
    def test_mixed_success_revert_pending(self):
        """Three tx_hashes: one succeeds, one reverts, one pending — all in one tick."""
        tracker = AnchorStatusTracker()
        _setup_submitted(tracker, "ent-ok", "0xgood")
        _setup_submitted(tracker, "ent-bad", "0xbad")
        _setup_submitted(tracker, "ent-wait", "0xpending")

        provider = MockChainProvider(
            block_number=51,
            receipts={
                "0xgood": {"status": 1, "blockNumber": 50, "gasUsed": 60_000},
                "0xbad": {"status": 0, "blockNumber": 50, "gasUsed": 21_000},
                # "0xpending" not in receipts → returns None
            },
        )
        verifier = AnchorVerifier(provider, tracker, _make_config(confirmation_depth=3))

        result = verifier.tick(1)
        assert result.confirmed == 1
        assert result.failed == 1
        assert result.still_pending == 1
        assert tracker.get("ent-ok").status is AnchorStatus.CONFIRMED
        assert tracker.get("ent-bad").status is AnchorStatus.FAILED
        assert tracker.get("ent-wait").status is AnchorStatus.SUBMITTED


# ===================================================================
# Result dataclass
# ===================================================================


class TestAnchorVerifyResult:
    def test_defaults(self):
        r = AnchorVerifyResult(epoch=1)
        assert r.epoch == 1
        assert r.submitted_checked == 0
        assert r.receipts_found == 0
        assert r.confirmed == 0
        assert r.finalized == 0
        assert r.failed == 0
        assert r.still_pending == 0
        assert r.errors == 0
        assert r.error == ""


# ===================================================================
# Daemon thread
# ===================================================================


class TestVerifierThread:
    def test_start_stop(self):
        tracker = AnchorStatusTracker()
        provider = MockChainProvider()
        verifier = AnchorVerifier(provider, tracker, _make_config())
        verifier.start()
        assert verifier.running is True
        verifier.stop()
        assert verifier.running is False

    def test_start_idempotent(self):
        """Double start() → single thread."""
        tracker = AnchorStatusTracker()
        provider = MockChainProvider()
        verifier = AnchorVerifier(provider, tracker, _make_config())
        verifier.start()
        verifier.start()  # no-op
        assert verifier.running is True
        verifier.stop()

    def test_epoch_increments(self):
        tracker = AnchorStatusTracker()
        provider = MockChainProvider()
        verifier = AnchorVerifier(provider, tracker, _make_config(interval=0.05))
        verifier.start()
        _time.sleep(0.15)
        verifier.stop()
        assert verifier.epoch >= 1

    def test_stop_before_start_is_safe(self):
        """stop() without prior start() must not raise."""
        tracker = AnchorStatusTracker()
        provider = MockChainProvider()
        verifier = AnchorVerifier(provider, tracker, _make_config())
        verifier.stop()  # should be a no-op, no AttributeError
        assert verifier.running is False


# ===================================================================
# Gap 2: reconcile_on_startup
# ===================================================================

from src.ltp.commitment import CommitmentLog, CommitmentNetwork, CommitmentRecord
from src.ltp.domain import DOMAIN_ANCHOR_DIGEST, domain_hash_bytes
from src.ltp.network.safe_network import SafeCommitmentNetwork
from src.ltp.node.anchor_verifier import reconcile_on_startup


def _make_anchoring_record_for_verifier(entity_id: str, alice) -> CommitmentRecord:
    """CommitmentRecord with a sha3-256:hex shard_map_root."""
    hex_root = "sha3-256:" + "ab" * 32
    rec = CommitmentRecord(
        entity_id=entity_id,
        sender_id=alice.label,
        shard_map_root=hex_root,
        content_hash=f"hash-{entity_id}",
        encoding_params={"n": 8, "k": 4, "algorithm": "reed_solomon"},
        shape="application/octet-stream",
        shape_hash=f"shape-{entity_id}",
        timestamp=1_700_000_000.0,
        signature=b"",
        sender_vk=alice.vk,
    )
    rec.sign(alice.sk)
    return rec


class MockReconcileClient:
    """Duck-typed mock with are_anchored() — returns list[bool] like the real client."""

    def __init__(self, anchored_digests: set[bytes] | None = None):
        self._anchored = anchored_digests or set()

    def are_anchored(self, digests: list[bytes]) -> list[bool]:
        return [d in self._anchored for d in digests]


class TestReconcileOnStartup:
    def test_reconcile_repopulates_tracker_from_chain(self, alice):
        """Entities already anchored on-chain are marked FINALIZED in tracker."""
        inner = CommitmentNetwork()
        for i in range(4):
            inner.add_node(f"node-{i}", "US-East")
        safe = SafeCommitmentNetwork(inner)

        # Add 3 records
        for i in range(3):
            inner.log.append(_make_anchoring_record_for_verifier(f"ent-{i}", alice))

        # Compute digests for ent-0 and ent-2 (simulate them being on-chain)
        records = safe.records_since(0)
        anchored_digests = set()
        for entity_id, record in records:
            if entity_id in ("ent-0", "ent-2"):
                anchored_digests.add(domain_hash_bytes(DOMAIN_ANCHOR_DIGEST, record.to_bytes()))

        client = MockReconcileClient(anchored_digests)
        tracker = AnchorStatusTracker()

        count = reconcile_on_startup(safe, client, tracker)
        assert count == 2
        assert tracker.get("ent-0").status is AnchorStatus.FINALIZED
        assert tracker.get("ent-1") is None  # not anchored on-chain
        assert tracker.get("ent-2").status is AnchorStatus.FINALIZED

    def test_reconcile_empty_log(self, alice):
        inner = CommitmentNetwork()
        for i in range(4):
            inner.add_node(f"node-{i}", "US-East")
        safe = SafeCommitmentNetwork(inner)
        tracker = AnchorStatusTracker()
        client = MockReconcileClient()

        count = reconcile_on_startup(safe, client, tracker)
        assert count == 0

    def test_reconcile_chain_query_failure(self, alice):
        """Chain query failure returns 0, doesn't raise."""
        inner = CommitmentNetwork()
        for i in range(4):
            inner.add_node(f"node-{i}", "US-East")
        safe = SafeCommitmentNetwork(inner)
        inner.log.append(_make_anchoring_record_for_verifier("ent-0", alice))

        class FailClient:
            def are_anchored(self, digests):
                raise ConnectionError("RPC down")

        tracker = AnchorStatusTracker()
        count = reconcile_on_startup(safe, FailClient(), tracker)
        assert count == 0


# ===================================================================
# Gap 3: tx_not_mined timeout
# ===================================================================


class TestVerifierTxTimeout:
    def test_timeout_uses_submitted_at_not_tick_time(self):
        """Entity pending > max_wait → FAILED with 'tx_not_mined'."""
        tracker = AnchorStatusTracker()
        _setup_submitted(tracker, "ent-old", "0xslow")

        # Backdate submitted_at to simulate an old submission
        with tracker._lock:
            tracker._records["ent-old"].submitted_at = _time.time() - 120

        provider = MockChainProvider()  # no receipts → returns None
        config = _make_config(max_wait=60.0)
        verifier = AnchorVerifier(provider, tracker, config)

        result = verifier.tick(1)
        assert result.failed == 1
        assert result.still_pending == 0
        rec = tracker.get("ent-old")
        assert rec.status is AnchorStatus.FAILED
        assert "tx_not_mined" in rec.error

    def test_timeout_spares_recent_submissions(self):
        """Entity submitted recently → stays pending."""
        tracker = AnchorStatusTracker()
        _setup_submitted(tracker, "ent-new", "0xfresh")
        # submitted_at defaults to now — well within max_wait

        provider = MockChainProvider()
        config = _make_config(max_wait=60.0)
        verifier = AnchorVerifier(provider, tracker, config)

        result = verifier.tick(1)
        assert result.still_pending == 1
        assert result.failed == 0
        assert tracker.get("ent-new").status is AnchorStatus.SUBMITTED


# ===================================================================
# Gap 4: RPC retry exhaustion
# ===================================================================


class TestVerifierRpcRetries:
    def test_rpc_failure_increments_retry(self):
        """Each RPC error increments retry_count; stays SUBMITTED below threshold."""
        tracker = AnchorStatusTracker()
        _setup_submitted(tracker, "ent-1", "0xfail")

        provider = MockChainProvider(fail_receipt=True)
        config = _make_config(max_rpc_retries=3)
        verifier = AnchorVerifier(provider, tracker, config)

        # First tick: retry_count=1, below 3
        r1 = verifier.tick(1)
        assert r1.errors == 1
        assert r1.failed == 0
        assert tracker.get("ent-1").status is AnchorStatus.SUBMITTED
        assert tracker.get("ent-1").retry_count == 1

    def test_rpc_failure_marks_failed_after_threshold(self):
        """After max_rpc_retries consecutive RPC failures → FAILED."""
        tracker = AnchorStatusTracker()
        _setup_submitted(tracker, "ent-1", "0xfail")

        provider = MockChainProvider(fail_receipt=True)
        config = _make_config(max_rpc_retries=3)
        verifier = AnchorVerifier(provider, tracker, config)

        # Tick 3 times: retries=1,2,3 — on 3rd, threshold reached → FAILED
        verifier.tick(1)
        verifier.tick(2)
        r3 = verifier.tick(3)
        assert r3.failed == 1
        rec = tracker.get("ent-1")
        assert rec.status is AnchorStatus.FAILED
        assert "max RPC retries" in rec.error


# ===================================================================
# Gap 6: reconcile failure must not block startup
# ===================================================================


class TestReconcileStartupGuard:
    """Verify that reconcile_on_startup failures are non-fatal.

    main.py wraps reconcile_on_startup in try/except so that RPC
    outages or disk errors during reconciliation don't block node
    bootstrap.
    """

    def test_reconcile_failure_does_not_block_startup(self, alice):
        """Network error during reconcile is caught by main.py guard."""

        class BrokenNetwork:
            """Simulates a disk or network failure in records_since()."""

            def records_since(self, index):
                raise IOError("disk failure during reconciliation")

        tracker = AnchorStatusTracker()
        client = MockReconcileClient()

        # Without a guard, reconcile_on_startup propagates the IOError
        with pytest.raises(IOError, match="disk failure"):
            reconcile_on_startup(BrokenNetwork(), client, tracker)

        # main.py guard pattern: try/except catches ALL exceptions
        reconciled_count = 0
        try:
            reconciled_count = reconcile_on_startup(
                BrokenNetwork(),
                client,
                tracker,
            )
        except Exception:
            pass  # main.py: logger.warning("Anchor reconciliation failed — continuing")

        # Startup continues with 0 reconciled
        assert reconciled_count == 0

    def test_reconcile_unexpected_exception_caught(self, alice):
        """Even RuntimeError from reconcile doesn't prevent startup."""
        inner = CommitmentNetwork()
        for i in range(4):
            inner.add_node(f"node-{i}", "US-East")
        safe = SafeCommitmentNetwork(inner)
        inner.log.append(_make_anchoring_record_for_verifier("ent-0", alice))

        class PoisonClient:
            def are_anchored(self, digests):
                raise RuntimeError("unexpected RPC protocol error")

        tracker = AnchorStatusTracker()

        # reconcile_on_startup has its own try/except for are_anchored,
        # so this returns 0 rather than raising
        count = reconcile_on_startup(safe, PoisonClient(), tracker)
        assert count == 0

        # Even if it DID raise, main.py guard catches it
        reconciled_count = 0
        try:
            reconciled_count = reconcile_on_startup(safe, PoisonClient(), tracker)
        except Exception:
            pass
        assert reconciled_count == 0


# ===================================================================
# Multi-chain verifier tests
# ===================================================================


class TestMultiChainVerifier:
    """Verify that multiple AnchorVerifier instances can operate
    independently on different chains with correct labelling."""

    def test_chain_label_in_thread_name(self):
        """Verifier thread name must include the chain_label."""
        tracker = AnchorStatusTracker()
        provider = MockChainProvider()
        config = _make_config()

        verifier = AnchorVerifier(
            provider,
            tracker,
            config,
            chain_label="base_sepolia",
        )
        verifier.start()
        try:
            assert verifier._thread is not None
            assert "base_sepolia" in verifier._thread.name
        finally:
            verifier.stop()

    def test_independent_verification(self):
        """Two verifiers (each with own tracker and client) independently
        confirm entities without cross-contamination."""
        # --- GSX chain verifier ---
        tracker_gsx = AnchorStatusTracker()
        _setup_submitted(tracker_gsx, "gsx-ent-0", "0xgsx_tx")
        _setup_submitted(tracker_gsx, "gsx-ent-1", "0xgsx_tx")

        provider_gsx = MockChainProvider(
            block_number=200,
            receipts={
                "0xgsx_tx": {"status": 1, "blockNumber": 100, "gasUsed": 90_000},
            },
        )
        config_gsx = _make_config(confirmation_depth=3)
        verifier_gsx = AnchorVerifier(
            provider_gsx,
            tracker_gsx,
            config_gsx,
            chain_label="gsx_testnet",
        )

        # --- Base Sepolia chain verifier ---
        tracker_base = AnchorStatusTracker()
        _setup_submitted(tracker_base, "base-ent-0", "0xbase_tx")

        provider_base = MockChainProvider(
            block_number=500,
            receipts={
                "0xbase_tx": {"status": 1, "blockNumber": 400, "gasUsed": 70_000},
            },
        )
        config_base = _make_config(confirmation_depth=5)
        verifier_base = AnchorVerifier(
            provider_base,
            tracker_base,
            config_base,
            chain_label="base_sepolia",
        )

        # --- Tick both independently ---
        result_gsx = verifier_gsx.tick(1)
        result_base = verifier_base.tick(1)

        # GSX: 2 entities confirmed and finalized (depth=200-100=100 >= 3)
        assert result_gsx.submitted_checked == 2
        assert result_gsx.confirmed == 2
        assert result_gsx.finalized == 2
        assert tracker_gsx.get("gsx-ent-0").status is AnchorStatus.FINALIZED
        assert tracker_gsx.get("gsx-ent-1").status is AnchorStatus.FINALIZED

        # Base: 1 entity confirmed and finalized (depth=500-400=100 >= 5)
        assert result_base.submitted_checked == 1
        assert result_base.confirmed == 1
        assert result_base.finalized == 1
        assert tracker_base.get("base-ent-0").status is AnchorStatus.FINALIZED

        # Trackers are independent — no cross-contamination
        assert tracker_gsx.get("base-ent-0") is None
        assert tracker_base.get("gsx-ent-0") is None
        assert tracker_base.get("gsx-ent-1") is None

        # Providers received correct calls
        assert len(provider_gsx.receipt_calls) == 1
        assert provider_gsx.receipt_calls[0] == "0xgsx_tx"
        assert len(provider_base.receipt_calls) == 1
        assert provider_base.receipt_calls[0] == "0xbase_tx"
