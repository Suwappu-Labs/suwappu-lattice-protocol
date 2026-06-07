"""
Tests for CommitmentLog.records_since(), NodeConfig anchor fields,
and AnchorStatusTracker lifecycle.
"""

from __future__ import annotations

import os
import tempfile
import threading

import pytest

from src.ltp.commitment import CommitmentLog, CommitmentNetwork, CommitmentRecord
from src.ltp.network.safe_network import SafeCommitmentNetwork
from src.ltp.node.anchor_status import AnchorStatus, AnchorStatusTracker
from src.ltp.node.config import NodeConfig

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_record(entity_id: str, alice) -> CommitmentRecord:
    """Create a minimal signed CommitmentRecord."""
    rec = CommitmentRecord(
        entity_id=entity_id,
        sender_id=alice.label,
        shard_map_root=f"root-{entity_id}",
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


# ===================================================================
# CommitmentLog.records_since()
# ===================================================================


class TestRecordsSince:
    def test_records_since_empty_log(self):
        log = CommitmentLog()
        assert log.records_since(0) == []

    def test_records_since_all(self, alice):
        log = CommitmentLog()
        for i in range(3):
            log.append(_make_record(f"ent-{i}", alice))
        result = log.records_since(0)
        assert len(result) == 3
        assert [eid for eid, _ in result] == ["ent-0", "ent-1", "ent-2"]

    def test_records_since_partial(self, alice):
        log = CommitmentLog()
        for i in range(3):
            log.append(_make_record(f"ent-{i}", alice))
        result = log.records_since(2)
        assert len(result) == 1
        assert result[0][0] == "ent-2"

    def test_records_since_beyond_length(self, alice):
        log = CommitmentLog()
        log.append(_make_record("only", alice))
        assert log.records_since(999) == []

    def test_records_since_negative_index_clamped(self, alice):
        """Negative index must clamp to 0, not read from the tail."""
        log = CommitmentLog()
        for i in range(3):
            log.append(_make_record(f"ent-{i}", alice))
        result = log.records_since(-1)
        # Clamped to 0 → returns all 3, not just the last 1
        assert len(result) == 3
        assert [eid for eid, _ in result] == ["ent-0", "ent-1", "ent-2"]

    def test_records_since_via_safe_network(self, alice):
        """SafeCommitmentNetwork.records_since delegates correctly under lock."""
        inner = CommitmentNetwork()
        for i in range(4):
            inner.add_node(f"node-{i}", "US-East")
        safe = SafeCommitmentNetwork(inner)
        # Append through the inner log directly (mimics distribute path)
        inner.log.append(_make_record("ent-a", alice))
        inner.log.append(_make_record("ent-b", alice))
        inner.log.append(_make_record("ent-c", alice))

        result = safe.records_since(1)
        assert len(result) == 2
        assert [eid for eid, _ in result] == ["ent-b", "ent-c"]


# ===================================================================
# NodeConfig anchor fields
# ===================================================================


class TestAnchorConfig:
    def test_anchor_config_defaults(self):
        cfg = NodeConfig()
        assert cfg.anchor_enabled is False
        assert cfg.anchor_rpc_url == ""
        assert cfg.anchor_registry_address == ""
        assert cfg.anchor_operator_key == ""
        assert cfg.anchor_chain_id == 103115120
        assert cfg.anchor_batch_size == 50
        assert cfg.anchor_interval_seconds == 15.0
        assert cfg.anchor_max_wait_seconds == 60.0
        assert cfg.anchor_confirmation_depth == 3
        assert cfg.anchor_finality_depth == 1
        assert cfg.anchor_max_rpc_retries == 5
        assert cfg.anchor_rest_port == 8082

    def test_anchor_config_from_env(self, monkeypatch):
        monkeypatch.setenv("ETP_ANCHOR_ENABLED", "true")
        monkeypatch.setenv("ETP_ANCHOR_RPC_URL", "http://localhost:8545")
        monkeypatch.setenv("ETP_ANCHOR_REGISTRY", "0xABC")
        monkeypatch.setenv("ETP_ANCHOR_OPERATOR_KEY", "0xDEAD")
        monkeypatch.setenv("ETP_ANCHOR_CHAIN_ID", "1")
        monkeypatch.setenv("ETP_ANCHOR_BATCH_SIZE", "100")
        monkeypatch.setenv("ETP_ANCHOR_INTERVAL", "30.0")
        monkeypatch.setenv("ETP_ANCHOR_MAX_WAIT", "120.0")
        monkeypatch.setenv("ETP_ANCHOR_CONFIRMATION_DEPTH", "6")
        monkeypatch.setenv("ETP_ANCHOR_REST_PORT", "9090")

        cfg = NodeConfig.from_env()
        assert cfg.anchor_enabled is True
        assert cfg.anchor_rpc_url == "http://localhost:8545"
        assert cfg.anchor_registry_address == "0xABC"
        assert cfg.anchor_operator_key == "0xDEAD"
        assert cfg.anchor_chain_id == 1
        assert cfg.anchor_batch_size == 100
        assert cfg.anchor_interval_seconds == 30.0
        assert cfg.anchor_max_wait_seconds == 120.0
        assert cfg.anchor_confirmation_depth == 6
        assert cfg.anchor_rest_port == 9090

    def test_anchor_config_from_toml(self, tmp_path):
        toml_content = """\
[node]
node_id = "test-node"

[anchor]
enabled = true
rpc_url = "http://rpc.example.com"
registry_address = "0x1234"
operator_key = "0xBEEF"
chain_id = 42
batch_size = 25
interval = 10.0
max_wait = 45.0
confirmation_depth = 5
rest_port = 7777
"""
        toml_file = tmp_path / "test.toml"
        toml_file.write_text(toml_content)

        cfg = NodeConfig.from_toml(str(toml_file))
        assert cfg.anchor_enabled is True
        assert cfg.anchor_rpc_url == "http://rpc.example.com"
        assert cfg.anchor_registry_address == "0x1234"
        assert cfg.anchor_operator_key == "0xBEEF"
        assert cfg.anchor_chain_id == 42
        assert cfg.anchor_batch_size == 25
        assert cfg.anchor_interval_seconds == 10.0
        assert cfg.anchor_max_wait_seconds == 45.0
        assert cfg.anchor_confirmation_depth == 5
        assert cfg.anchor_rest_port == 7777

    def test_anchor_config_overlay(self, tmp_path, monkeypatch):
        """TOML base values + env var overrides."""
        toml_content = """\
[anchor]
enabled = false
rpc_url = "http://base.example.com"
batch_size = 10
"""
        toml_file = tmp_path / "overlay.toml"
        toml_file.write_text(toml_content)

        # Override enabled and rpc_url via env
        monkeypatch.setenv("ETP_ANCHOR_ENABLED", "true")
        monkeypatch.setenv("ETP_ANCHOR_RPC_URL", "http://override.example.com")

        cfg = NodeConfig.from_toml_with_env_overlay(str(toml_file))
        assert cfg.anchor_enabled is True  # overridden
        assert cfg.anchor_rpc_url == "http://override.example.com"  # overridden
        assert cfg.anchor_batch_size == 10  # from TOML, not overridden


# ===================================================================
# AnchorStatusTracker
# ===================================================================


class TestAnchorStatusTracker:
    def test_status_lifecycle(self):
        tracker = AnchorStatusTracker()
        digest = b"\x00" * 32

        tracker.mark_pending("ent-1", digest)
        assert tracker.get("ent-1").status is AnchorStatus.PENDING

        tracker.mark_submitted("ent-1", "0xabc")
        rec = tracker.get("ent-1")
        assert rec.status is AnchorStatus.SUBMITTED
        assert rec.tx_hash == "0xabc"

        tracker.mark_confirmed("ent-1", block_number=100, gas_used=80_000)
        rec = tracker.get("ent-1")
        assert rec.status is AnchorStatus.CONFIRMED
        assert rec.block_number == 100
        assert rec.gas_used == 80_000
        assert rec.confirmed_at > 0

        tracker.mark_finalized("ent-1")
        assert tracker.get("ent-1").status is AnchorStatus.FINALIZED

    def test_mark_failed(self):
        tracker = AnchorStatusTracker()
        tracker.mark_pending("ent-fail", b"\x01" * 32)
        tracker.mark_failed("ent-fail", "execution reverted")
        rec = tracker.get("ent-fail")
        assert rec.status is AnchorStatus.FAILED
        assert rec.error == "execution reverted"

    def test_get_unknown_entity(self):
        tracker = AnchorStatusTracker()
        assert tracker.get("nonexistent") is None

    def test_get_by_status(self):
        tracker = AnchorStatusTracker()
        tracker.mark_pending("a", b"\x00" * 32)
        tracker.mark_pending("b", b"\x01" * 32)
        tracker.mark_pending("c", b"\x02" * 32)
        tracker.mark_submitted("b", "0x1")

        pending = tracker.get_by_status(AnchorStatus.PENDING)
        assert len(pending) == 2
        ids = {r.entity_id for r in pending}
        assert ids == {"a", "c"}

        submitted = tracker.get_by_status(AnchorStatus.SUBMITTED)
        assert len(submitted) == 1
        assert submitted[0].entity_id == "b"

    def test_stats(self):
        tracker = AnchorStatusTracker()
        tracker.mark_pending("a", b"\x00" * 32)
        tracker.mark_pending("b", b"\x01" * 32)
        tracker.mark_pending("c", b"\x02" * 32)
        tracker.mark_submitted("a", "0x1")
        tracker.mark_failed("c", "nonce too low")

        s = tracker.stats()
        assert s["pending"] == 1
        assert s["submitted"] == 1
        assert s["failed"] == 1
        assert s["confirmed"] == 0
        assert s["finalized"] == 0

    def test_pending_count(self):
        tracker = AnchorStatusTracker()
        assert tracker.pending_count == 0
        tracker.mark_pending("x", b"\x00" * 32)
        tracker.mark_pending("y", b"\x01" * 32)
        assert tracker.pending_count == 2
        tracker.mark_submitted("x", "0x1")
        assert tracker.pending_count == 1

    def test_invalid_transition_raises(self):
        """Invalid state transitions raise ValueError."""
        tracker = AnchorStatusTracker()
        tracker.mark_pending("ent-1", b"\x00" * 32)

        # PENDING -> FINALIZED (skips SUBMITTED, CONFIRMED)
        with pytest.raises(ValueError, match="Invalid anchor transition"):
            tracker.mark_finalized("ent-1")

        # PENDING -> CONFIRMED (skips SUBMITTED)
        with pytest.raises(ValueError, match="Invalid anchor transition"):
            tracker.mark_confirmed("ent-1", block_number=1, gas_used=1)

        # Advance to FAILED, then try to re-submit
        tracker.mark_failed("ent-1", "reverted")
        with pytest.raises(ValueError, match="Invalid anchor transition"):
            tracker.mark_submitted("ent-1", "0xdead")

    def test_mark_on_nonexistent_entity_raises(self):
        """mark_* on unknown entity raises KeyError."""
        tracker = AnchorStatusTracker()
        with pytest.raises(KeyError):
            tracker.mark_submitted("ghost", "0x1")
        with pytest.raises(KeyError):
            tracker.mark_confirmed("ghost", 1, 1)
        with pytest.raises(KeyError):
            tracker.mark_finalized("ghost")
        with pytest.raises(KeyError):
            tracker.mark_failed("ghost", "err")

    def test_invalid_digest_length_raises(self):
        """anchor_digest must be exactly 32 bytes."""
        tracker = AnchorStatusTracker()
        with pytest.raises(ValueError, match="exactly 32 bytes"):
            tracker.mark_pending("ent-1", b"\x00" * 16)
        with pytest.raises(ValueError, match="exactly 32 bytes"):
            tracker.mark_pending("ent-1", b"")

    def test_get_returns_snapshot_not_live_reference(self):
        """Mutating the returned record must not affect tracker state."""
        tracker = AnchorStatusTracker()
        tracker.mark_pending("ent-1", b"\x00" * 32)

        snapshot = tracker.get("ent-1")
        snapshot.tx_hash = "MUTATED"
        snapshot.error = "MUTATED"

        # Internal state must be unaffected
        actual = tracker.get("ent-1")
        assert actual.tx_hash == ""
        assert actual.error == ""

    def test_failed_from_submitted(self):
        """SUBMITTED -> FAILED is valid (e.g., tx reverted)."""
        tracker = AnchorStatusTracker()
        tracker.mark_pending("ent-1", b"\x00" * 32)
        tracker.mark_submitted("ent-1", "0xabc")
        tracker.mark_failed("ent-1", "out of gas")
        assert tracker.get("ent-1").status is AnchorStatus.FAILED

    def test_failed_from_confirmed(self):
        """CONFIRMED -> FAILED is valid (e.g., reorg past confirmation depth)."""
        tracker = AnchorStatusTracker()
        tracker.mark_pending("ent-1", b"\x00" * 32)
        tracker.mark_submitted("ent-1", "0xabc")
        tracker.mark_confirmed("ent-1", block_number=50, gas_used=80_000)
        tracker.mark_failed("ent-1", "chain reorg")
        assert tracker.get("ent-1").status is AnchorStatus.FAILED

    def test_thread_safety(self):
        """10 concurrent threads marking entities — no corruption."""
        tracker = AnchorStatusTracker()
        errors: list[str] = []

        def worker(thread_id: int):
            try:
                eid = f"thread-{thread_id}"
                tracker.mark_pending(eid, bytes([thread_id]) * 32)
                tracker.mark_submitted(eid, f"0x{thread_id:04x}")
                tracker.mark_confirmed(eid, block_number=thread_id * 10, gas_used=50_000)
                tracker.mark_finalized(eid)
            except Exception as exc:
                errors.append(f"thread-{thread_id}: {exc}")

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Thread errors: {errors}"
        assert len(tracker.get_by_status(AnchorStatus.FINALIZED)) == 10
        s = tracker.stats()
        assert s["finalized"] == 10
        assert s["pending"] == 0


# ===================================================================
# AnchorScheduler batch submission pipeline
# ===================================================================

import time as _time

from src.ltp.domain import signer_fingerprint
from src.ltp.node.anchor_scheduler import AnchorScheduler, AnchorTickResult
from src.ltp.primitives import canonical_hash_bytes


def _make_anchoring_record(entity_id: str, alice) -> CommitmentRecord:
    """CommitmentRecord with a sha3-256:hex shard_map_root (scheduler-compatible)."""
    hex_root = "sha3-256:" + "ab" * 32  # 64 hex chars = 32 bytes
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


class MockAnchorClient:
    """Duck-typed mock for AnchorClient."""

    def __init__(self, *, fail_on_call=None, tx_hash="0x" + "ab" * 32):
        self.submissions: list = []
        self.call_count: int = 0
        self._fail_on_call = fail_on_call
        self._tx_hash = tx_hash

    def batch_anchor(self, submissions):
        self.call_count += 1
        if self._fail_on_call is not None and self.call_count >= self._fail_on_call:
            raise RuntimeError("Mock chain error")
        self.submissions.extend(submissions)
        return self._tx_hash

    def signer_sequence(self, vk_hash):
        return 0


def _make_scheduler(alice, *, batch_size=50, max_wait=60.0, client=None, n_records=0):
    """Create an AnchorScheduler with a SafeCommitmentNetwork and optional pre-loaded records."""
    inner = CommitmentNetwork()
    for i in range(4):
        inner.add_node(f"node-{i}", "US-East")
    safe = SafeCommitmentNetwork(inner)

    for i in range(n_records):
        inner.log.append(_make_anchoring_record(f"ent-{i}", alice))

    config = NodeConfig()
    config.anchor_batch_size = batch_size
    config.anchor_max_wait_seconds = max_wait
    config.anchor_chain_id = 103115120

    tracker = AnchorStatusTracker()
    mock_client = client or MockAnchorClient()

    scheduler = AnchorScheduler(
        network=safe,
        client=mock_client,
        tracker=tracker,
        config=config,
        signer_vk=alice.vk,
    )
    return scheduler, safe, tracker, mock_client, inner


# -------------------------------------------------------------------
# Polling tests
# -------------------------------------------------------------------


class TestAnchorSchedulerPolling:
    def test_tick_empty_log(self, alice):
        scheduler, *_ = _make_scheduler(alice)
        result = scheduler.tick(1)
        assert result.records_polled == 0
        assert result.batch_submitted is False
        assert result.pending_batch_size == 0

    def test_tick_polls_new_records(self, alice):
        scheduler, *_ = _make_scheduler(alice, n_records=3)
        result = scheduler.tick(1)
        assert result.records_polled == 3
        assert result.records_queued == 3

    def test_tick_advances_last_seen_index(self, alice):
        scheduler, safe, *_ = _make_scheduler(alice, n_records=3)
        scheduler.tick(1)
        assert scheduler.last_seen_index == 3

    def test_tick_skips_already_tracked(self, alice):
        scheduler, safe, tracker, *_ = _make_scheduler(alice, n_records=2)
        # Pre-mark entity in tracker
        tracker.mark_pending("ent-0", b"\x00" * 32)
        result = scheduler.tick(1)
        assert result.records_polled == 2
        assert result.records_skipped == 1
        assert result.records_queued == 1

    def test_tick_no_submit_below_batch_size(self, alice):
        scheduler, *_ = _make_scheduler(alice, batch_size=50, n_records=2)
        result = scheduler.tick(1)
        assert result.batch_submitted is False
        assert result.pending_batch_size == 2

    def test_multi_tick_batch_accumulation(self, alice):
        """Batch buffer persists across ticks until threshold is reached."""
        scheduler, safe, tracker, mock_client, inner = _make_scheduler(alice, batch_size=3)
        # Tick 1: add 2 records — below batch_size, no submission
        inner.log.append(_make_anchoring_record("acc-0", alice))
        inner.log.append(_make_anchoring_record("acc-1", alice))
        r1 = scheduler.tick(1)
        assert r1.records_queued == 2
        assert r1.batch_submitted is False
        assert r1.pending_batch_size == 2

        # Tick 2: add 1 more record — reaches batch_size=3, triggers submission
        inner.log.append(_make_anchoring_record("acc-2", alice))
        r2 = scheduler.tick(2)
        assert r2.records_queued == 1
        assert r2.batch_submitted is True
        assert r2.batch_size == 3
        assert mock_client.call_count == 1
        assert len(mock_client.submissions) == 3
        assert r2.pending_batch_size == 0

    def test_conversion_error_skips_gracefully(self, alice):
        """A malformed record is skipped without blocking the batch."""
        scheduler, safe, tracker, mock_client, inner = _make_scheduler(
            alice, batch_size=50, max_wait=0.0
        )
        # Good record
        inner.log.append(_make_anchoring_record("good-0", alice))
        # Bad record: shard_map_root is not valid hex
        bad_rec = CommitmentRecord(
            entity_id="bad-record",
            sender_id=alice.label,
            shard_map_root="NOT-VALID-HEX",
            content_hash="hash-bad",
            encoding_params={"n": 8, "k": 4, "algorithm": "reed_solomon"},
            shape="application/octet-stream",
            shape_hash="shape-bad",
            timestamp=1_700_000_000.0,
            signature=b"",
            sender_vk=alice.vk,
        )
        bad_rec.sign(alice.sk)
        inner.log.append(bad_rec)
        # Another good record
        inner.log.append(_make_anchoring_record("good-1", alice))

        result = scheduler.tick(1)
        assert result.records_polled == 3
        assert result.records_queued == 2  # bad one skipped
        assert result.batch_submitted is True
        assert result.batch_size == 2
        # Bad record should NOT be in tracker
        assert tracker.get("bad-record") is None
        # Good records should be SUBMITTED
        assert tracker.get("good-0").status is AnchorStatus.SUBMITTED
        assert tracker.get("good-1").status is AnchorStatus.SUBMITTED


# -------------------------------------------------------------------
# Batch submission tests
# -------------------------------------------------------------------


class TestAnchorSchedulerSubmission:
    def test_submit_on_batch_size(self, alice):
        scheduler, safe, tracker, mock_client, _ = _make_scheduler(alice, batch_size=3, n_records=3)
        result = scheduler.tick(1)
        assert result.batch_submitted is True
        assert result.batch_size == 3
        assert mock_client.call_count == 1
        assert len(mock_client.submissions) == 3

    def test_submit_on_max_wait(self, alice):
        scheduler, safe, tracker, mock_client, inner = _make_scheduler(
            alice, batch_size=50, max_wait=0.0, n_records=1
        )
        # First tick: polls record, adds to batch but max_wait=0 fires immediately
        # Since max_wait=0.0, the time check passes as soon as there's a pending record
        result = scheduler.tick(1)
        assert result.batch_submitted is True
        assert result.batch_size == 1

    def test_all_marked_submitted(self, alice):
        scheduler, safe, tracker, mock_client, _ = _make_scheduler(alice, batch_size=3, n_records=3)
        scheduler.tick(1)
        for i in range(3):
            rec = tracker.get(f"ent-{i}")
            assert rec is not None
            assert rec.status is AnchorStatus.SUBMITTED

    def test_tx_hash_in_result(self, alice):
        expected_hash = "0x" + "ff" * 32
        client = MockAnchorClient(tx_hash=expected_hash)
        scheduler, *_ = _make_scheduler(alice, batch_size=2, n_records=2, client=client)
        result = scheduler.tick(1)
        assert result.tx_hash == expected_hash

    def test_batch_clears_after_submit(self, alice):
        scheduler, *_ = _make_scheduler(alice, batch_size=3, n_records=3)
        result = scheduler.tick(1)
        assert result.batch_submitted is True
        assert result.pending_batch_size == 0
        assert scheduler.pending_batch_size == 0

    def test_partial_batch_on_max_wait(self, alice):
        """< batch_size records submitted when max_wait timer fires."""
        scheduler, safe, tracker, mock_client, inner = _make_scheduler(
            alice, batch_size=50, max_wait=0.0, n_records=2
        )
        result = scheduler.tick(1)
        assert result.batch_submitted is True
        assert result.batch_size == 2
        assert mock_client.call_count == 1


# -------------------------------------------------------------------
# Failure tests
# -------------------------------------------------------------------


class TestAnchorSchedulerFailure:
    def test_failure_marks_all_failed(self, alice):
        client = MockAnchorClient(fail_on_call=1)
        scheduler, safe, tracker, _, _ = _make_scheduler(
            alice, batch_size=3, n_records=3, client=client
        )
        result = scheduler.tick(1)
        assert result.batch_submitted is False
        assert result.error == "batch submission failed (see logs)"
        for i in range(3):
            rec = tracker.get(f"ent-{i}")
            assert rec is not None
            assert rec.status is AnchorStatus.FAILED

    def test_failure_rolls_back_sequences(self, alice):
        client = MockAnchorClient(fail_on_call=1)
        scheduler, safe, tracker, _, _ = _make_scheduler(
            alice, batch_size=3, n_records=3, client=client
        )
        # Record the vk_hash to check sequence
        vk_hash = signer_fingerprint(alice.vk)

        scheduler.tick(1)
        # After failure, sequence should be rolled back to 0
        assert scheduler._signer_sequences.get(vk_hash, 0) == 0

    def test_failure_clears_batch(self, alice):
        client = MockAnchorClient(fail_on_call=1)
        scheduler, *_ = _make_scheduler(alice, batch_size=3, n_records=3, client=client)
        scheduler.tick(1)
        assert scheduler.pending_batch_size == 0


# -------------------------------------------------------------------
# Submission building tests
# -------------------------------------------------------------------


class TestAnchorSubmissionBuilding:
    def test_anchor_digest_is_32_bytes(self, alice):
        scheduler, safe, tracker, mock_client, _ = _make_scheduler(alice, batch_size=1, n_records=1)
        scheduler.tick(1)
        sub = mock_client.submissions[0]
        assert len(sub.anchor_digest) == 32

    def test_entity_id_hash_is_canonical(self, alice):
        scheduler, safe, tracker, mock_client, _ = _make_scheduler(alice, batch_size=1, n_records=1)
        scheduler.tick(1)
        sub = mock_client.submissions[0]
        expected = canonical_hash_bytes(b"ent-0")
        assert sub.entity_id_hash == expected

    def test_signer_vk_hash_from_record(self, alice):
        scheduler, safe, tracker, mock_client, _ = _make_scheduler(alice, batch_size=1, n_records=1)
        scheduler.tick(1)
        sub = mock_client.submissions[0]
        expected = signer_fingerprint(alice.vk)
        assert sub.signer_vk_hash == expected

    def test_sequence_increments(self, alice):
        scheduler, safe, tracker, mock_client, inner = _make_scheduler(
            alice, batch_size=50, max_wait=0.0
        )
        # Add 3 records one at a time with separate ticks
        for i in range(3):
            inner.log.append(_make_anchoring_record(f"seq-{i}", alice))
        # Single tick picks up all 3, batch fires on max_wait=0
        scheduler.tick(1)
        seqs = [sub.sequence for sub in mock_client.submissions]
        assert seqs == [1, 2, 3]

    def test_different_signers_independent(self, alice, bob):
        """Different signers have independent sequence counters."""
        scheduler, safe, tracker, mock_client, inner = _make_scheduler(
            alice, batch_size=50, max_wait=0.0
        )
        # Add records from two different signers
        inner.log.append(_make_anchoring_record("from-alice", alice))
        inner.log.append(_make_anchoring_record("from-bob", bob))
        inner.log.append(_make_anchoring_record("from-alice-2", alice))

        scheduler.tick(1)
        subs = mock_client.submissions
        # alice: seq 1, bob: seq 1, alice: seq 2
        assert subs[0].sequence == 1  # alice first
        assert subs[1].sequence == 1  # bob first
        assert subs[2].sequence == 2  # alice second

    def test_seed_sequence(self, alice):
        """Seeded counter continues from on-chain value."""
        scheduler, safe, tracker, mock_client, inner = _make_scheduler(
            alice, batch_size=50, max_wait=0.0
        )
        vk_hash = signer_fingerprint(alice.vk)
        scheduler.seed_sequence(vk_hash, 42)

        inner.log.append(_make_anchoring_record("seeded-0", alice))
        scheduler.tick(1)
        assert mock_client.submissions[0].sequence == 43

    def test_merkle_root_extracted_correctly(self, alice):
        """merkle_root is the raw 32 bytes from the sha3-256:hex shard_map_root."""
        scheduler, safe, tracker, mock_client, _ = _make_scheduler(alice, batch_size=1, n_records=1)
        scheduler.tick(1)
        sub = mock_client.submissions[0]
        # _make_anchoring_record uses "sha3-256:" + "ab" * 32
        assert sub.merkle_root == bytes.fromhex("ab" * 32)
        assert len(sub.merkle_root) == 32

    def test_policy_hash_is_zero_sentinel(self, alice):
        """policy_hash must be 32 zero bytes (no SignerPolicy in commit path)."""
        scheduler, safe, tracker, mock_client, _ = _make_scheduler(alice, batch_size=1, n_records=1)
        scheduler.tick(1)
        sub = mock_client.submissions[0]
        assert sub.policy_hash == b"\x00" * 32

    def test_target_chain_id_from_config(self, alice):
        """target_chain_id must match config.anchor_chain_id."""
        scheduler, safe, tracker, mock_client, _ = _make_scheduler(alice, batch_size=1, n_records=1)
        scheduler.tick(1)
        sub = mock_client.submissions[0]
        assert sub.target_chain_id == 103115120

    def test_receipt_type_is_commit(self, alice):
        """receipt_type must be 'COMMIT' for commitment-path anchoring."""
        scheduler, safe, tracker, mock_client, _ = _make_scheduler(alice, batch_size=1, n_records=1)
        scheduler.tick(1)
        sub = mock_client.submissions[0]
        assert sub.receipt_type == "COMMIT"

    def test_valid_until_is_future(self, alice):
        """valid_until must be approximately now + 3600."""
        scheduler, safe, tracker, mock_client, _ = _make_scheduler(alice, batch_size=1, n_records=1)
        before = int(_time.time())
        scheduler.tick(1)
        after = int(_time.time())
        sub = mock_client.submissions[0]
        assert before + 3600 <= sub.valid_until <= after + 3600

    def test_submission_to_calldata_succeeds(self, alice):
        """All generated submissions must produce valid ABI-encoded calldata."""
        scheduler, safe, tracker, mock_client, _ = _make_scheduler(alice, batch_size=3, n_records=3)
        scheduler.tick(1)
        for sub in mock_client.submissions:
            cd = sub.to_calldata()
            # 32*4 (digests) + 8*3 (uints) + 4+len(receipt_type) = 156 + len("COMMIT")=6 = 162
            assert len(cd) >= 156


# -------------------------------------------------------------------
# Daemon thread tests
# -------------------------------------------------------------------


class TestAnchorSchedulerThread:
    def test_start_stop(self, alice):
        scheduler, *_ = _make_scheduler(alice)
        scheduler.start()
        assert scheduler.running is True
        scheduler.stop()
        assert scheduler.running is False

    def test_start_idempotent(self, alice):
        """Double start() → single thread."""
        scheduler, *_ = _make_scheduler(alice)
        scheduler.start()
        scheduler.start()  # should be no-op
        assert scheduler.running is True
        scheduler.stop()

    def test_epoch_increments(self, alice):
        scheduler, *_ = _make_scheduler(alice)
        assert scheduler.epoch == 0
        scheduler.tick(1)
        # tick() itself doesn't bump _epoch (that's _run_loop's job)
        # but the epoch we passed is in the result
        scheduler.start()
        _time.sleep(0.15)  # Let at least one loop iteration run
        scheduler.stop()
        assert scheduler.epoch >= 1


# -------------------------------------------------------------------
# AnchorTickResult dataclass
# -------------------------------------------------------------------


class TestAnchorTickResult:
    def test_defaults(self):
        r = AnchorTickResult(epoch=1)
        assert r.epoch == 1
        assert r.records_polled == 0
        assert r.records_queued == 0
        assert r.records_skipped == 0
        assert r.batch_submitted is False
        assert r.batch_size == 0
        assert r.tx_hash == ""
        assert r.error == ""
        assert r.pending_batch_size == 0


# ===================================================================
# Multi-chain scheduler tests
# ===================================================================


class TestMultiChainScheduler:
    """Verify that multiple AnchorScheduler instances can operate
    independently on different chains with correct labelling."""

    def test_chain_label_in_thread_name(self, alice):
        """Scheduler thread name must include the chain_label."""
        inner = CommitmentNetwork()
        for i in range(4):
            inner.add_node(f"node-{i}", "US-East")
        safe = SafeCommitmentNetwork(inner)
        config = NodeConfig()
        tracker = AnchorStatusTracker()
        client = MockAnchorClient()

        scheduler = AnchorScheduler(
            network=safe,
            client=client,
            tracker=tracker,
            config=config,
            signer_vk=alice.vk,
            chain_label="suwappu_testnet",
        )
        scheduler.start()
        try:
            assert scheduler._thread is not None
            assert "suwappu_testnet" in scheduler._thread.name
        finally:
            scheduler.stop()

    def test_chain_id_stamped_on_records(self, alice):
        """Records submitted by a scheduler with chain_id must carry that chain_id in the tracker."""
        inner = CommitmentNetwork()
        for i in range(4):
            inner.add_node(f"node-{i}", "US-East")
        safe = SafeCommitmentNetwork(inner)
        inner.log.append(_make_anchoring_record("ent-chain", alice))

        config = NodeConfig()
        config.anchor_batch_size = 1

        tracker = AnchorStatusTracker()
        client = MockAnchorClient()

        scheduler = AnchorScheduler(
            network=safe,
            client=client,
            tracker=tracker,
            config=config,
            signer_vk=alice.vk,
            chain_id=84532,
        )
        scheduler.tick(1)

        rec = tracker.get("ent-chain")
        assert rec is not None
        assert rec.chain_id == 84532

    def test_independent_pipelines(self, alice):
        """Two schedulers (one per chain) submit batches independently."""
        # --- SUWAPPU chain scheduler ---
        inner_suwappu = CommitmentNetwork()
        for i in range(4):
            inner_suwappu.add_node(f"suwappu-node-{i}", "US-East")
        safe_suwappu = SafeCommitmentNetwork(inner_suwappu)
        inner_suwappu.log.append(_make_anchoring_record("suwappu-ent-0", alice))
        inner_suwappu.log.append(_make_anchoring_record("suwappu-ent-1", alice))

        config_suwappu = NodeConfig()
        config_suwappu.anchor_batch_size = 50
        config_suwappu.anchor_max_wait_seconds = 0.0
        config_suwappu.anchor_chain_id = 103115120

        tracker_suwappu = AnchorStatusTracker()
        client_suwappu = MockAnchorClient(tx_hash="0x" + "aa" * 32)

        scheduler_suwappu = AnchorScheduler(
            network=safe_suwappu,
            client=client_suwappu,
            tracker=tracker_suwappu,
            config=config_suwappu,
            signer_vk=alice.vk,
            chain_label="suwappu_testnet",
            chain_id=103115120,
        )

        # --- Base Sepolia chain scheduler ---
        inner_base = CommitmentNetwork()
        for i in range(4):
            inner_base.add_node(f"base-node-{i}", "US-West")
        safe_base = SafeCommitmentNetwork(inner_base)
        inner_base.log.append(_make_anchoring_record("base-ent-0", alice))

        config_base = NodeConfig()
        config_base.anchor_batch_size = 50
        config_base.anchor_max_wait_seconds = 0.0
        config_base.anchor_chain_id = 84532

        tracker_base = AnchorStatusTracker()
        client_base = MockAnchorClient(tx_hash="0x" + "bb" * 32)

        scheduler_base = AnchorScheduler(
            network=safe_base,
            client=client_base,
            tracker=tracker_base,
            config=config_base,
            signer_vk=alice.vk,
            chain_label="base_sepolia",
            chain_id=84532,
        )

        # --- Tick both independently ---
        result_suwappu = scheduler_suwappu.tick(1)
        result_base = scheduler_base.tick(1)

        # SUWAPPU submitted its 2-record batch
        assert result_suwappu.batch_submitted is True
        assert result_suwappu.batch_size == 2
        assert client_suwappu.call_count == 1
        assert len(client_suwappu.submissions) == 2

        # Base submitted its 1-record batch
        assert result_base.batch_submitted is True
        assert result_base.batch_size == 1
        assert client_base.call_count == 1
        assert len(client_base.submissions) == 1

        # Trackers are independent — no cross-contamination
        assert tracker_suwappu.get("suwappu-ent-0") is not None
        assert tracker_suwappu.get("suwappu-ent-1") is not None
        assert tracker_suwappu.get("base-ent-0") is None

        assert tracker_base.get("base-ent-0") is not None
        assert tracker_base.get("suwappu-ent-0") is None

        # Chain IDs are correct on each tracker's records
        assert tracker_suwappu.get("suwappu-ent-0").chain_id == 103115120
        assert tracker_base.get("base-ent-0").chain_id == 84532

        # Tx hashes are from the correct client
        assert tracker_suwappu.get("suwappu-ent-0").tx_hash == "0x" + "aa" * 32
        assert tracker_base.get("base-ent-0").tx_hash == "0x" + "bb" * 32
