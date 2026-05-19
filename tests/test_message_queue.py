"""
MessageQueue ABC + InMemoryQueue tests.

Tests FIFO ordering, destructive dequeue, group isolation,
queue depth tracking, and thread safety.
"""

from __future__ import annotations

import threading

import pytest

from src.ltp.cloud.queue import InMemoryQueue

# ---------------------------------------------------------------------------
# Basic InMemoryQueue operations
# ---------------------------------------------------------------------------


class TestInMemoryQueue:
    def test_enqueue_returns_message_id(self):
        q = InMemoryQueue()
        msg_id = q.enqueue("epoch-1", {"node_id": "n1", "amount": 100})
        assert isinstance(msg_id, str)
        assert len(msg_id) > 0

    def test_dequeue_returns_correct_messages(self):
        q = InMemoryQueue()
        q.enqueue("epoch-1", {"a": 1})
        q.enqueue("epoch-1", {"a": 2})

        msgs = q.dequeue("epoch-1")
        assert len(msgs) == 2
        assert msgs[0]["payload"] == {"a": 1}
        assert msgs[1]["payload"] == {"a": 2}

    def test_dequeue_is_destructive(self):
        q = InMemoryQueue()
        q.enqueue("epoch-1", {"a": 1})
        q.dequeue("epoch-1")

        # Second dequeue should be empty
        assert q.dequeue("epoch-1") == []

    def test_peek_is_non_destructive(self):
        q = InMemoryQueue()
        q.enqueue("epoch-1", {"a": 1})

        peeked = q.peek("epoch-1")
        assert len(peeked) == 1

        # Peek again — still there
        assert len(q.peek("epoch-1")) == 1

        # Dequeue still returns it
        assert len(q.dequeue("epoch-1")) == 1

    def test_pending_groups(self):
        q = InMemoryQueue()
        q.enqueue("epoch-1", {"a": 1})
        q.enqueue("epoch-3", {"a": 3})

        groups = q.pending_groups()
        assert "epoch-1" in groups
        assert "epoch-3" in groups
        assert len(groups) == 2

    def test_pending_groups_empty_after_dequeue(self):
        q = InMemoryQueue()
        q.enqueue("epoch-1", {"a": 1})
        q.dequeue("epoch-1")
        assert q.pending_groups() == []

    def test_queue_depth_per_group(self):
        q = InMemoryQueue()
        q.enqueue("g1", {"a": 1})
        q.enqueue("g1", {"a": 2})
        q.enqueue("g2", {"a": 3})

        assert q.queue_depth("g1") == 2
        assert q.queue_depth("g2") == 1

    def test_queue_depth_total(self):
        q = InMemoryQueue()
        q.enqueue("g1", {"a": 1})
        q.enqueue("g1", {"a": 2})
        q.enqueue("g2", {"a": 3})

        assert q.queue_depth() == 3

    def test_empty_dequeue(self):
        q = InMemoryQueue()
        assert q.dequeue("nonexistent") == []

    def test_dequeue_max_messages(self):
        q = InMemoryQueue()
        for i in range(5):
            q.enqueue("batch", {"i": i})

        # Only dequeue 2
        msgs = q.dequeue("batch", max_messages=2)
        assert len(msgs) == 2
        assert msgs[0]["payload"]["i"] == 0
        assert msgs[1]["payload"]["i"] == 1

        # Remaining 3 still there
        assert q.queue_depth("batch") == 3


# ---------------------------------------------------------------------------
# FIFO Ordering
# ---------------------------------------------------------------------------


class TestQueueFIFOOrdering:
    def test_fifo_order_preserved(self):
        q = InMemoryQueue()
        for i in range(10):
            q.enqueue("ordered", {"seq": i})

        msgs = q.dequeue("ordered")
        for i, msg in enumerate(msgs):
            assert msg["payload"]["seq"] == i

    def test_groups_are_independent(self):
        q = InMemoryQueue()
        q.enqueue("alpha", {"val": "a1"})
        q.enqueue("beta", {"val": "b1"})
        q.enqueue("alpha", {"val": "a2"})

        alpha_msgs = q.dequeue("alpha")
        assert len(alpha_msgs) == 2
        assert alpha_msgs[0]["payload"]["val"] == "a1"
        assert alpha_msgs[1]["payload"]["val"] == "a2"

        beta_msgs = q.dequeue("beta")
        assert len(beta_msgs) == 1
        assert beta_msgs[0]["payload"]["val"] == "b1"


# ---------------------------------------------------------------------------
# Thread Safety
# ---------------------------------------------------------------------------


class TestQueueThreadSafety:
    def test_concurrent_enqueue(self):
        q = InMemoryQueue()
        errors = []

        def enqueue_batch(group, start, count):
            try:
                for i in range(start, start + count):
                    q.enqueue(group, {"i": i})
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=enqueue_batch, args=("g1", i * 100, 50)) for i in range(5)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert q.queue_depth("g1") == 250  # 5 threads x 50 messages


# ---------------------------------------------------------------------------
# Audit Fixes
# ---------------------------------------------------------------------------


class TestAuditFixes:
    def test_peek_snapshot_isolation(self):
        """peek() returns copies — mutations don't leak back to queue."""
        q = InMemoryQueue()
        q.enqueue("g1", {"val": "original"})

        peeked = q.peek("g1")
        peeked[0]["payload"]["val"] = "mutated"

        # Internal state should be unchanged
        check = q.peek("g1")
        assert check[0]["payload"]["val"] == "original"
