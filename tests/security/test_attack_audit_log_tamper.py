"""LTP-A-024 regression: cryptographically chained audit log.

``ComplianceAuditLogger`` chains every appended event to the prior
``head_hash`` so any retroactive mutation of an event body (or of a
chain hash) is detectable via ``verify_chain_integrity()``.

This test exercises the attacker's two natural mutation surfaces:
1. Tamper with the event *body* after it's been chained.
2. Tamper with the chain hash itself.

Both must be caught by ``verify_chain_integrity()`` and the first
invalid index must point at the tampered entry.
"""

from __future__ import annotations

import pytest

from src.ltp.compliance import (
    AuditEvent,
    AuditEventType,
    ComplianceAuditLogger,
)


def _seed(logger: ComplianceAuditLogger, n: int = 5) -> None:
    for i in range(n):
        logger.log(AuditEvent(
            event_type=AuditEventType.ANCHOR_SUBMITTED,
            actor_id=f"actor-{i}",
            action="submit",
            target_id=f"anchor-{i}",
            outcome="success",
        ))


def test_clean_chain_verifies():
    logger = ComplianceAuditLogger(operator_id="test")
    _seed(logger)
    valid, idx = logger.verify_chain_integrity()
    assert valid
    assert idx == logger.length


def test_chain_detects_event_body_tamper():
    """Mutating an event body after append must be detected at the
    tampered entry's index."""
    logger = ComplianceAuditLogger(operator_id="test")
    _seed(logger)

    # Tamper with the middle event's outcome.
    logger._events[2].outcome = "failure"  # noqa: SLF001 — adversarial path

    valid, idx = logger.verify_chain_integrity()
    assert not valid, "audit log accepted a tampered event body"
    assert idx == 2


def test_chain_detects_chain_hash_tamper():
    """Mutating a chain hash entry must be detected at that index."""
    logger = ComplianceAuditLogger(operator_id="test")
    _seed(logger)

    logger._chain_hashes[3] = "sha3-256:tampered" + "0" * 56  # noqa: SLF001

    valid, idx = logger.verify_chain_integrity()
    assert not valid, "audit log accepted a tampered chain hash"
    assert idx == 3


def test_head_hash_advances_monotonically():
    logger = ComplianceAuditLogger(operator_id="test")
    seen = {logger.head_hash}
    for i in range(10):
        logger.log(AuditEvent(
            event_type=AuditEventType.ANCHOR_SUBMITTED,
            actor_id=f"a{i}",
            action="x",
        ))
        assert logger.head_hash not in seen, "head_hash collided across events"
        seen.add(logger.head_hash)
