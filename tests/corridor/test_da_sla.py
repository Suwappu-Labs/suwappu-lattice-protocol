"""Commitment-Node DA SLA tests — mirror `gsx-ltp/src/da.rs` test surface."""

from __future__ import annotations

import pytest

from ltp.corridor import (
    DA_SLA_DEFAULT,
    Cid,
    CommitmentNetwork,
    DaSla,
    LatencyExceeded,
    PayloadMismatch,
    RetentionExpired,
    verify_sla,
)


def test_cid_is_content_addressed() -> None:
    assert Cid.of(b"alpha") == Cid.of(b"alpha")
    assert Cid.of(b"alpha") != Cid.of(b"beta")


def test_store_then_retrieve() -> None:
    net = CommitmentNetwork()
    payload = b"institutional payload, ~4KB in practice"
    cid = net.store(payload, DA_SLA_DEFAULT, now=10)
    commitment, returned = net.retrieve(cid)
    assert commitment.cid == cid
    assert returned == payload
    assert commitment.size_bytes == len(payload)


def test_verify_sla_happy_path() -> None:
    net = CommitmentNetwork()
    cid = net.store(b"happy", DA_SLA_DEFAULT, now=100)
    commitment, returned = net.retrieve(cid)
    verify_sla(commitment, requested_at=1000, responded_at=1010, payload_returned=returned)


def test_verify_sla_late_response_breach() -> None:
    net = CommitmentNetwork()
    cid = net.store(
        b"late",
        DaSla(retention_rounds=10_000, max_retrieval_latency_rounds=5),
        now=10,
    )
    commitment, returned = net.retrieve(cid)
    with pytest.raises(LatencyExceeded):
        verify_sla(commitment, requested_at=100, responded_at=200, payload_returned=returned)


def test_verify_sla_payload_mismatch_breach() -> None:
    net = CommitmentNetwork()
    cid = net.store(b"original", DA_SLA_DEFAULT, now=10)
    commitment, _returned = net.retrieve(cid)
    with pytest.raises(PayloadMismatch):
        verify_sla(commitment, requested_at=100, responded_at=100, payload_returned=b"forged")


def test_retention_expiry_pruned() -> None:
    net = CommitmentNetwork()
    net.store(
        b"stale",
        DaSla(retention_rounds=100, max_retrieval_latency_rounds=16),
        now=10,
    )
    assert len(net) == 1
    pruned = net.prune_expired(now=150)
    assert pruned == 1
    assert net.is_empty()


def test_retrieve_after_expiry_via_verify() -> None:
    net = CommitmentNetwork()
    cid = net.store(
        b"x",
        DaSla(retention_rounds=100, max_retrieval_latency_rounds=16),
        now=10,
    )
    commitment, returned = net.retrieve(cid)
    with pytest.raises(RetentionExpired):
        verify_sla(commitment, requested_at=200, responded_at=200, payload_returned=returned)


def test_default_sla_matches_paper() -> None:
    # Defaults must match the Rust crate's `DaSla::DEFAULT`.
    assert DA_SLA_DEFAULT.retention_rounds == 100_000
    assert DA_SLA_DEFAULT.max_retrieval_latency_rounds == 16
