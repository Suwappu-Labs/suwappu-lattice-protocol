"""Tests for DKG transport protocol (Spec C3b §6)."""

from __future__ import annotations

import pytest

from src.ltp.execution.committee.dkg.transport import (
    DKGTransport,
    FakeDKGTransport,
)
from src.ltp.execution.committee.dkg.types import (
    DKGCommitment,
    DKGComplaint,
    DKGShare,
)

FP_A = b"\x01" * 32
FP_B = b"\x02" * 32
FP_C = b"\x03" * 32


class TestFakeDKGTransportCommitments:
    def test_broadcast_and_receive(self):
        t = FakeDKGTransport()
        c = DKGCommitment(
            dealer_fp=FP_A,
            feldman_commitments=[b"\xaa" * 96],
            pedersen_commitments=[b"\xbb" * 96],
            round_id=1,
        )
        t.broadcast_commitment(c)
        received = t.receive_commitments()
        assert len(received) == 1
        assert received[0] is c

    def test_multiple_commitments_ordered(self):
        t = FakeDKGTransport()
        c1 = DKGCommitment(FP_A, [b"\xaa" * 96], [b"\xbb" * 96], 1)
        c2 = DKGCommitment(FP_B, [b"\xcc" * 96], [b"\xdd" * 96], 2)
        t.broadcast_commitment(c1)
        t.broadcast_commitment(c2)
        received = t.receive_commitments()
        assert len(received) == 2
        assert received[0].dealer_fp == FP_A
        assert received[1].dealer_fp == FP_B


class TestFakeDKGTransportShares:
    def test_send_and_receive_per_recipient(self):
        t = FakeDKGTransport()
        s_ab = DKGShare(dealer_fp=FP_A, recipient_fp=FP_B, share=10, blinding_share=20)
        s_ac = DKGShare(dealer_fp=FP_A, recipient_fp=FP_C, share=30, blinding_share=40)
        t.send_share(FP_B, s_ab)
        t.send_share(FP_C, s_ac)

        b_shares = t.receive_shares(FP_B)
        c_shares = t.receive_shares(FP_C)
        assert len(b_shares) == 1
        assert b_shares[0].share == 10
        assert len(c_shares) == 1
        assert c_shares[0].share == 30

    def test_receive_empty_if_no_shares(self):
        t = FakeDKGTransport()
        assert t.receive_shares(FP_A) == []


class TestFakeDKGTransportComplaints:
    def test_broadcast_and_receive_complaints(self):
        t = FakeDKGTransport()
        complaint = DKGComplaint(
            complainant_fp=FP_B,
            dealer_fp=FP_A,
            revealed_share=10,
            revealed_blinding=20,
            round_id=5,
        )
        t.broadcast_complaint(complaint)
        received = t.receive_complaints()
        assert len(received) == 1
        assert received[0] is complaint


class TestDKGTransportProtocol:
    def test_fake_implements_protocol(self):
        transport: DKGTransport = FakeDKGTransport()
        assert hasattr(transport, "broadcast_commitment")
        assert hasattr(transport, "broadcast_complaint")
        assert hasattr(transport, "send_share")
        assert hasattr(transport, "receive_commitments")
        assert hasattr(transport, "receive_shares")
        assert hasattr(transport, "receive_complaints")
