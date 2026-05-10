"""Tests for DKG core types (Spec C3b §2)."""

from __future__ import annotations

import pytest

from src.ltp.execution.committee.dkg.types import (
    DKGState,
    DKGPhase,
    DKGCommitment,
    DKGShare,
    DKGComplaint,
    DKGResult,
    DKGSessionConfig,
)


class TestDKGState:

    def test_has_eight_states(self):
        assert len(DKGState) == 8

    def test_state_values(self):
        expected = {
            "idle", "committing", "sharing", "verifying",
            "complaining", "finalizing", "completed", "failed",
        }
        assert {s.value for s in DKGState} == expected


class TestDKGPhase:

    def test_has_two_phases(self):
        assert len(DKGPhase) == 2

    def test_phase_values(self):
        assert {p.value for p in DKGPhase} == {"eager", "inline"}


class TestDKGCommitment:

    def test_frozen(self):
        c = DKGCommitment(
            dealer_fp=b"\x01" * 32,
            feldman_commitments=[b"\xaa" * 96],
            pedersen_commitments=[b"\xbb" * 96],
            round_id=5,
        )
        with pytest.raises(AttributeError):
            c.round_id = 10

    def test_fields(self):
        fp = b"\x01" * 32
        c = DKGCommitment(
            dealer_fp=fp,
            feldman_commitments=[b"\xaa" * 96, b"\xbb" * 96],
            pedersen_commitments=[b"\xcc" * 96, b"\xdd" * 96],
            round_id=7,
        )
        assert c.dealer_fp == fp
        assert len(c.feldman_commitments) == 2
        assert len(c.pedersen_commitments) == 2
        assert c.round_id == 7


class TestDKGShare:

    def test_frozen(self):
        s = DKGShare(
            dealer_fp=b"\x01" * 32,
            recipient_fp=b"\x02" * 32,
            share=42,
            blinding_share=99,
        )
        with pytest.raises(AttributeError):
            s.share = 0

    def test_fields(self):
        s = DKGShare(
            dealer_fp=b"\x01" * 32,
            recipient_fp=b"\x02" * 32,
            share=12345,
            blinding_share=67890,
        )
        assert s.dealer_fp == b"\x01" * 32
        assert s.recipient_fp == b"\x02" * 32
        assert s.share == 12345
        assert s.blinding_share == 67890


class TestDKGComplaint:

    def test_frozen(self):
        c = DKGComplaint(
            complainant_fp=b"\x01" * 32,
            dealer_fp=b"\x02" * 32,
            revealed_share=1,
            revealed_blinding=2,
            round_id=3,
        )
        with pytest.raises(AttributeError):
            c.round_id = 99


class TestDKGResult:

    def test_frozen(self):
        r = DKGResult(
            vm_tag=0x01,
            epoch=1,
            group_pk=b"\xaa" * 48,
            participant_vks={b"\x01" * 32: b"\xbb" * 48},
            threshold=2,
            qual_set=frozenset([b"\x01" * 32]),
            phase=DKGPhase.EAGER,
        )
        with pytest.raises(AttributeError):
            r.epoch = 99

    def test_fields(self):
        vks = {b"\x01" * 32: b"\xaa" * 48, b"\x02" * 32: b"\xbb" * 48}
        qual = frozenset([b"\x01" * 32, b"\x02" * 32])
        r = DKGResult(
            vm_tag=0x01,
            epoch=5,
            group_pk=b"\xff" * 48,
            participant_vks=vks,
            threshold=2,
            qual_set=qual,
            phase=DKGPhase.INLINE,
        )
        assert r.vm_tag == 0x01
        assert r.epoch == 5
        assert len(r.group_pk) == 48
        assert len(r.participant_vks) == 2
        assert r.threshold == 2
        assert r.qual_set == qual
        assert r.phase is DKGPhase.INLINE


class TestDKGSessionConfig:

    def test_mutable(self):
        cfg = DKGSessionConfig(
            vm_tag=0x01,
            epoch=1,
            threshold=2,
            participants=[b"\x01" * 32, b"\x02" * 32, b"\x03" * 32],
            timeout_rounds=10,
            start_round=100,
        )
        cfg.timeout_rounds = 20
        assert cfg.timeout_rounds == 20

    def test_fields(self):
        parts = [b"\x01" * 32, b"\x02" * 32]
        cfg = DKGSessionConfig(
            vm_tag=0x02,
            epoch=3,
            threshold=1,
            participants=parts,
            timeout_rounds=15,
            start_round=50,
        )
        assert cfg.vm_tag == 0x02
        assert cfg.epoch == 3
        assert cfg.threshold == 1
        assert cfg.participants == parts
        assert cfg.timeout_rounds == 15
        assert cfg.start_round == 50
