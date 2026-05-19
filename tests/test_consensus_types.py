"""Tests for DAG data structures (Spec D1a §1)."""

from ltp.consensus.types import (
    Block,
    Certificate,
    CommitDecision,
    EquivocationProof,
    RoundState,
)


class TestBlock:
    """Block frozen dataclass and digest computation."""

    def test_block_creation(self):
        b = Block(author=0, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        assert b.author == 0
        assert b.round == 1
        assert b.payload == (b"tx1",)
        assert b.parents == frozenset()
        assert b.timestamp_ms == 1000
        assert isinstance(b.digest, bytes)
        assert len(b.digest) == 32  # SHA3-256

    def test_digest_deterministic(self):
        b1 = Block(author=0, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        b2 = Block(author=0, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        assert b1.digest == b2.digest

    def test_digest_changes_with_author(self):
        b1 = Block(author=0, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        b2 = Block(author=1, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        assert b1.digest != b2.digest

    def test_digest_changes_with_round(self):
        b1 = Block(author=0, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        b2 = Block(author=0, round=2, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        assert b1.digest != b2.digest

    def test_digest_changes_with_payload(self):
        b1 = Block(author=0, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        b2 = Block(author=0, round=1, payload=(b"tx2",), parents=frozenset(), timestamp_ms=1000)
        assert b1.digest != b2.digest

    def test_digest_changes_with_parents(self):
        b1 = Block(author=0, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        b2 = Block(
            author=0,
            round=1,
            payload=(b"tx1",),
            parents=frozenset({b"\x00" * 32}),
            timestamp_ms=1000,
        )
        assert b1.digest != b2.digest

    def test_block_is_frozen(self):
        b = Block(author=0, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        import dataclasses

        assert dataclasses.is_dataclass(b)
        try:
            b.author = 1  # type: ignore[misc]
            assert False, "Should be frozen"
        except AttributeError:
            pass

    def test_digest_ignores_timestamp(self):
        """Timestamp is not part of the digest — it's metadata only."""
        b1 = Block(author=0, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        b2 = Block(author=0, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=9999)
        assert b1.digest == b2.digest

    def test_digest_no_length_substitution_collision(self):
        b1 = Block(author=0, round=1, payload=(b"ab", b"c"), parents=frozenset(), timestamp_ms=1000)
        b2 = Block(author=0, round=1, payload=(b"a", b"bc"), parents=frozenset(), timestamp_ms=1000)
        assert b1.digest != b2.digest


class TestCertificate:
    """Certificate creation and quorum validation."""

    def test_certificate_creation(self):
        b = Block(author=0, round=1, payload=(), parents=frozenset(), timestamp_ms=1000)
        cert = Certificate(block=b, signers=frozenset({0, 1, 2}))
        assert cert.block is b
        assert cert.signers == frozenset({0, 1, 2})
        assert cert.digest == b.digest

    def test_certificate_is_frozen(self):
        b = Block(author=0, round=1, payload=(), parents=frozenset(), timestamp_ms=1000)
        cert = Certificate(block=b, signers=frozenset({0, 1, 2}))
        try:
            cert.block = b  # type: ignore[misc]
            assert False, "Should be frozen"
        except AttributeError:
            pass

    def test_certificate_digest_matches_block(self):
        b = Block(author=0, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        cert = Certificate(block=b, signers=frozenset({0, 1}))
        assert cert.digest == b.digest


class TestCommitDecision:
    """CommitDecision structure."""

    def test_commit_decision_creation(self):
        b = Block(author=0, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        cert = Certificate(block=b, signers=frozenset({0, 1, 2}))
        cd = CommitDecision(leader_certificate=cert, committed_blocks=[b], round=1)
        assert cd.leader_certificate is cert
        assert cd.committed_blocks == [b]
        assert cd.round == 1


class TestEquivocationProof:
    """EquivocationProof requires same author+round, different digest."""

    def test_equivocation_proof_creation(self):
        a = Block(author=0, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        b = Block(author=0, round=1, payload=(b"tx2",), parents=frozenset(), timestamp_ms=1000)
        proof = EquivocationProof(author=0, block_a=a, block_b=b, round=1)
        assert proof.author == 0
        assert proof.block_a.digest != proof.block_b.digest
        assert proof.round == 1


class TestRoundState:
    """RoundState is mutable — tracks per-round progress."""

    def test_round_state_defaults(self):
        rs = RoundState(round=5)
        assert rs.round == 5
        assert rs.proposals == {}
        assert rs.acks == {}
        assert rs.certificates == {}
        assert rs.timed_out is False

    def test_round_state_mutable(self):
        rs = RoundState(round=1)
        rs.timed_out = True
        assert rs.timed_out is True
        b = Block(author=0, round=1, payload=(), parents=frozenset(), timestamp_ms=1000)
        rs.proposals[0] = b
        assert 0 in rs.proposals


from ltp.consensus.faults import FaultConfig, FaultType, PartitionConfig
from ltp.consensus.message_bus import MessageBus


class TestFaultTypes:
    """FaultType enum and config dataclasses."""

    def test_fault_type_values(self):
        assert FaultType.HONEST.value == "honest"
        assert FaultType.EQUIVOCATE.value == "equivocate"
        assert FaultType.WITHHOLD.value == "withhold"
        assert FaultType.CRASH.value == "crash"
        assert FaultType.DELAY.value == "delay"
        assert FaultType.CENSOR.value == "censor"

    def test_fault_config(self):
        fc = FaultConfig(validator=1, fault_type=FaultType.CRASH, start_round=5)
        assert fc.validator == 1
        assert fc.fault_type == FaultType.CRASH
        assert fc.start_round == 5
        assert fc.end_round is None
        assert fc.params == {}

    def test_partition_config(self):
        pc = PartitionConfig(
            group_a=frozenset({0, 1}),
            group_b=frozenset({2, 3}),
            start_round=3,
            duration=5,
        )
        assert pc.group_a == frozenset({0, 1})
        assert pc.group_b == frozenset({2, 3})
        assert pc.start_round == 3
        assert pc.duration == 5


class TestMessageBus:
    """In-memory message routing with partition support."""

    def test_send_and_receive(self):
        bus = MessageBus(num_validators=4)
        bus.send(from_v=0, to_v=1, message="hello")
        pending = bus.pending_for(1)
        assert len(pending) == 1
        assert pending[0] == (0, "hello")

    def test_broadcast(self):
        bus = MessageBus(num_validators=4)
        bus.broadcast(from_v=0, message="block")
        for v in range(1, 4):
            pending = bus.pending_for(v)
            assert len(pending) == 1
            assert pending[0] == (0, "block")
        assert bus.pending_for(0) == []

    def test_deliver_all_clears_pending(self):
        bus = MessageBus(num_validators=4)
        bus.broadcast(from_v=0, message="block")
        delivered = bus.deliver_all()
        assert len(delivered) > 0
        for v in range(4):
            assert bus.pending_for(v) == []

    def test_partition_blocks_cross_group(self):
        bus = MessageBus(num_validators=4)
        pc = PartitionConfig(
            group_a=frozenset({0, 1}),
            group_b=frozenset({2, 3}),
            start_round=0,
        )
        bus.set_partition(pc)
        bus.broadcast(from_v=0, message="block")
        assert len(bus.pending_for(1)) == 1
        assert bus.pending_for(2) == []
        assert bus.pending_for(3) == []

    def test_clear_partition_restores_delivery(self):
        bus = MessageBus(num_validators=4)
        pc = PartitionConfig(
            group_a=frozenset({0, 1}),
            group_b=frozenset({2, 3}),
            start_round=0,
        )
        bus.set_partition(pc)
        bus.clear_partition()
        bus.broadcast(from_v=0, message="healed")
        assert len(bus.pending_for(2)) == 1
        assert len(bus.pending_for(3)) == 1
