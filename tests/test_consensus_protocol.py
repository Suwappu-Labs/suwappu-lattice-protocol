"""Tests for MysticetiProtocol (Spec D1a §2)."""

from ltp.consensus.protocol import MysticetiProtocol
from ltp.consensus.types import Block, Certificate, EquivocationProof


class TestPropose:
    """Block proposal logic."""

    def test_propose_creates_block(self):
        proto = MysticetiProtocol(validator_index=0, num_validators=4)
        block = proto.propose(round=1, payload=(b"tx1",))
        assert block.author == 0
        assert block.round == 1
        assert block.payload == (b"tx1",)
        assert isinstance(block.digest, bytes)

    def test_propose_round_0_has_no_parents(self):
        proto = MysticetiProtocol(validator_index=0, num_validators=4)
        block = proto.propose(round=0, payload=())
        assert block.parents == frozenset()

    def test_propose_references_known_parent_certs(self):
        """Propose at round 2 should reference certs from round 1."""
        proto = MysticetiProtocol(validator_index=0, num_validators=4)
        b1 = Block(author=1, round=1, payload=(), parents=frozenset(), timestamp_ms=1000)
        cert1 = Certificate(block=b1, signers=frozenset({0, 1, 2}))
        proto.receive_certificate(cert1)
        block = proto.propose(round=2, payload=(b"tx2",))
        assert cert1.digest in block.parents

    def test_propose_stored_in_dag(self):
        proto = MysticetiProtocol(validator_index=0, num_validators=4)
        block = proto.propose(round=1, payload=())
        assert proto.dag_store.get_block(block.digest) is block


class TestReceiveBlock:
    """Receiving and acknowledging blocks."""

    def test_receive_valid_block_returns_ack(self):
        proto = MysticetiProtocol(validator_index=0, num_validators=4)
        block = Block(author=1, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        ack = proto.receive_block(block)
        assert ack == 0

    def test_receive_block_stores_it(self):
        proto = MysticetiProtocol(validator_index=0, num_validators=4)
        block = Block(author=1, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        proto.receive_block(block)
        assert proto.dag_store.get_block(block.digest) is block

    def test_receive_duplicate_block_returns_none(self):
        proto = MysticetiProtocol(validator_index=0, num_validators=4)
        block = Block(author=1, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        proto.receive_block(block)
        ack = proto.receive_block(block)
        assert ack is None

    def test_receive_block_from_equivocator_returns_none(self):
        proto = MysticetiProtocol(validator_index=0, num_validators=4)
        b1 = Block(author=1, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        b2 = Block(author=1, round=1, payload=(b"tx2",), parents=frozenset(), timestamp_ms=1000)
        proto.receive_block(b1)
        proto.receive_block(b2)  # triggers equivocation detection
        b3 = Block(author=1, round=2, payload=(), parents=frozenset(), timestamp_ms=2000)
        assert proto.receive_block(b3) is None


class TestReceiveAck:
    """Ack accumulation and certificate formation."""

    def test_ack_accumulates(self):
        proto = MysticetiProtocol(validator_index=0, num_validators=4)
        block = proto.propose(round=1, payload=())
        cert = proto.receive_ack(block.digest, signer=1)
        assert cert is None  # only 2 acks so far (author + signer 1), need 3

    def test_ack_forms_certificate_at_quorum(self):
        """n=4, f=1, quorum=2f+1=3. Author's own propose counts as an ack."""
        proto = MysticetiProtocol(validator_index=0, num_validators=4)
        block = proto.propose(round=1, payload=())
        # Author (0) implicitly acks own block. Need 2 more.
        proto.receive_ack(block.digest, signer=1)
        cert = proto.receive_ack(block.digest, signer=2)
        assert cert is not None
        assert isinstance(cert, Certificate)
        assert cert.block is block
        assert len(cert.signers) >= 3

    def test_ack_below_quorum_returns_none(self):
        proto = MysticetiProtocol(validator_index=0, num_validators=4)
        block = proto.propose(round=1, payload=())
        cert = proto.receive_ack(block.digest, signer=1)
        assert cert is None


class TestEquivocation:
    """Equivocation detection."""

    def test_detect_equivocation(self):
        proto = MysticetiProtocol(validator_index=0, num_validators=4)
        b1 = Block(author=1, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        proto.receive_block(b1)
        b2 = Block(author=1, round=1, payload=(b"tx2",), parents=frozenset(), timestamp_ms=1000)
        proof = proto.detect_equivocation(b2)
        assert proof is not None
        assert isinstance(proof, EquivocationProof)
        assert proof.author == 1
        assert proof.round == 1

    def test_no_equivocation_for_new_block(self):
        proto = MysticetiProtocol(validator_index=0, num_validators=4)
        b = Block(author=1, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        proof = proto.detect_equivocation(b)
        assert proof is None

    def test_is_equivocator_after_detection(self):
        proto = MysticetiProtocol(validator_index=0, num_validators=4)
        b1 = Block(author=1, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        proto.receive_block(b1)
        b2 = Block(author=1, round=1, payload=(b"tx2",), parents=frozenset(), timestamp_ms=1000)
        proto.receive_block(b2)
        assert proto.is_equivocator(1) is True
        assert proto.is_equivocator(0) is False


class TestLeaderAndRound:
    """Leader election and round management."""

    def test_leader_for_round(self):
        proto = MysticetiProtocol(validator_index=0, num_validators=4)
        assert proto.leader_for_round(0) == 0
        assert proto.leader_for_round(1) == 1
        assert proto.leader_for_round(4) == 0
        assert proto.leader_for_round(7) == 3

    def test_skip_round(self):
        proto = MysticetiProtocol(validator_index=0, num_validators=4)
        proto.skip_round(5)
        assert proto.dag_store.blocks_at_round(5) == []
