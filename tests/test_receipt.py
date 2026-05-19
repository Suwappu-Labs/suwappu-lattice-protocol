"""Tests for Approval Receipts (receipt.py)."""

import time

import pytest

from src.ltp import (
    CommitmentLog,
    CommitmentNetwork,
    CommitmentRecord,
    Entity,
    KeyPair,
    LTPProtocol,
    reset_poc_state,
)
from src.ltp.receipt import ApprovalReceipt, ReceiptType


@pytest.fixture(autouse=True)
def fresh_state():
    reset_poc_state()
    yield
    reset_poc_state()


@pytest.fixture
def alice():
    return KeyPair.generate("alice")


@pytest.fixture
def bob():
    return KeyPair.generate("bob")


@pytest.fixture
def committed_state(alice):
    """Create a committed entity and return (entity_id, record, sth, network)."""
    net = CommitmentNetwork()
    for i in range(3):
        net.add_node(f"node-{i}", "us-east-1")
    proto = LTPProtocol(net)
    entity = Entity(content=b"test-content", shape="text/plain")
    eid, record, cek = proto.commit(entity, alice)
    sth = net.log.latest_sth
    return eid, record, sth, net


class TestReceiptCreation:
    """Test receipt creation and signing."""

    def test_for_commit(self, alice, committed_state):
        eid, record, sth, net = committed_state
        receipt = ApprovalReceipt.for_commit(
            entity_id=eid,
            record=record,
            sth=sth,
            signer_kp=alice,
            signer_role="operator",
            sequence=0,
            target_chain_id="base-testnet",
        )
        assert receipt.receipt_type == ReceiptType.COMMIT
        assert receipt.entity_id == eid
        assert receipt.sequence == 0
        assert receipt.target_chain_id == "base-testnet"
        assert receipt.signature != b""
        assert receipt.receipt_id != ""

    def test_for_materialize(self, alice, committed_state):
        eid, record, sth, net = committed_state
        receipt = ApprovalReceipt.for_materialize(
            entity_id=eid,
            record=record,
            sth=sth,
            signer_kp=alice,
            signer_role="operator",
            sequence=1,
            target_chain_id="base-testnet",
        )
        assert receipt.receipt_type == ReceiptType.MATERIALIZE

    def test_receipt_id_stability(self, alice, committed_state):
        """Same inputs → same receipt_id (via canonical encoding)."""
        eid, record, sth, net = committed_state
        receipt = ApprovalReceipt.for_commit(
            entity_id=eid,
            record=record,
            sth=sth,
            signer_kp=alice,
            signer_role="operator",
            sequence=0,
            target_chain_id="base-testnet",
        )
        recomputed = receipt.compute_receipt_id()
        assert receipt.receipt_id == recomputed


class TestReceiptVerification:
    """Test receipt signature verification."""

    def test_verify_valid(self, alice, committed_state):
        eid, record, sth, net = committed_state
        receipt = ApprovalReceipt.for_commit(
            entity_id=eid,
            record=record,
            sth=sth,
            signer_kp=alice,
            signer_role="operator",
            sequence=0,
            target_chain_id="base-testnet",
        )
        assert receipt.verify(alice.vk)

    def test_verify_wrong_signer(self, alice, bob, committed_state):
        eid, record, sth, net = committed_state
        receipt = ApprovalReceipt.for_commit(
            entity_id=eid,
            record=record,
            sth=sth,
            signer_kp=alice,
            signer_role="operator",
            sequence=0,
            target_chain_id="base-testnet",
        )
        assert not receipt.verify(bob.vk)

    def test_tamper_detection(self, alice, committed_state):
        eid, record, sth, net = committed_state
        receipt = ApprovalReceipt.for_commit(
            entity_id=eid,
            record=record,
            sth=sth,
            signer_kp=alice,
            signer_role="operator",
            sequence=0,
            target_chain_id="base-testnet",
        )
        # Tamper with entity_id
        receipt.entity_id = "tampered" + receipt.entity_id[8:]
        assert not receipt.verify(alice.vk)

    def test_tamper_receipt_id(self, alice, committed_state):
        eid, record, sth, net = committed_state
        receipt = ApprovalReceipt.for_commit(
            entity_id=eid,
            record=record,
            sth=sth,
            signer_kp=alice,
            signer_role="operator",
            sequence=0,
            target_chain_id="base-testnet",
        )
        receipt.receipt_id = "fake-receipt-id"
        assert not receipt.verify(alice.vk)


class TestAnchorDigest:
    """Test anchor_digest for on-chain anchoring."""

    def test_anchor_digest_is_32_bytes(self, alice, committed_state):
        eid, record, sth, net = committed_state
        receipt = ApprovalReceipt.for_commit(
            entity_id=eid,
            record=record,
            sth=sth,
            signer_kp=alice,
            signer_role="operator",
            sequence=0,
            target_chain_id="base-testnet",
        )
        digest = receipt.anchor_digest()
        assert isinstance(digest, bytes)
        assert len(digest) == 32

    def test_anchor_digest_stability(self, alice, committed_state):
        eid, record, sth, net = committed_state
        receipt = ApprovalReceipt.for_commit(
            entity_id=eid,
            record=record,
            sth=sth,
            signer_kp=alice,
            signer_role="operator",
            sequence=0,
            target_chain_id="base-testnet",
        )
        assert receipt.anchor_digest() == receipt.anchor_digest()

    def test_anchor_digest_uniqueness(self, alice, committed_state):
        eid, record, sth, net = committed_state
        r1 = ApprovalReceipt.for_commit(
            entity_id=eid,
            record=record,
            sth=sth,
            signer_kp=alice,
            signer_role="operator",
            sequence=0,
            target_chain_id="base-testnet",
        )
        r2 = ApprovalReceipt.for_commit(
            entity_id=eid,
            record=record,
            sth=sth,
            signer_kp=alice,
            signer_role="operator",
            sequence=1,
            target_chain_id="base-testnet",
        )
        assert r1.anchor_digest() != r2.anchor_digest()


class TestReceiptTypes:
    """Test all receipt types."""

    def test_all_types_defined(self):
        assert ReceiptType.COMMIT.value == "COMMIT"
        assert ReceiptType.MATERIALIZE.value == "MATERIALIZE"
        assert ReceiptType.SHARD_AUDIT_PASS.value == "SHARD_AUDIT_PASS"
        assert ReceiptType.KEY_ROTATION.value == "KEY_ROTATION"
        assert ReceiptType.DELETION.value == "DELETION"
        assert ReceiptType.GOVERNANCE.value == "GOVERNANCE"
