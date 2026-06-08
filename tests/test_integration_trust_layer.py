"""
End-to-end integration tests for the SUWAPPU Pre-Blockchain Trust Packaging Layer.

Tests the full pipeline from Entity → Commit → Receipt → Envelope → Anchor,
verifying that all components interoperate correctly and don't interfere with
the existing LTP COMMIT → LATTICE → MATERIALIZE data path.
"""

import time

import pytest

from src.ltp import (
    ApprovalReceipt,
    CommitmentNetwork,
    Entity,
    KeyPair,
    LTPProtocol,
    SequenceTracker,
    SignedEnvelope,
    reset_poc_state,
)
from src.ltp.anchor import AnchorSubmission, EntityState, validate_transition
from src.ltp.domain import DOMAIN_COMMIT_RECORD
from src.ltp.evidence import EvidenceBundle
from src.ltp.governance import ApprovalRule, SignerEntry, SignerPolicy
from src.ltp.merkle_log.portable_proof import TreeType
from src.ltp.receipt import ReceiptType
from src.ltp.verify import (
    verify_commitment_chain,
    verify_envelope,
    verify_merkle_proof,
    verify_receipt,
    verify_sth,
)


@pytest.fixture(autouse=True)
def fresh_state():
    reset_poc_state()
    yield
    reset_poc_state()


@pytest.fixture
def network_with_nodes():
    net = CommitmentNetwork()
    for i in range(4):
        net.add_node(f"node-{i}", "us-east-1")
    return net


@pytest.fixture
def alice():
    return KeyPair.generate("alice")


@pytest.fixture
def bob():
    return KeyPair.generate("bob")


# ── Core pipeline: trust layer does not break data path ──────────────────


class TestTrustLayerDoesNotBreakDataPath:
    """Verify COMMIT → LATTICE → MATERIALIZE still works with trust layer active."""

    def test_full_data_path_unchanged(self, alice, network_with_nodes):
        proto = LTPProtocol(network_with_nodes)
        entity = Entity(content=b"integration test content", shape="text/plain")

        eid, record, cek = proto.commit(entity, alice)

        # Generate trust artifacts (should not affect internal state)
        sth = network_with_nodes.log.latest_sth
        receipt = ApprovalReceipt.for_commit(
            entity_id=eid,
            record=record,
            sth=sth,
            signer_kp=alice,
            signer_role="operator",
            sequence=0,
            target_chain_id="base-testnet",
        )
        envelope = record.to_envelope(alice.vk, alice.sk, "alice")

        # Verify trust artifacts
        assert receipt.verify(alice.vk)
        assert envelope.verify()

        # LATTICE + MATERIALIZE still work
        sealed = proto.lattice(eid, record, cek, alice)
        recovered = proto.materialize(sealed, alice)
        assert recovered == entity.content

    def test_multiple_entities_each_get_receipts(self, alice, network_with_nodes):
        proto = LTPProtocol(network_with_nodes)
        tracker = SequenceTracker(chain_id="base-testnet")
        receipts = []
        future = time.time() + 3600

        for i in range(3):
            entity = Entity(content=f"entity-{i}".encode(), shape="text/plain")
            eid, record, cek = proto.commit(entity, alice)
            sth = network_with_nodes.log.latest_sth

            receipt = ApprovalReceipt.for_commit(
                entity_id=eid,
                record=record,
                sth=sth,
                signer_kp=alice,
                signer_role="operator",
                sequence=i,
                target_chain_id="base-testnet",
            )
            ok, _ = tracker.validate_and_advance(
                alice.vk,
                i,
                "base-testnet",
                future,
            )
            assert ok
            assert receipt.verify(alice.vk)
            receipts.append(receipt)

        assert len(receipts) == 3
        assert len({r.receipt_id for r in receipts}) == 3  # All unique


# ── Full commit-to-anchor pipeline ────────────────────────────────────────


class TestCommitToAnchorPipeline:
    """Full pipeline: commit → receipt → envelope → anchor submission."""

    def test_full_pipeline(self, alice, network_with_nodes):
        proto = LTPProtocol(network_with_nodes)
        entity = Entity(content=b"anchor-test", shape="text/plain")

        # Step 1: Commit
        eid, record, cek = proto.commit(entity, alice)
        sth = network_with_nodes.log.latest_sth

        # Step 2: Receipt
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
        assert len(receipt.anchor_digest()) == 32

        # Step 3: Envelope
        envelope = record.to_envelope(alice.vk, alice.sk, "alice")
        assert envelope.verify()

        # Step 4: Portable proof
        proof = network_with_nodes.log.get_portable_proof(eid)
        assert proof.verify()

        # Step 5: State machine
        ok, _ = validate_transition(EntityState.UNKNOWN, EntityState.COMMITTED)
        assert ok
        ok, _ = validate_transition(EntityState.COMMITTED, EntityState.ANCHORED)
        assert ok

        # Step 6: Anchor submission
        from src.ltp.primitives import canonical_hash_bytes

        sub = AnchorSubmission.from_receipt(
            receipt=receipt,
            policy_hash_bytes=canonical_hash_bytes(b"default-policy"),
            target_chain_id_int=10143,
        )
        calldata = sub.to_calldata()
        assert len(calldata) == 32 + 32 + 32 + 32 + 8 + 8 + 8 + 4 + len("COMMIT".encode())
        assert calldata[:32] == receipt.anchor_digest()

    def test_commit_then_materialize_receipts(self, alice, network_with_nodes):
        proto = LTPProtocol(network_with_nodes)
        entity = Entity(content=b"materialize-test", shape="text/plain")

        eid, record, cek = proto.commit(entity, alice)
        sth = network_with_nodes.log.latest_sth

        commit_receipt = ApprovalReceipt.for_commit(
            entity_id=eid,
            record=record,
            sth=sth,
            signer_kp=alice,
            signer_role="operator",
            sequence=0,
            target_chain_id="base-testnet",
        )

        sealed = proto.lattice(eid, record, cek, alice)
        recovered = proto.materialize(sealed, alice)
        assert recovered == entity.content

        mat_receipt = ApprovalReceipt.for_materialize(
            entity_id=eid,
            record=record,
            sth=sth,
            signer_kp=alice,
            signer_role="operator",
            sequence=1,
            target_chain_id="base-testnet",
        )

        assert commit_receipt.verify(alice.vk)
        assert mat_receipt.verify(alice.vk)
        assert commit_receipt.receipt_id != mat_receipt.receipt_id
        assert commit_receipt.anchor_digest() != mat_receipt.anchor_digest()


# ── Verification SDK integration ─────────────────────────────────────────


class TestVerificationSDKIntegration:
    """Pure verification functions against real protocol outputs."""

    def test_all_verifiers_pass_for_valid_artifacts(self, alice, network_with_nodes):
        proto = LTPProtocol(network_with_nodes)
        entity = Entity(content=b"verify-all", shape="text/plain")
        eid, record, cek = proto.commit(entity, alice)
        sth = network_with_nodes.log.latest_sth

        receipt = ApprovalReceipt.for_commit(
            entity_id=eid,
            record=record,
            sth=sth,
            signer_kp=alice,
            signer_role="operator",
            sequence=0,
            target_chain_id="base-testnet",
        )
        envelope = record.to_envelope(alice.vk, alice.sk, "alice")
        proof = network_with_nodes.log.get_portable_proof(eid)

        assert verify_envelope(envelope).valid
        assert verify_receipt(receipt).valid
        assert verify_merkle_proof(proof).valid
        assert verify_sth(sth).valid

    def test_verify_envelope_result_has_metadata(self, alice, network_with_nodes):
        proto = LTPProtocol(network_with_nodes)
        entity = Entity(content=b"metadata-test", shape="text/plain")
        eid, record, cek = proto.commit(entity, alice)
        envelope = record.to_envelope(alice.vk, alice.sk, "alice")

        result = verify_envelope(envelope)
        assert result.valid
        assert result.artifact == "envelope"
        assert "signer_kid" in result.details
        assert result.details["payload_type"] == "commitment-record"

    def test_verify_receipt_result_has_metadata(self, alice, network_with_nodes):
        proto = LTPProtocol(network_with_nodes)
        entity = Entity(content=b"receipt-meta", shape="text/plain")
        eid, record, cek = proto.commit(entity, alice)
        sth = network_with_nodes.log.latest_sth
        receipt = ApprovalReceipt.for_commit(
            entity_id=eid,
            record=record,
            sth=sth,
            signer_kp=alice,
            signer_role="operator",
            sequence=0,
            target_chain_id="base-testnet",
        )

        result = verify_receipt(receipt)
        assert result.valid
        assert result.artifact == "receipt"
        assert result.details["receipt_type"] == "COMMIT"

    def test_verify_chain_of_records(self, alice, network_with_nodes):
        proto = LTPProtocol(network_with_nodes)
        records, proofs = [], []

        for i in range(3):
            entity = Entity(content=f"chain-{i}".encode(), shape="text/plain")
            eid, record, cek = proto.commit(entity, alice)
            proof = network_with_nodes.log.get_portable_proof(eid)
            records.append(record)
            proofs.append(proof)

        result = verify_commitment_chain(records, proofs)
        assert result.valid
        assert result.details["chain_length"] == 3

    def test_verify_fails_tampered_envelope(self, alice, network_with_nodes):
        proto = LTPProtocol(network_with_nodes)
        entity = Entity(content=b"tamper-test", shape="text/plain")
        eid, record, cek = proto.commit(entity, alice)
        envelope = record.to_envelope(alice.vk, alice.sk, "alice")

        envelope.payload = b"tampered"
        result = verify_envelope(envelope)
        assert not result.valid
        assert result.artifact == "envelope"


# ── Governance + Policy integration ───────────────────────────────────────


class TestGovernancePolicyIntegration:
    """Policy-gated receipt verification."""

    def test_policy_gates_receipt_verification(self, alice, bob, network_with_nodes):
        proto = LTPProtocol(network_with_nodes)
        entity = Entity(content=b"policy-test", shape="text/plain")
        eid, record, cek = proto.commit(entity, alice)
        sth = network_with_nodes.log.latest_sth

        policy = SignerPolicy(
            policy_id="",
            policy_version=1,
            signers=[
                SignerEntry(
                    signer_id="alice",
                    vk=alice.vk,
                    roles={"operator"},
                    valid_from=0,
                    valid_until=10000,
                ),
            ],
            approval_rules=[
                ApprovalRule(
                    action_type="COMMIT",
                    required_roles={"operator"},
                    min_signers=1,
                ),
            ],
        )
        policy.sign_policy(alice.sk)

        receipt = ApprovalReceipt.for_commit(
            entity_id=eid,
            record=record,
            sth=sth,
            signer_kp=alice,
            signer_role="operator",
            sequence=0,
            target_chain_id="base-testnet",
        )

        # Alice's receipt should pass policy check
        result = verify_receipt(receipt, policy=policy)
        assert result.valid

    def test_unauthorized_signer_fails_policy(self, alice, bob, network_with_nodes):
        proto = LTPProtocol(network_with_nodes)
        entity = Entity(content=b"auth-test", shape="text/plain")
        eid, record, cek = proto.commit(entity, bob)  # Bob commits
        sth = network_with_nodes.log.latest_sth

        # Policy only authorizes alice as operator
        policy = SignerPolicy(
            policy_id="",
            policy_version=1,
            signers=[
                SignerEntry(
                    signer_id="alice",
                    vk=alice.vk,
                    roles={"operator"},
                    valid_from=0,
                    valid_until=10000,
                ),
            ],
            approval_rules=[
                ApprovalRule(
                    action_type="COMMIT",
                    required_roles={"operator"},
                ),
            ],
        )
        policy.sign_policy(alice.sk)

        # Bob signs the receipt
        receipt = ApprovalReceipt.for_commit(
            entity_id=eid,
            record=record,
            sth=sth,
            signer_kp=bob,
            signer_role="operator",
            sequence=0,
            target_chain_id="base-testnet",
        )

        result = verify_receipt(receipt, policy=policy)
        assert not result.valid
        assert "not authorized" in result.reason


# ── Evidence Bundle integration ───────────────────────────────────────────


class TestEvidenceBundleIntegration:
    """Evidence bundle aggregates all artifacts for a complete audit trail."""

    def test_bundle_covers_full_action(self, alice, network_with_nodes):
        proto = LTPProtocol(network_with_nodes)
        entity = Entity(content=b"evidence-test", shape="text/plain")
        eid, record, cek = proto.commit(entity, alice)
        sth = network_with_nodes.log.latest_sth

        receipt = ApprovalReceipt.for_commit(
            entity_id=eid,
            record=record,
            sth=sth,
            signer_kp=alice,
            signer_role="operator",
            sequence=0,
            target_chain_id="base-testnet",
        )
        proof = network_with_nodes.log.get_portable_proof(eid)

        bundle = EvidenceBundle.create(
            entity_id=eid,
            receipts=[receipt.canonical_bytes_unsigned()],
            merkle_proofs=[proof.canonical_bytes()],
            sth_snapshots=[sth.canonical_bytes()],
            policy_hash="default",
            metadata={"action": "COMMIT", "chain": "base-testnet"},
        )

        assert bundle.bundle_id != ""
        assert bundle.bundle_id == bundle.compute_bundle_id()  # Stable
        assert len(bundle.receipts) == 1
        assert len(bundle.merkle_proofs) == 1
        assert len(bundle.sth_snapshots) == 1
        assert bundle.entity_id == eid

    def test_bundle_id_changes_on_add(self, alice, network_with_nodes):
        proto = LTPProtocol(network_with_nodes)
        entity = Entity(content=b"bundle-change-test", shape="text/plain")
        eid, record, cek = proto.commit(entity, alice)

        bundle = EvidenceBundle.create(entity_id=eid)
        id_before = bundle.bundle_id
        bundle.add_sth_snapshot(b"snapshot-bytes")
        assert bundle.bundle_id != id_before
