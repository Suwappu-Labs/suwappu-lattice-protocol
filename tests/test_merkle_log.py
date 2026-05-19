"""
Tests for the CT-style Merkle log reference implementation (src/merkle_log/).

Validates the three properties the whitepaper §5.1.4 claims but the original
CommitmentLog did not demonstrate:
  1. Tamper-evidence  — any modification to a past record changes the root
  2. Inclusion proofs — O(log N) verifiable membership proofs
  3. Equivocation     — two valid STHs at same sequence with different roots
                        constitutes a cryptographic fork proof

Also includes an LTP integration test demonstrating that CommitmentRecord
bytes can be committed to the log and later proven.

Test classes:
  TestMerkleTree      — low-level tree: root, leaf, audit path correctness
  TestInclusionProof  — proof generation and verification
  TestSignedTreeHead  — STH signing, verification, tamper detection
  TestMerkleLog       — full log lifecycle: append → sign → prove → verify
  TestEquivocation    — fork / equivocation detection
  TestAppendOnly      — consistency proof: newer STH extends older STH
  TestLTPIntegration  — CommitmentRecord bytes round-trip through MerkleLog
"""

import json
import os

import pytest

from src.ltp import KeyPair
from src.ltp.merkle_log import InclusionProof, MerkleLog, MerkleTree, SignedTreeHead
from src.ltp.merkle_log.tree import (
    _audit_path,
    _compute_root,
    _internal_hash,
    _largest_pow2_below,
    _leaf_hash,
    _verify_inclusion,
)
from src.ltp.primitives import canonical_hash_bytes

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def operator_kp() -> KeyPair:
    return KeyPair.generate("log-operator-a")


@pytest.fixture(scope="module")
def operator_b_kp() -> KeyPair:
    return KeyPair.generate("log-operator-b")


@pytest.fixture
def log(operator_kp: KeyPair) -> MerkleLog:
    return MerkleLog(operator_kp.vk, operator_kp.sk)


# ---------------------------------------------------------------------------
# TestMerkleTree — low-level tree properties
# ---------------------------------------------------------------------------


class TestMerkleTree:
    def test_empty_tree_root_is_canonical(self):
        t = MerkleTree()
        assert t.size == 0
        assert t.root() == canonical_hash_bytes(b"")

    def test_single_leaf_root_equals_leaf_hash(self):
        t = MerkleTree()
        t.append(b"record")
        assert t.root() == _leaf_hash(b"record")

    def test_append_returns_sequential_indices(self):
        t = MerkleTree()
        assert t.append(b"a") == 0
        assert t.append(b"b") == 1
        assert t.append(b"c") == 2

    def test_append_changes_root(self):
        t = MerkleTree()
        t.append(b"data")
        root_before = t.root()
        t.append(b"more")
        assert t.root() != root_before

    def test_root_is_deterministic(self):
        t1, t2 = MerkleTree(), MerkleTree()
        for data in [b"x", b"y", b"z"]:
            t1.append(data)
            t2.append(data)
        assert t1.root() == t2.root()

    def test_tamper_any_leaf_changes_root(self):
        """Simulates an adversary modifying a committed record."""
        t = MerkleTree()
        for i in range(8):
            t.append(f"record-{i}".encode())
        original_root = t.root()

        # Directly modify an internal leaf (simulating storage tampering)
        t._leaves[3] = canonical_hash_bytes(b"tampered")
        assert t.root() != original_root

    def test_root_all_sizes_1_to_20(self):
        """root() must not raise for any non-zero tree size."""
        t = MerkleTree()
        for i in range(20):
            t.append(f"leaf-{i}".encode())
            _ = t.root()  # must not raise

    def test_audit_path_length_is_log_n(self):
        """Path length must be at most ceil(log2(n)) for all n."""
        import math

        t = MerkleTree()
        for i in range(1, 33):
            t.append(f"r{i}".encode())
            for idx in range(t.size):
                path = t.audit_path(idx)
                assert len(path) <= math.ceil(math.log2(t.size) + 1)

    def test_leaf_index_out_of_range_raises(self):
        t = MerkleTree()
        t.append(b"only")
        with pytest.raises(IndexError):
            t.audit_path(1)

    def test_largest_pow2_below(self):
        cases = {2: 1, 3: 2, 4: 2, 5: 4, 6: 4, 7: 4, 8: 4, 9: 8, 16: 8, 17: 16}
        for n, expected in cases.items():
            assert _largest_pow2_below(n) == expected, f"n={n}"

    def test_verify_inclusion_matches_root(self):
        """_verify_inclusion must reproduce the tree root for every leaf."""
        leaves_data = [f"d{i}".encode() for i in range(7)]
        leaves_hashed = [_leaf_hash(d) for d in leaves_data]
        root = _compute_root(leaves_hashed)
        for idx, data in enumerate(leaves_data):
            path = _audit_path(idx, leaves_hashed)
            reconstructed = _verify_inclusion(idx, len(leaves_data), _leaf_hash(data), path)
            assert reconstructed == root, f"Failed for index {idx}"


# ---------------------------------------------------------------------------
# TestInclusionProof — proof generation and verification
# ---------------------------------------------------------------------------


class TestInclusionProof:
    def test_valid_proof_verifies(self):
        t = MerkleTree()
        records = [f"rec-{i}".encode() for i in range(10)]
        for r in records:
            t.append(r)
        root = t.root()
        for idx, r in enumerate(records):
            proof = InclusionProof(
                leaf_index=idx,
                tree_size=t.size,
                audit_path=t.audit_path(idx),
                root_hash=root,
            )
            assert proof.verify(r, root), f"Proof failed for record {idx}"

    def test_wrong_data_fails(self):
        t = MerkleTree()
        t.append(b"original")
        root = t.root()
        proof = InclusionProof(leaf_index=0, tree_size=1, audit_path=[], root_hash=root)
        assert not proof.verify(b"tampered", root)

    def test_wrong_root_fails(self):
        t = MerkleTree()
        t.append(b"record")
        root = t.root()
        proof = InclusionProof(leaf_index=0, tree_size=1, audit_path=[], root_hash=root)
        wrong_root = canonical_hash_bytes(b"not-the-root")
        assert not proof.verify(b"record", wrong_root)

    def test_tampered_audit_path_fails(self):
        t = MerkleTree()
        for i in range(4):
            t.append(f"item-{i}".encode())
        root = t.root()
        proof = InclusionProof(
            leaf_index=0,
            tree_size=t.size,
            audit_path=t.audit_path(0),
            root_hash=root,
        )
        # Replace one sibling with garbage
        tampered_path = list(proof.audit_path)
        tampered_path[0] = canonical_hash_bytes(b"garbage")
        tampered_proof = InclusionProof(
            leaf_index=0, tree_size=t.size, audit_path=tampered_path, root_hash=root
        )
        assert not tampered_proof.verify(b"item-0", root)

    def test_single_leaf_proof(self):
        t = MerkleTree()
        t.append(b"solo")
        root = t.root()
        proof = InclusionProof(leaf_index=0, tree_size=1, audit_path=[], root_hash=root)
        assert proof.verify(b"solo", root)
        assert proof.path_length == 0

    def test_proof_path_length_property(self):
        t = MerkleTree()
        for i in range(8):
            t.append(f"e{i}".encode())
        proof = InclusionProof(
            leaf_index=0,
            tree_size=t.size,
            audit_path=t.audit_path(0),
            root_hash=t.root(),
        )
        assert proof.path_length == len(proof.audit_path)


# ---------------------------------------------------------------------------
# TestSignedTreeHead — STH signing and tamper detection
# ---------------------------------------------------------------------------


class TestSignedTreeHead:
    def test_sign_and_verify(self, operator_kp):
        root = canonical_hash_bytes(b"some-root")
        sth = SignedTreeHead.sign(
            sequence=0,
            tree_size=42,
            root_hash=root,
            operator_vk=operator_kp.vk,
            operator_sk=operator_kp.sk,
        )
        assert sth.verify()

    def test_tampered_root_fails(self, operator_kp):
        root = canonical_hash_bytes(b"real-root")
        sth = SignedTreeHead.sign(
            sequence=0,
            tree_size=10,
            root_hash=root,
            operator_vk=operator_kp.vk,
            operator_sk=operator_kp.sk,
        )
        # Flip root hash
        import dataclasses

        tampered = dataclasses.replace(sth, root_hash=canonical_hash_bytes(b"fake-root"))
        assert not tampered.verify()

    def test_tampered_tree_size_fails(self, operator_kp):
        root = canonical_hash_bytes(b"root")
        sth = SignedTreeHead.sign(
            sequence=0,
            tree_size=5,
            root_hash=root,
            operator_vk=operator_kp.vk,
            operator_sk=operator_kp.sk,
        )
        import dataclasses

        tampered = dataclasses.replace(sth, tree_size=999)
        assert not tampered.verify()

    def test_tampered_sequence_fails(self, operator_kp):
        root = canonical_hash_bytes(b"root")
        sth = SignedTreeHead.sign(
            sequence=3,
            tree_size=5,
            root_hash=root,
            operator_vk=operator_kp.vk,
            operator_sk=operator_kp.sk,
        )
        import dataclasses

        tampered = dataclasses.replace(sth, sequence=99)
        assert not tampered.verify()

    def test_different_operators_produce_different_sths(self, operator_kp, operator_b_kp):
        root = canonical_hash_bytes(b"same-root")
        sth_a = SignedTreeHead.sign(
            sequence=0,
            tree_size=1,
            root_hash=root,
            operator_vk=operator_kp.vk,
            operator_sk=operator_kp.sk,
        )
        sth_b = SignedTreeHead.sign(
            sequence=0,
            tree_size=1,
            root_hash=root,
            operator_vk=operator_b_kp.vk,
            operator_sk=operator_b_kp.sk,
        )
        assert sth_a.verify()
        assert sth_b.verify()
        assert sth_a.signature != sth_b.signature


# ---------------------------------------------------------------------------
# TestMerkleLog — full log lifecycle
# ---------------------------------------------------------------------------


class TestMerkleLog:
    def test_empty_log(self, log):
        assert log.size == 0
        assert log.latest_sth is None

    def test_append_increments_size(self, log):
        log.append(b"r1")
        log.append(b"r2")
        assert log.size == 2

    def test_publish_sth_returns_valid_sth(self, log):
        log.append(b"record")
        sth = log.publish_sth()
        assert sth.verify()
        assert sth.tree_size == log.size

    def test_sth_sequence_monotonically_increasing(self, log):
        for _ in range(3):
            log.append(b"data")
        sth0 = log.publish_sth()
        log.append(b"more")
        sth1 = log.publish_sth()
        assert sth1.sequence == sth0.sequence + 1

    def test_inclusion_proof_validates_against_sth(self, log):
        records = [f"entry-{i}".encode() for i in range(6)]
        for r in records:
            log.append(r)
        sth = log.publish_sth()
        for idx, r in enumerate(records):
            proof = log.inclusion_proof(idx)
            assert proof.verify(r, sth.root_hash), f"Proof failed for record {idx}"

    def test_inclusion_proof_fails_for_wrong_record(self, log):
        log.append(b"committed")
        sth = log.publish_sth()
        proof = log.inclusion_proof(0)
        assert not proof.verify(b"not-what-was-committed", sth.root_hash)

    def test_get_record_roundtrip(self, log):
        log.append(b"payload")
        assert log.get_record(0) == b"payload"

    def test_get_record_out_of_range(self, log):
        with pytest.raises(IndexError):
            log.get_record(999)

    def test_latest_sth_tracks_most_recent(self, log):
        log.append(b"a")
        sth1 = log.publish_sth()
        log.append(b"b")
        sth2 = log.publish_sth()
        assert log.latest_sth.sequence == sth2.sequence
        assert log.latest_sth.root_hash == sth2.root_hash

    def test_root_changes_after_append(self, log):
        log.append(b"first")
        sth1 = log.publish_sth()
        log.append(b"second")
        sth2 = log.publish_sth()
        assert sth1.root_hash != sth2.root_hash


# ---------------------------------------------------------------------------
# TestEquivocation — fork / equivocation detection
# ---------------------------------------------------------------------------


class TestEquivocation:
    def test_equivocation_detected(self, operator_kp):
        """
        Two valid STHs at the same sequence with different roots constitute a
        cryptographic equivocation proof.  detect_equivocation() must return True.
        """
        root_a = canonical_hash_bytes(b"honest-root")
        root_b = canonical_hash_bytes(b"forked-root")

        sth_a = SignedTreeHead.sign(
            sequence=5,
            tree_size=10,
            root_hash=root_a,
            operator_vk=operator_kp.vk,
            operator_sk=operator_kp.sk,
        )
        sth_b = SignedTreeHead.sign(
            sequence=5,
            tree_size=10,
            root_hash=root_b,
            operator_vk=operator_kp.vk,
            operator_sk=operator_kp.sk,
        )
        # Both signatures are valid — the operator signed both roots
        assert sth_a.verify()
        assert sth_b.verify()
        # But they're inconsistent at the same sequence — equivocation proven
        assert MerkleLog.detect_equivocation(sth_a, sth_b)

    def test_consistent_sths_not_equivocation(self, operator_kp):
        """Different sequence numbers → not equivocation (just progress)."""
        root = canonical_hash_bytes(b"root")
        sth_0 = SignedTreeHead.sign(
            sequence=0,
            tree_size=5,
            root_hash=root,
            operator_vk=operator_kp.vk,
            operator_sk=operator_kp.sk,
        )
        sth_1 = SignedTreeHead.sign(
            sequence=1,
            tree_size=6,
            root_hash=canonical_hash_bytes(b"new-root"),
            operator_vk=operator_kp.vk,
            operator_sk=operator_kp.sk,
        )
        assert not MerkleLog.detect_equivocation(sth_0, sth_1)

    def test_same_root_not_equivocation(self, operator_kp):
        """Same root at same sequence is redundant but not a fork."""
        root = canonical_hash_bytes(b"root")
        sth1 = SignedTreeHead.sign(
            sequence=3,
            tree_size=7,
            root_hash=root,
            operator_vk=operator_kp.vk,
            operator_sk=operator_kp.sk,
        )
        sth2 = SignedTreeHead.sign(
            sequence=3,
            tree_size=7,
            root_hash=root,
            operator_vk=operator_kp.vk,
            operator_sk=operator_kp.sk,
        )
        assert not MerkleLog.detect_equivocation(sth1, sth2)

    def test_invalid_sth_not_equivocation(self, operator_kp, operator_b_kp):
        """A forged / tampered STH that fails verify() cannot prove equivocation."""
        import dataclasses

        real_root = canonical_hash_bytes(b"real")
        sth_real = SignedTreeHead.sign(
            sequence=2,
            tree_size=4,
            root_hash=real_root,
            operator_vk=operator_kp.vk,
            operator_sk=operator_kp.sk,
        )
        # Tamper with the root — signature no longer valid
        sth_tampered = dataclasses.replace(sth_real, root_hash=canonical_hash_bytes(b"fake"))
        assert not sth_tampered.verify()
        assert not MerkleLog.detect_equivocation(sth_real, sth_tampered)


# ---------------------------------------------------------------------------
# TestAppendOnly — consistency between older and newer STHs
# ---------------------------------------------------------------------------


class TestAppendOnly:
    def test_newer_extends_older(self, log):
        for r in [b"a", b"b", b"c"]:
            log.append(r)
        sth_old = log.publish_sth()
        log.append(b"d")
        sth_new = log.publish_sth()
        assert log.verify_append_only(sth_old, sth_new)

    def test_reversed_sths_fail(self, log):
        for r in [b"x", b"y"]:
            log.append(r)
        sth1 = log.publish_sth()
        log.append(b"z")
        sth2 = log.publish_sth()
        assert not log.verify_append_only(sth2, sth1)

    def test_same_sequence_fails(self, log):
        log.append(b"once")
        sth = log.publish_sth()
        assert not log.verify_append_only(sth, sth)


# ---------------------------------------------------------------------------
# TestLTPIntegration — CommitmentRecord bytes → MerkleLog
# ---------------------------------------------------------------------------


class TestLTPIntegration:
    """
    Shows that LTP commitment records can be committed to the Merkle log and
    later proven.  This is the practical integration path: LTPProtocol.commit()
    returns a CommitmentRecord; the operator serializes it to JSON and appends
    it to the MerkleLog; the receiver verifies the inclusion proof.
    """

    def test_commitment_record_inclusion_proof(self, operator_kp):
        from src.ltp import (
            CommitmentNetwork,
            Entity,
            LTPProtocol,
        )
        from src.ltp import (
            KeyPair as LTPKeyPair,
        )

        # Set up a minimal LTP network
        alice = LTPKeyPair.generate("alice-integration")
        net = CommitmentNetwork()
        for nid, region in [
            ("node-1", "US-East"),
            ("node-2", "EU-West"),
            ("node-3", "AP-East"),
            ("node-4", "US-West"),
            ("node-5", "EU-East"),
            ("node-6", "AP-South"),
        ]:
            net.add_node(nid, region)
        protocol = LTPProtocol(net)

        # Commit an entity via LTP
        entity = Entity(content=b"merkle-log integration test", shape="text/plain")
        entity_id, record, _ = protocol.commit(entity, alice, n=6, k=3)

        # Serialize the commitment record to bytes (what goes into the log)
        record_bytes = json.dumps(
            {
                "entity_id": record.entity_id,
                "sender_id": record.sender_id,
                "shard_map_root": record.shard_map_root,
                "shape_hash": record.shape_hash,
                "timestamp": record.timestamp,
            },
            sort_keys=True,
        ).encode()

        # Append to Merkle log and publish STH
        log = MerkleLog(operator_kp.vk, operator_kp.sk)
        idx = log.append(record_bytes)
        sth = log.publish_sth()

        # Receiver verifies: (a) STH signature, (b) inclusion proof
        assert sth.verify(), "Operator STH signature must be valid"

        proof = log.inclusion_proof(idx)
        assert proof.verify(record_bytes, sth.root_hash), (
            "Inclusion proof must confirm commitment record is in the log"
        )

    def test_multiple_entities_all_provable(self, operator_kp):
        """All committed records must be simultaneously provable."""
        log = MerkleLog(operator_kp.vk, operator_kp.sk)
        records = [
            json.dumps({"entity_id": f"sha3-256:{'ab' * 32}", "index": i}).encode()
            for i in range(12)
        ]
        indices = [log.append(r) for r in records]
        sth = log.publish_sth()

        for idx, r in zip(indices, records):
            proof = log.inclusion_proof(idx)
            assert proof.verify(r, sth.root_hash), f"Proof failed for record {idx}"

    def test_tampered_record_detected(self, operator_kp):
        """A receiver presenting a tampered record must fail the inclusion proof."""
        log = MerkleLog(operator_kp.vk, operator_kp.sk)
        original = b'{"entity_id": "sha3-256:aabbcc", "size": 1024}'
        log.append(original)
        sth = log.publish_sth()
        proof = log.inclusion_proof(0)

        tampered = b'{"entity_id": "sha3-256:aabbcc", "size": 99999}'
        assert not proof.verify(tampered, sth.root_hash)
