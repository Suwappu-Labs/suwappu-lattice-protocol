"""Tests for DAGStore (Spec D1a §2)."""

from ltp.consensus.dag_store import DAGStore
from ltp.consensus.types import Block, Certificate


def _block(
    author: int,
    round: int,
    payload: tuple[bytes, ...] = (),
    parents: frozenset[bytes] = frozenset(),
) -> Block:
    return Block(author=author, round=round, payload=payload, parents=parents, timestamp_ms=1000)


def _cert(block: Block, signers: frozenset[int]) -> Certificate:
    return Certificate(block=block, signers=signers)


class TestDAGStoreBlocks:
    """Block storage and retrieval."""

    def test_add_and_get_block(self):
        dag = DAGStore()
        b = _block(0, 1)
        dag.add_block(b)
        assert dag.get_block(b.digest) is b

    def test_get_missing_block_returns_none(self):
        dag = DAGStore()
        assert dag.get_block(b"\x00" * 32) is None

    def test_reject_duplicate_block_same_round_author(self):
        dag = DAGStore()
        b1 = _block(0, 1, payload=(b"tx1",))
        b2 = _block(0, 1, payload=(b"tx2",))
        dag.add_block(b1)
        added = dag.add_block(b2)
        assert added is False
        assert dag.get_block(b1.digest) is b1

    def test_blocks_at_round(self):
        dag = DAGStore()
        b0 = _block(0, 1)
        b1 = _block(1, 1)
        b2 = _block(0, 2)
        dag.add_block(b0)
        dag.add_block(b1)
        dag.add_block(b2)
        round_1 = dag.blocks_at_round(1)
        assert len(round_1) == 2
        assert set(b.author for b in round_1) == {0, 1}

    def test_blocks_at_empty_round(self):
        dag = DAGStore()
        assert dag.blocks_at_round(99) == []


class TestDAGStoreCertificates:
    """Certificate storage and quorum queries."""

    def test_add_and_get_certificate(self):
        dag = DAGStore()
        b = _block(0, 1)
        cert = _cert(b, frozenset({0, 1, 2}))
        dag.add_certificate(cert)
        assert dag.get_certificate(0, 1) is cert

    def test_get_missing_certificate_returns_none(self):
        dag = DAGStore()
        assert dag.get_certificate(0, 1) is None

    def test_certificates_at_round(self):
        dag = DAGStore()
        b0 = _block(0, 1)
        b1 = _block(1, 1)
        c0 = _cert(b0, frozenset({0, 1, 2}))
        c1 = _cert(b1, frozenset({0, 1, 2}))
        dag.add_certificate(c0)
        dag.add_certificate(c1)
        certs = dag.certificates_at_round(1)
        assert len(certs) == 2

    def test_has_quorum_certificates(self):
        """2f+1 certificates at a round means quorum. For n=4, f=1, need 3."""
        dag = DAGStore()
        for author in range(3):
            b = _block(author, 1)
            dag.add_certificate(_cert(b, frozenset({0, 1, 2})))
        assert dag.has_quorum_certificates(round=1, quorum_threshold=3) is True

    def test_no_quorum_certificates(self):
        dag = DAGStore()
        b = _block(0, 1)
        dag.add_certificate(_cert(b, frozenset({0, 1, 2})))
        assert dag.has_quorum_certificates(round=1, quorum_threshold=3) is False

    def test_certificates_at_empty_round(self):
        dag = DAGStore()
        assert dag.certificates_at_round(99) == []
