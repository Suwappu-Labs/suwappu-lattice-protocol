"""
MerkleLog — high-level CT-style append-only commitment log.

Wraps MerkleTree with operator signing (STH publication), inclusion proof
generation, and equivocation detection.  This is the reference implementation
of the LTP §5.1.4 recommended deployment: a CT-style multi-operator Merkle log.

Minimum conformance contract (per whitepaper §5.1.4):
  MUST  append records to an append-only BLAKE2b-256 Merkle tree
  MUST  publish ML-DSA-65 Signed Tree Heads (STHs)
  MUST  produce O(log N) inclusion proofs for any committed record
  MUST  detect operator equivocation via detect_equivocation()
  SHOULD exchange STHs with at least one independent operator

Single-operator usage (sufficient for testing and private deployments):
  log = MerkleLog(operator_vk, operator_sk)
  idx = log.append(record_bytes)
  sth = log.publish_sth()
  proof = log.inclusion_proof(idx)
  assert proof.verify(record_bytes, sth.root_hash)

Multi-operator gossip (production):
  Each operator runs its own MerkleLog instance.  Participants exchange STHs
  and call detect_equivocation(sth_a, sth_b) when they receive a new STH.
  Any equivocation is cryptographic proof of operator misbehavior, no further
  investigation needed.
"""

from __future__ import annotations

from .tree import MerkleTree
from .sth import SignedTreeHead
from .proof import InclusionProof

__all__ = ["MerkleLog"]


class MerkleLog:
    """
    CT-style append-only Merkle commitment log.

    Each MerkleLog instance is operated by a single keypair (operator_vk /
    operator_sk).  In a multi-operator deployment, independent instances are
    cross-checked via STH gossip.

    Thread safety (LTP-A-028 in docs/security/audits/internal/SECURITY_AUDIT_2026-05-15.md):
        ``append`` and ``publish_sth`` acquire an internal ``threading.Lock``
        so concurrent calls from multiple threads are safe — the lock
        serializes tree mutation and STH sequence assignment.  Read-only
        accessors (``size``, ``latest_sth``, ``inclusion_proof``) do not
        take the lock; callers that read during concurrent appends may
        observe transient states.  For strong read-after-write guarantees
        across threads, call ``publish_sth`` and pass the returned STH to
        the reader.
    """

    def __init__(self, operator_vk: bytes, operator_sk: bytes) -> None:
        """
        Args:
            operator_vk: ML-DSA-65 verification key (public — included in every STH).
            operator_sk: ML-DSA-65 signing key (private — never leaves this object).
        """
        import threading
        self._tree = MerkleTree()
        self._records: list[bytes] = []   # raw record bytes, parallel to tree leaves
        self._operator_vk = operator_vk
        self._operator_sk = operator_sk
        self._sths: list[SignedTreeHead] = []
        self._sequence: int = 0
        # Serializes mutators (append / publish_sth) so concurrent
        # producers can't race on tree state or STH sequence.
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Core log operations
    # ------------------------------------------------------------------

    @property
    def size(self) -> int:
        """Number of records committed to the log."""
        return self._tree.size

    @property
    def latest_sth(self) -> SignedTreeHead | None:
        """Most recently published STH, or None if publish_sth() has not been called."""
        return self._sths[-1] if self._sths else None

    def append(self, record: bytes) -> int:
        """
        Append a raw record to the log.

        The record is stored verbatim; the tree stores its leaf hash.
        Returns the 0-based leaf index, which is used for inclusion proofs.
        Thread-safe — see class docstring.
        """
        with self._lock:
            idx = self._tree.append(record)
            self._records.append(record)
            return idx

    def publish_sth(self) -> SignedTreeHead:
        """
        Sign the current tree state and publish a Signed Tree Head.

        The STH sequence number increments monotonically with each call.
        Callers SHOULD publish an STH after each batch of appends so that
        receivers can detect any log inconsistency.

        Returns the signed STH (also stored in self._sths). Thread-safe —
        see class docstring.
        """
        with self._lock:
            sth = SignedTreeHead.sign(
                sequence=self._sequence,
                tree_size=self._tree.size,
                root_hash=self._tree.root(),
                operator_vk=self._operator_vk,
                operator_sk=self._operator_sk,
            )
            self._sths.append(sth)
            self._sequence += 1
            return sth

    def inclusion_proof(self, index: int) -> InclusionProof:
        """
        Generate an O(log N) inclusion proof for the record at index.

        The proof is relative to the current tree root.  Recipients SHOULD
        verify it against a trusted STH root_hash rather than a self-reported root.

        Raises IndexError if index is out of range.
        """
        return InclusionProof(
            leaf_index=index,
            tree_size=self._tree.size,
            audit_path=self._tree.audit_path(index),
            root_hash=self._tree.root(),
        )

    def get_record(self, index: int) -> bytes:
        """Return the raw record bytes stored at index."""
        if not 0 <= index < len(self._records):
            raise IndexError(f"Record index {index} out of range (size={self.size})")
        return self._records[index]

    # ------------------------------------------------------------------
    # Fork / equivocation detection
    # ------------------------------------------------------------------

    @staticmethod
    def detect_equivocation(
        sth1: SignedTreeHead, sth2: SignedTreeHead
    ) -> bool:
        """
        Return True if the two STHs constitute a cryptographic equivocation proof.

        An equivocation occurs when a log operator publishes two valid, signed
        STHs at the same sequence number with different root hashes.  This proves
        the operator presented inconsistent views of the log to different parties
        — a protocol violation.

        The two STHs together form a self-contained evidence bundle: any third
        party can verify both signatures and observe the root-hash mismatch,
        without needing to inspect the full log.

        Requirements for equivocation:
          - Same sequence number
          - Both signatures must verify (both are validly signed)
          - Different root hashes
        """
        if sth1.sequence != sth2.sequence:
            return False
        if not sth1.verify() or not sth2.verify():
            return False
        return sth1.root_hash != sth2.root_hash

    # ------------------------------------------------------------------
    # Consistency check (append-only verification)
    # ------------------------------------------------------------------

    def consistency_proof(self, old_size: int) -> list[bytes]:
        """
        Generate an O(log N) consistency proof (RFC 6962 §2.1.2).

        Proves the first `old_size` leaves haven't changed since the tree
        had that many leaves.
        """
        return self._tree.consistency_proof(old_size)

    def verify_append_only(
        self, older_sth: SignedTreeHead, newer_sth: SignedTreeHead
    ) -> bool:
        """
        Verify that newer_sth represents an append-only extension of older_sth.

        Uses O(log N) RFC 6962 consistency proofs rather than recomputing
        from stored leaves.

        Returns True if the append-only invariant is not violated.
        """
        if not older_sth.verify() or not newer_sth.verify():
            return False
        if older_sth.sequence >= newer_sth.sequence:
            return False
        if older_sth.tree_size > newer_sth.tree_size:
            return False
        if older_sth.tree_size == 0:
            from ..primitives import canonical_hash_bytes
            return older_sth.root_hash == canonical_hash_bytes(b'')
        from .tree import verify_consistency
        proof = self._tree.consistency_proof(older_sth.tree_size)
        return verify_consistency(
            older_sth.tree_size,
            newer_sth.tree_size,
            older_sth.root_hash,
            newer_sth.root_hash,
            proof,
        )
