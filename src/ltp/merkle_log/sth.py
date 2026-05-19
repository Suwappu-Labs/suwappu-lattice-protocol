"""
Signed Tree Head (STH) for the Merkle log.

Each STH is a ML-DSA-65-signed snapshot of the log state, binding the operator's
identity to a specific (sequence, tree_size, root_hash) triple.

STHs serve two critical functions:
  1. Tamper detection: any modification to log history changes root_hash,
     which invalidates the ML-DSA signature covering it.
  2. Equivocation detection: two valid STHs with the same sequence number
     but different root hashes are cryptographic proof that the operator
     presented inconsistent views of the log (a fork).  The pair of STHs
     constitutes a self-contained, unforgeable evidence bundle.

Signable payload (canonical byte encoding):
  sequence (8 bytes, big-endian uint64)
  || tree_size (8 bytes, big-endian uint64)
  || timestamp (8 bytes, IEEE 754 double big-endian)
  || root_hash (32 bytes, BLAKE2b-256)

The timestamp is included so STHs are not replayable across time even if an
operator signs the same tree state twice.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass

from ..primitives import MLDSA

__all__ = ["SignedTreeHead"]


@dataclass
class SignedTreeHead:
    """
    A signed snapshot of the Merkle log.

    Fields are set at signing time and must not be modified afterward.
    Call verify() before trusting any STH received from an external source.
    """

    sequence: int  # monotonically increasing counter, unique per operator
    tree_size: int  # number of leaves in the tree at signing time
    timestamp: float  # unix timestamp (wall clock, informational only)
    root_hash: bytes  # 32-byte BLAKE2b-256 Merkle root
    operator_vk: bytes  # ML-DSA-65 verification key of the signing operator
    signature: bytes  # ML-DSA-65 signature over signable_payload()

    def signable_payload(self) -> bytes:
        """
        Canonical byte string that the ML-DSA signature covers.

        Deterministic encoding — same fields always produce same bytes.

        NOTE: This is the legacy encoding path with NO domain prefix.
        New code should use canonical_bytes() which includes the
        GSX-LTP domain tag. This method is preserved for backward
        compatibility with existing signatures.
        """
        return (
            struct.pack(">Q", self.sequence)
            + struct.pack(">Q", self.tree_size)
            + struct.pack(">d", self.timestamp)
            + self.root_hash
        )

    def canonical_bytes(self) -> bytes:
        """Deterministic binary encoding using CanonicalEncoder with domain tag.

        Forward-looking encoding path for envelopes and receipts.
        The legacy signable_payload() (without domain prefix) is preserved
        for backward compatibility with existing ML-DSA signatures.
        """
        from ..domain import DOMAIN_STH_SIGN
        from ..encoding import CanonicalEncoder

        return (
            CanonicalEncoder(DOMAIN_STH_SIGN)
            .uint64(self.sequence)
            .uint64(self.tree_size)
            .float64(self.timestamp)
            .raw_bytes(self.root_hash)
            .length_prefixed_bytes(self.operator_vk)
            .finalize()
        )

    def verify(self) -> bool:
        """Return True iff the ML-DSA-65 signature is valid for this STH."""
        return MLDSA.verify(self.operator_vk, self.signable_payload(), self.signature)

    @classmethod
    def sign_envelope(
        cls,
        sequence: int,
        tree_size: int,
        root_hash: bytes,
        operator_vk: bytes,
        operator_sk: bytes,
    ) -> "SignedEnvelope":
        """Create a SignedEnvelope wrapping an STH.

        Uses canonical_bytes() as the payload. The existing sign() classmethod
        is UNCHANGED — this is an additive capability.
        """
        from ..domain import DOMAIN_STH_SIGN
        from ..envelope import SignedEnvelope

        sth = cls.sign(sequence, tree_size, root_hash, operator_vk, operator_sk)
        return SignedEnvelope.create(
            domain=DOMAIN_STH_SIGN,
            signer_vk=operator_vk,
            signer_sk=operator_sk,
            signer_id="log-operator",
            payload_type="sth",
            payload=sth.canonical_bytes(),
        )

    @classmethod
    def sign(
        cls,
        sequence: int,
        tree_size: int,
        root_hash: bytes,
        operator_vk: bytes,
        operator_sk: bytes,
    ) -> "SignedTreeHead":
        """
        Create and sign a new STH.

        Args:
            sequence:     monotonically increasing counter for this operator
            tree_size:    number of leaves at the time of signing
            root_hash:    current Merkle root (32 bytes)
            operator_vk:  ML-DSA-65 verification key (public)
            operator_sk:  ML-DSA-65 signing key (private)
        """
        ts = time.time()
        payload = (
            struct.pack(">Q", sequence)
            + struct.pack(">Q", tree_size)
            + struct.pack(">d", ts)
            + root_hash
        )
        # LTP-A-032 Phase 4d: operator_sk may be raw bytes (legacy) or
        # a KeyPair. Route through KeyPair.sign when applicable so
        # HSM-backed kps stay sentinel-only.
        from ..keypair import KeyPair as _KeyPair

        if isinstance(operator_sk, _KeyPair):
            signature = operator_sk.sign(payload)
        else:
            signature = MLDSA.sign(operator_sk, payload)
        return cls(
            sequence=sequence,
            tree_size=tree_size,
            timestamp=ts,
            root_hash=root_hash,
            operator_vk=operator_vk,
            signature=signature,
        )
