"""
Lattice key — the minimal sealed transfer object for LTP (Option C).

Provides:
  - LatticeKey — serializes/seals/unseals the three core secrets

Option C design: the sealed key contains exactly:
  - entity_id      (which entity to materialize)
  - cek            (Content Encryption Key for shard decryption)
  - commitment_ref (hash of commitment record for verification)
  - access_policy  (materialization rules)

Everything else (shard_ids, encoding_params, sender_id) is read from
the commitment record at materialize time — not stored in the key.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from .keypair import KeyPair, SealedBox

__all__ = ["LatticeKey"]


@dataclass
class LatticeKey:
    """
    The lattice key — the ONLY data transmitted sender → receiver.

    Option C design — contains exactly 3 secrets + policy:
      - entity_id:      which entity to materialize (32-byte hash string)
      - cek:            Content Encryption Key for shard decryption (32 bytes)
      - commitment_ref: hash of commitment record for verification (hash string)
      - access_policy:  materialization rules (~20-50 bytes of JSON)

    REMOVED from key (vs. v1):
      - shard_ids[]     → receiver derives locations from entity_id
      - encoding_params → receiver reads from commitment record
      - sender_id       → receiver reads from commitment record

    The entire key is sealed (envelope-encrypted) to the receiver's public key.
    Each seal() generates a fresh ML-KEM encapsulation (forward secrecy).
    """

    entity_id: str
    cek: bytes
    commitment_ref: str
    access_policy: dict = field(default_factory=lambda: {"type": "unrestricted"})

    def _plaintext_payload(self) -> bytes:
        """Serialize the key's inner payload (before sealing)."""
        return json.dumps(
            {
                "entity_id": self.entity_id,
                "cek": self.cek.hex(),
                "commitment_ref": self.commitment_ref,
                "access_policy": self.access_policy,
            },
            separators=(",", ":"),
        ).encode()

    def seal(self, receiver_ek: bytes) -> bytes:
        """
        Seal the entire key to receiver's ML-KEM encapsulation key.

        Returns opaque ciphertext — only the holder of the corresponding dk
        can unseal. Each call produces a fresh ML-KEM encapsulation.
        """
        return SealedBox.seal(self._plaintext_payload(), receiver_ek)

    @classmethod
    def unseal(cls, sealed_data: bytes, receiver_keypair: KeyPair) -> "LatticeKey":
        """Unseal with receiver's private key. Raises ValueError if wrong receiver."""
        plaintext = SealedBox.unseal(sealed_data, receiver_keypair)
        d = json.loads(plaintext)
        return cls(
            entity_id=d["entity_id"],
            cek=bytes.fromhex(d["cek"]),
            commitment_ref=d["commitment_ref"],
            access_policy=d["access_policy"],
        )

    def canonical_bytes(self) -> bytes:
        """Deterministic binary encoding using CanonicalEncoder.

        Replaces the fragile json.dumps(sort_keys=True) path with
        structured binary encoding. The legacy _plaintext_payload() is
        preserved for backward compatibility with existing sealed keys.
        """
        import json as _json

        from .domain import DOMAIN_LATTICE_KEY
        from .encoding import CanonicalEncoder

        return (
            CanonicalEncoder(DOMAIN_LATTICE_KEY)
            .string(self.entity_id)
            .length_prefixed_bytes(self.cek)
            .string(self.commitment_ref)
            .string(_json.dumps(self.access_policy, sort_keys=True, separators=(",", ":")))
            .finalize()
        )

    @property
    def plaintext_size(self) -> int:
        """Size of inner payload before sealing."""
        return len(self._plaintext_payload())
